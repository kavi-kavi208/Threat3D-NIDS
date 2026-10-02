package com.nids.threat3d.pipeline;

import com.nids.threat3d.engine.HybridThreatScorer;
import com.nids.threat3d.engine.anomaly.AnomalyDetectionEngine;
import com.nids.threat3d.engine.anomaly.AnomalyDetectionResult;
import com.nids.threat3d.engine.signature.SignatureDetectionEngine;
import com.nids.threat3d.engine.signature.SignatureMatchResult;
import com.nids.threat3d.feature.FeatureExtractor;
import com.nids.threat3d.feature.FeatureVector;
import com.nids.threat3d.flow.AggregatedFlow;
import com.nids.threat3d.flow.FlowTracker;
import com.nids.threat3d.ingestion.SyntheticTrafficSource;
import com.nids.threat3d.ingestion.TrafficRecord;
import com.nids.threat3d.ingestion.TrafficSource;
import com.nids.threat3d.model.NetworkFlow;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.repository.NetworkFlowRepository;
import com.nids.threat3d.repository.ThreatAlertRepository;
import com.nids.threat3d.service.DefenseRecommendationService;
import com.nids.threat3d.service.DefenseRecommendationService.DefenseRecommendation;
import com.nids.threat3d.service.ThreatCorrelationService;
import com.nids.threat3d.service.ThreatCorrelationService.CorrelationResult;
import com.nids.threat3d.simulation.ScenarioType;
import com.nids.threat3d.threat.DetectionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NIDS Detection Pipeline — Phase 2 core orchestrator.
 *
 * <p>Connects all Phase 2 components in a safe, single-pass pipeline:</p>
 * <pre>
 *  TrafficRecord
 *       │
 *       ▼
 *  FlowTracker          (5-tuple flow aggregation)
 *       │
 *       ▼
 *  FeatureExtractor     (41-dimensional FeatureVector)
 *       │
 *       ├──▶ SignatureDetectionEngine  (rule-based — exact thresholds)
 *       │
 *       └──▶ AnomalyDetectionEngine   (Java Statistical Anomaly Detection — Welford Z-score)
 *                 │
 *                 ▼
 *          HybridThreatScorer         (0-100 score → DetectionEvent)
 *                 │
 *                 ├──▶ ThreatCorrelationService   (time-windowed multi-event correlation)
 *                 │
 *                 ├──▶ DefenseRecommendationService (simulated countermeasures)
 *                 │
 *                 ├──▶ ThreatAlertRepository       (H2 persistence — HIGH/CRITICAL only)
 *                 │
 *                 └──▶ NetworkFlowRepository       (H2 persistence — every flow)
 * </pre>
 *
 * <h3>Safety contract</h3>
 * <ul>
 *   <li>Processes <em>only</em> synthetic or PCAP-replay data — no live packet capture.</li>
 *   <li>Never modifies firewall rules, routing tables, or any OS network setting.</li>
 *   <li>All detection is performed in-memory and persisted to a local H2 database.</li>
 *   <li>Recommendations from {@link DefenseRecommendationService} are labelled
 *       {@code [SIMULATED]} and carry the mandatory disclaimer.</li>
 * </ul>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@Service
public class NidsDetectionPipeline {

    private static final Logger log = LoggerFactory.getLogger(NidsDetectionPipeline.class);

    // ── Threshold: only persist ThreatAlert for events above this severity ────
    private static final int ALERT_PERSIST_THRESHOLD = HybridThreatScorer.HIGH_THRESHOLD;

    // ── Default batch size for synthetic simulation runs ──────────────────────
    @Value("${nids.pipeline.batch-size:50}")
    private int defaultBatchSize;

    // ── Maximum records per single simulation run ──────────────────────────────
    @Value("${nids.pipeline.max-records-per-run:500}")
    private int maxRecordsPerRun;

    // ── Injected Phase 2 components ───────────────────────────────────────────
    private final FlowTracker                  flowTracker;
    private final FeatureExtractor             featureExtractor;
    private final SignatureDetectionEngine     signatureEngine;
    private final AnomalyDetectionEngine       anomalyEngine;
    private final HybridThreatScorer           scorer;
    private final ThreatCorrelationService     correlationService;
    private final DefenseRecommendationService recommendationService;

    // ── Injected Phase 1 repositories ─────────────────────────────────────────
    private final ThreatAlertRepository  alertRepository;
    private final NetworkFlowRepository  flowRepository;

    // ── Pipeline statistics ───────────────────────────────────────────────────
    private final AtomicLong totalRecordsProcessed   = new AtomicLong(0);
    private final AtomicLong totalEventsGenerated    = new AtomicLong(0);
    private final AtomicLong totalAlertsPersistedDb  = new AtomicLong(0);
    private final AtomicLong totalPipelineErrors     = new AtomicLong(0);

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.nids.threat3d.service.RealtimeEventPublisher realtimePublisher;

    public NidsDetectionPipeline(FlowTracker flowTracker,
                                 FeatureExtractor featureExtractor,
                                 SignatureDetectionEngine signatureEngine,
                                 AnomalyDetectionEngine anomalyEngine,
                                 HybridThreatScorer scorer,
                                 ThreatCorrelationService correlationService,
                                 DefenseRecommendationService recommendationService,
                                 ThreatAlertRepository alertRepository,
                                 NetworkFlowRepository flowRepository) {
        this.flowTracker           = flowTracker;
        this.featureExtractor      = featureExtractor;
        this.signatureEngine       = signatureEngine;
        this.anomalyEngine         = anomalyEngine;
        this.scorer                = scorer;
        this.correlationService    = correlationService;
        this.recommendationService = recommendationService;
        this.alertRepository       = alertRepository;
        this.flowRepository        = flowRepository;
    }

    public void setRealtimePublisher(com.nids.threat3d.service.RealtimeEventPublisher realtimePublisher) {
        this.realtimePublisher = realtimePublisher;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — single record
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Process a single {@link TrafficRecord} through the full detection pipeline.
     *
     * @param record a validated, synthetic or PCAP-sourced traffic record
     * @return a {@link PipelineResult} containing the detection event,
     *         optional correlation result, and defense recommendation
     */
    @Transactional
    public PipelineResult processRecord(TrafficRecord record) {
        if (record == null) {
            throw new IllegalArgumentException("TrafficRecord must not be null");
        }

        try {
            // 1. Flow aggregation
            AggregatedFlow flow = flowTracker.processRecord(record);

            // 2. Feature extraction
            Set<Integer> ports   = flowTracker.getContactedPortsForSource(record.getSourceIp());
            Set<String>  destIps = flowTracker.getContactedDestIpsForSource(record.getSourceIp());
            FeatureVector features = featureExtractor.extract(flow, ports, destIps);

            // 3. Parallel detection paths (signature + anomaly)
            SignatureMatchResult sigResult  = signatureEngine.evaluate(flow, features);
            AnomalyDetectionResult anomResult = anomalyEngine.analyse(features);

            // 4. Hybrid scoring → DetectionEvent
            DetectionEvent event = scorer.score(flow, sigResult, anomResult);

            // 5. Threat correlation
            Optional<CorrelationResult> correlation = correlationService.ingestAndCorrelate(event);

            // 6. Defense recommendation
            DefenseRecommendation recommendation = correlation.isPresent()
                    ? recommendationService.recommendFromCorrelation(correlation.get())
                    : recommendationService.recommend(event);

            // 7. Persist flow entity to H2
            persistFlowEntity(flow);

            // 8. Persist ThreatAlert for matched signatures or elevated threat events
            if (sigResult.isMatched() || (int) event.getThreatScore() >= HybridThreatScorer.MEDIUM_THRESHOLD) {
                persistThreatAlert(event, sigResult);
            }

            totalRecordsProcessed.incrementAndGet();
            totalEventsGenerated.incrementAndGet();

            if (realtimePublisher != null) {
                realtimePublisher.publishDetectionEvent(event);
            }

            log.debug("[Pipeline] src={} score={} severity={} action={}",
                    event.getSourceIp(), (int) event.getThreatScore(),
                    event.getSeverity(), event.getRecommendedAction());

            return new PipelineResult(event, correlation.orElse(null), recommendation, null);

        } catch (Exception ex) {
            totalPipelineErrors.incrementAndGet();
            log.error("[Pipeline] Error processing record src={}: {}",
                    record.getSourceIp(), ex.getMessage(), ex);
            return new PipelineResult(null, null, null, ex.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — batch
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Process a batch of {@link TrafficRecord} objects.
     *
     * @param records list of records (null entries are skipped)
     * @return ordered list of {@link PipelineResult} — one per non-null record
     */
    @Transactional
    public List<PipelineResult> processBatch(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) {
            return Collections.emptyList();
        }
        List<PipelineResult> results = new ArrayList<>(records.size());
        for (TrafficRecord rec : records) {
            if (rec != null) {
                results.add(processRecord(rec));
            }
        }
        return results;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — simulation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Run a named simulation scenario through the full pipeline.
     *
     * <p>Generates synthetic traffic for the given {@link ScenarioType} and
     * processes it in batches, collecting all {@link PipelineResult} objects.</p>
     *
     * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong><br>
     * All traffic is generated in-memory from {@link SyntheticTrafficSource}.
     * No packets are transmitted on any real network interface.</p>
     *
     * @param scenarioType  which named scenario to simulate
     * @param totalRecords  number of synthetic records to generate (clamped to
     *                      {@code nids.pipeline.max-records-per-run})
     * @return a {@link SimulationSummary} with aggregate statistics and all results
     */
    @Transactional
    public SimulationSummary runSimulation(ScenarioType scenarioType, int totalRecords) {
        if (scenarioType == null) {
            throw new IllegalArgumentException("ScenarioType must not be null");
        }
        int clampedTotal = Math.min(Math.max(1, totalRecords), maxRecordsPerRun);
        log.info("[Pipeline] Starting simulation: scenario={} records={}", scenarioType, clampedTotal);

        TrafficSource source = new SyntheticTrafficSource(scenarioType, clampedTotal);
        List<PipelineResult> allResults = new CopyOnWriteArrayList<>();
        int batchSize = Math.min(defaultBatchSize, clampedTotal);
        int batchNumber = 0;

        Instant startedAt = Instant.now();
        while (source.hasMore()) {
            List<TrafficRecord> batch = source.pollBatch(batchSize);
            if (batch.isEmpty()) break;
            List<PipelineResult> batchResults = processBatch(batch);
            allResults.addAll(batchResults);
            batchNumber++;
            log.debug("[Pipeline] Simulation batch {}: processed {} records, total so far: {}",
                    batchNumber, batch.size(), allResults.size());
        }

        long durationMs = Math.max(1, java.time.Duration.between(startedAt, Instant.now()).toMillis());
        SimulationSummary summary = buildSummary(scenarioType, clampedTotal, allResults, durationMs);
        log.info("[Pipeline] Simulation complete: scenario={} processed={} events={} alerts={}",
                scenarioType, summary.getTotalRecordsProcessed(),
                summary.getTotalEventsGenerated(), summary.getTotalHighCriticalAlerts());
        return summary;
    }

    /**
     * Run a simulation from an external {@link TrafficSource} (e.g. PCAP replay).
     *
     * @param source      a custom {@link TrafficSource} implementation
     * @param displayName a label used in logs (e.g. "pcap:capture.pcap")
     * @return a {@link SimulationSummary}
     */
    @Transactional
    public SimulationSummary runFromSource(TrafficSource source, String displayName) {
        if (source == null) {
            throw new IllegalArgumentException("TrafficSource must not be null");
        }
        String label = (displayName != null && !displayName.isBlank()) ? displayName : source.getSourceType();
        log.info("[Pipeline] Starting run from source: {}", label);

        List<PipelineResult> allResults = new ArrayList<>();
        int safeguard = 0;

        while (source.hasMore() && safeguard < maxRecordsPerRun) {
            List<TrafficRecord> batch = source.pollBatch(defaultBatchSize);
            if (batch.isEmpty()) break;
            allResults.addAll(processBatch(batch));
            safeguard += batch.size();
        }

        SimulationSummary summary = buildSummary(ScenarioType.NORMAL_TRAFFIC, safeguard, allResults);
        log.info("[Pipeline] Source run complete: label={} processed={}", label, safeguard);
        return summary;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Persistence helpers
    // ─────────────────────────────────────────────────────────────────────────

    private void persistFlowEntity(AggregatedFlow flow) {
        try {
            NetworkFlow entity = flow.toNetworkFlowEntity();
            flowRepository.save(entity);
        } catch (Exception ex) {
            log.warn("[Pipeline] Could not persist NetworkFlow for src={}: {}",
                    flow.getKey().getSourceIp(), ex.getMessage());
        }
    }

    private final Map<String, Instant> alertDeduplicationMap = new java.util.concurrent.ConcurrentHashMap<>();

    private void persistThreatAlert(DetectionEvent event, SignatureMatchResult sigResult) {
        String ruleId = sigResult.isMatched() ? sigResult.getRuleId() : "ANOMALY-" + event.getThreatType().name();
        String dedupKey = ruleId + ":" + event.getSourceIp() + ":" + event.getDestinationIp();

        Instant now = Instant.now();
        Instant lastAlert = alertDeduplicationMap.get(dedupKey);
        if (lastAlert != null && java.time.Duration.between(lastAlert, now).toMillis() < 2500) {
            // Throttled duplicate within 2.5s for the same flow & rule to prevent DB flood
            return;
        }
        alertDeduplicationMap.put(dedupKey, now);

        try {
            String details = truncate(event.getExplanation(), 900);

            ThreatAlert alert = new ThreatAlert(
                    ruleId,
                    event.getSourceIp(),
                    event.getDestinationIp(),
                    event.getSourcePort(),
                    event.getDestinationPort(),
                    event.getProtocol(),
                    event.getThreatType().name(),
                    event.getSeverity(),
                    (float) (event.getThreatScore() / 100.0),
                    "ACTIVE",
                    event.getMitreTechnique(),
                    details
            );
            ThreatAlert savedAlert = alertRepository.save(alert);
            totalAlertsPersistedDb.incrementAndGet();

            if (realtimePublisher != null) {
                realtimePublisher.publishThreatAlert(savedAlert);
            }
        } catch (Exception ex) {
            log.warn("[Pipeline] Could not persist ThreatAlert for src={}: {}",
                    event.getSourceIp(), ex.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pipeline statistics (thread-safe counters)
    // ─────────────────────────────────────────────────────────────────────────

    public long getTotalRecordsProcessed()  { return totalRecordsProcessed.get(); }
    public long getTotalEventsGenerated()   { return totalEventsGenerated.get(); }
    public long getTotalAlertsPersistedDb() { return totalAlertsPersistedDb.get(); }
    public long getTotalPipelineErrors()    { return totalPipelineErrors.get(); }

    /** Resets all pipeline counters and clears the flow tracker buffer. */
    public void resetPipeline() {
        flowTracker.clear();
        anomalyEngine.resetBaseline();
        correlationService.clearBuffer();
        alertDeduplicationMap.clear();
        totalRecordsProcessed.set(0);
        totalEventsGenerated.set(0);
        totalAlertsPersistedDb.set(0);
        totalPipelineErrors.set(0);
        log.info("[Pipeline] Pipeline reset: flow tracker cleared, anomaly baseline reset, correlation buffer cleared.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    private SimulationSummary buildSummary(ScenarioType scenario, int requested,
                                           List<PipelineResult> results) {
        return buildSummary(scenario, requested, results, 0L);
    }

    private SimulationSummary buildSummary(ScenarioType scenario, int requested,
                                           List<PipelineResult> results, long durationMs) {
        int processed       = 0;
        int eventsGenerated = 0;
        int highCritical    = 0;
        int errors          = 0;
        int correlated      = 0;

        Map<String, Integer> severityCounts = new LinkedHashMap<>();
        severityCounts.put("LOW",      0);
        severityCounts.put("MEDIUM",   0);
        severityCounts.put("HIGH",     0);
        severityCounts.put("CRITICAL", 0);

        for (PipelineResult r : results) {
            processed++;
            if (r.hasError()) {
                errors++;
                continue;
            }
            eventsGenerated++;
            String sev = r.getDetectionEvent().getSeverity();
            severityCounts.merge(sev, 1, Integer::sum);
            if ("HIGH".equals(sev) || "CRITICAL".equals(sev)) highCritical++;
            if (r.getCorrelationResult() != null) correlated++;
        }

        return new SimulationSummary(
                scenario, requested, processed, eventsGenerated,
                highCritical, correlated, errors,
                Collections.unmodifiableMap(severityCounts),
                Collections.unmodifiableList(results),
                durationMs
        );
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "…";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner result types
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Immutable result for a single record processed through the pipeline.
     */
    public static final class PipelineResult {

        private final DetectionEvent       detectionEvent;
        private final CorrelationResult    correlationResult;
        private final DefenseRecommendation recommendation;
        private final String               errorMessage;  // null on success

        public PipelineResult(DetectionEvent detectionEvent,
                              CorrelationResult correlationResult,
                              DefenseRecommendation recommendation,
                              String errorMessage) {
            this.detectionEvent    = detectionEvent;
            this.correlationResult = correlationResult;
            this.recommendation    = recommendation;
            this.errorMessage      = errorMessage;
        }

        public boolean hasError()                         { return errorMessage != null; }
        public DetectionEvent getDetectionEvent()         { return detectionEvent; }
        public CorrelationResult getCorrelationResult()   { return correlationResult; }
        public DefenseRecommendation getRecommendation()  { return recommendation; }
        public String getErrorMessage()                   { return errorMessage; }
    }

    /**
     * Aggregate statistics for a completed simulation or source-based run.
     */
    public static final class SimulationSummary {

        private final ScenarioType          scenarioType;
        private final int                   requestedRecords;
        private final int                   totalRecordsProcessed;
        private final int                   totalEventsGenerated;
        private final int                   totalHighCriticalAlerts;
        private final int                   totalCorrelated;
        private final int                   totalErrors;
        private final Map<String, Integer>  severityBreakdown;
        private final List<PipelineResult>  results;
        private final long                  durationMs;

        public SimulationSummary(ScenarioType scenarioType, int requestedRecords,
                                 int totalRecordsProcessed, int totalEventsGenerated,
                                 int totalHighCriticalAlerts, int totalCorrelated,
                                 int totalErrors, Map<String, Integer> severityBreakdown,
                                 List<PipelineResult> results, long durationMs) {
            this.scenarioType            = scenarioType;
            this.requestedRecords        = requestedRecords;
            this.totalRecordsProcessed   = totalRecordsProcessed;
            this.totalEventsGenerated    = totalEventsGenerated;
            this.totalHighCriticalAlerts = totalHighCriticalAlerts;
            this.totalCorrelated         = totalCorrelated;
            this.totalErrors             = totalErrors;
            this.severityBreakdown       = severityBreakdown;
            this.results                 = results;
            this.durationMs              = durationMs;
        }

        public SimulationSummary(ScenarioType scenarioType, int requestedRecords,
                                 int totalRecordsProcessed, int totalEventsGenerated,
                                 int totalHighCriticalAlerts, int totalCorrelated,
                                 int totalErrors, Map<String, Integer> severityBreakdown,
                                 List<PipelineResult> results) {
            this(scenarioType, requestedRecords, totalRecordsProcessed, totalEventsGenerated,
                 totalHighCriticalAlerts, totalCorrelated, totalErrors, severityBreakdown, results, 0L);
        }

        public ScenarioType getScenarioType()              { return scenarioType; }
        public int getRequestedRecords()                   { return requestedRecords; }
        public int getTotalRecordsProcessed()              { return totalRecordsProcessed; }
        public int getTotalEventsGenerated()               { return totalEventsGenerated; }
        public int getTotalHighCriticalAlerts()            { return totalHighCriticalAlerts; }
        public int getTotalCorrelated()                    { return totalCorrelated; }
        public int getTotalErrors()                        { return totalErrors; }
        public Map<String, Integer> getSeverityBreakdown() { return severityBreakdown; }
        public List<PipelineResult> getResults()           { return results; }
        public long getDurationMs()                        { return durationMs; }

        public double getThroughputRecordsPerSec() {
            if (durationMs <= 0) return 0.0;
            return (totalRecordsProcessed * 1000.0) / durationMs;
        }

        public boolean isFullySuccessful() { return totalErrors == 0; }

        @Override
        public String toString() {
            return String.format(
                    "SimulationSummary[scenario=%s, requested=%d, processed=%d, " +
                    "events=%d, highCritical=%d, correlated=%d, errors=%d, duration=%dms, severity=%s]",
                    scenarioType, requestedRecords, totalRecordsProcessed,
                    totalEventsGenerated, totalHighCriticalAlerts,
                    totalCorrelated, totalErrors, durationMs, severityBreakdown);
        }
    }
}
