package com.nids.threat3d.service;

import com.nids.threat3d.engine.HybridThreatScorer;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.DetectionEvent;
import com.nids.threat3d.threat.MitreMapping;
import com.nids.threat3d.threat.ThreatType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Threat Correlation Service — Phase 2.
 *
 * <p>Groups {@link DetectionEvent} objects by source IP within a configurable
 * sliding time window and identifies patterns that indicate <em>multi-stage
 * suspicious activity</em> (e.g. reconnaissance followed by exploitation).</p>
 *
 * <h3>Correlation logic</h3>
 * <ol>
 *   <li><strong>Ingest</strong> — every scored event is stored in an in-memory
 *       ring-buffer keyed by {@code sourceIp}.</li>
 *   <li><strong>Prune</strong> — events older than {@code correlationWindowSeconds}
 *       are removed on every ingest and on every explicit query.</li>
 *   <li><strong>Correlate</strong> — for each source IP with ≥ 2 distinct threat
 *       types in the window, a {@link CorrelationResult} is produced.</li>
 *   <li><strong>Escalate</strong> — if the set of threat types matches a known
 *       multi-stage kill-chain pattern, the result is escalated to
 *       {@link ThreatType#MULTI_STAGE_SUSPICIOUS_ACTIVITY} and the composite
 *       score is boosted.</li>
 * </ol>
 *
 * <p>This service performs <strong>data correlation only</strong>.  It never
 * modifies the network, sends commands to firewalls, or executes exploits.<br>
 * {@value DefenseAction#SAFETY_DISCLAIMER}</p>
 */
@Service
public class ThreatCorrelationService {

    private static final Logger log = LoggerFactory.getLogger(ThreatCorrelationService.class);

    // ── Configurable window (default 120 s, override via application properties) ─
    @Value("${nids.correlation.window-seconds:120}")
    private long correlationWindowSeconds;

    // ── Minimum distinct threat types required to flag correlation ────────────
    @Value("${nids.correlation.min-distinct-types:2}")
    private int minDistinctTypes;

    // ── Max events buffered per source IP (prevents unbounded memory growth) ──
    private static final int MAX_EVENTS_PER_SOURCE = 200;

    /**
     * In-memory ring-buffer: sourceIp → time-ordered list of DetectionEvents.
     * ConcurrentHashMap for thread safety; inner list operations are synchronised.
     */
    private final Map<String, List<DetectionEvent>> eventBuffer = new ConcurrentHashMap<>();

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Ingest a new {@link DetectionEvent} into the correlation buffer and
     * immediately attempt correlation for the event's source IP.
     *
     * @param event the scored detection event from {@link com.nids.threat3d.engine.HybridThreatScorer}
     * @return an {@link Optional} containing a {@link CorrelationResult} if a
     *         multi-event pattern was found, or {@link Optional#empty()} for
     *         single low-severity events that do not yet form a pattern
     */
    public Optional<CorrelationResult> ingestAndCorrelate(DetectionEvent event) {
        if (event == null || event.getSourceIp() == null) {
            return Optional.empty();
        }

        String sourceIp = event.getSourceIp();

        // Add to buffer (thread-safe)
        eventBuffer.compute(sourceIp, (ip, existing) -> {
            List<DetectionEvent> list = (existing != null) ? existing : new ArrayList<>();
            synchronized (list) {
                list.add(event);
                // Cap to prevent unbounded growth
                if (list.size() > MAX_EVENTS_PER_SOURCE) {
                    list.remove(0);
                }
            }
            return list;
        });

        // Prune stale events and attempt correlation
        return correlateForSource(sourceIp);
    }

    /**
     * Explicitly correlate all buffered events for a given source IP.
     * Useful for on-demand querying (e.g. from a REST controller).
     *
     * @param sourceIp the source IP address to correlate
     * @return correlation result or empty if no pattern found
     */
    public Optional<CorrelationResult> correlateForSource(String sourceIp) {
        List<DetectionEvent> raw = eventBuffer.get(sourceIp);
        if (raw == null) return Optional.empty();

        List<DetectionEvent> window;
        synchronized (raw) {
            pruneStale(raw);
            window = new ArrayList<>(raw);   // snapshot for analysis
        }

        return analyse(sourceIp, window);
    }

    /**
     * Correlate all buffered source IPs and return every active correlation result.
     * Intended for periodic sweeps or dashboard polling.
     *
     * @return list of all active correlation results (may be empty)
     */
    public List<CorrelationResult> correlateAll() {
        List<CorrelationResult> results = new ArrayList<>();
        for (String ip : eventBuffer.keySet()) {
            correlateForSource(ip).ifPresent(results::add);
        }
        // Sort: highest composite score first
        results.sort(Comparator.comparingDouble(CorrelationResult::getCompositeScore).reversed());
        log.debug("[ThreatCorrelation] correlateAll → {} active correlations across {} sources",
                results.size(), eventBuffer.size());
        return results;
    }

    /**
     * Returns a snapshot of all buffered source IPs and their event counts
     * (after pruning stale entries). Useful for diagnostics.
     */
    public Map<String, Integer> getBufferSummary() {
        Map<String, Integer> summary = new LinkedHashMap<>();
        for (Map.Entry<String, List<DetectionEvent>> e : eventBuffer.entrySet()) {
            List<DetectionEvent> list = e.getValue();
            synchronized (list) {
                pruneStale(list);
                if (!list.isEmpty()) {
                    summary.put(e.getKey(), list.size());
                }
            }
        }
        return summary;
    }

    /**
     * Clears the entire event buffer.  Call between simulation scenarios
     * to prevent cross-contamination.
     */
    public void clearBuffer() {
        eventBuffer.clear();
        log.info("[ThreatCorrelation] Event buffer cleared.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core analysis
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Analyses events within the time window for a single source IP.
     * Returns a {@link CorrelationResult} only when the minimum distinct-type
     * threshold is met.
     */
    private Optional<CorrelationResult> analyse(String sourceIp, List<DetectionEvent> window) {
        if (window.isEmpty()) return Optional.empty();

        // Filter out NORMAL events — only suspicious events participate
        List<DetectionEvent> suspicious = window.stream()
                .filter(e -> e.getThreatType() != ThreatType.NORMAL)
                .collect(Collectors.toList());

        if (suspicious.isEmpty()) return Optional.empty();

        // Distinct threat types seen from this source in the window
        Set<ThreatType> distinctTypes = suspicious.stream()
                .map(DetectionEvent::getThreatType)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (distinctTypes.size() < minDistinctTypes) return Optional.empty();

        // Composite score: weighted average of individual scores, boosted for multi-stage
        double compositeScore = computeCompositeScore(suspicious, distinctTypes);

        // Determine overall threat type — escalate if kill-chain pattern matches
        ThreatType correlatedType = resolveCorrelatedThreatType(distinctTypes);

        // Highest-severity event's recommendation as the group recommendation
        DefenseAction groupAction = selectGroupAction(suspicious);

        // MITRE mapping for the correlated type
        MitreMapping mitre = MitreMapping.forThreatType(correlatedType,
                buildMitreReason(distinctTypes));

        // Time span of the correlated window
        Instant windowStart = suspicious.stream()
                .map(DetectionEvent::getTimestamp)
                .min(Comparator.naturalOrder())
                .orElse(Instant.now());
        Instant windowEnd = suspicious.stream()
                .map(DetectionEvent::getTimestamp)
                .max(Comparator.naturalOrder())
                .orElse(Instant.now());

        // Explainable narrative
        String narrative = buildNarrative(sourceIp, suspicious, distinctTypes,
                compositeScore, correlatedType, mitre);

        CorrelationResult result = new CorrelationResult(
                sourceIp,
                correlatedType,
                HybridThreatScorer.toSeverity((int) Math.round(compositeScore)),
                compositeScore,
                new ArrayList<>(distinctTypes),
                suspicious.size(),
                windowStart,
                windowEnd,
                groupAction,
                mitre,
                narrative
        );

        log.debug("[ThreatCorrelation] {} → {} events, types={}, score={:.1f}, type={}",
                sourceIp, suspicious.size(), distinctTypes.size(),
                compositeScore, correlatedType);

        return Optional.of(result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scoring helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Composite score formula:
     * <pre>
     *   base    = weighted average of individual threat scores (recent events weighted 2×)
     *   bonus   = +10 per additional distinct type beyond the minimum (capped at +20)
     *   escalation = +15 if a kill-chain pattern is recognised
     *   result  = min(base + bonus + escalation, 100)
     * </pre>
     */
    private double computeCompositeScore(List<DetectionEvent> events,
                                         Set<ThreatType> distinctTypes) {
        int n = events.size();
        double weightedSum = 0.0;
        double weightTotal = 0.0;

        for (int i = 0; i < n; i++) {
            // More-recent events receive double weight
            double weight = (i >= n / 2) ? 2.0 : 1.0;
            weightedSum  += events.get(i).getThreatScore() * weight;
            weightTotal  += weight;
        }

        double base = (weightTotal > 0) ? weightedSum / weightTotal : 0.0;

        // Bonus for each distinct type beyond the minimum
        int extraTypes = Math.max(0, distinctTypes.size() - minDistinctTypes);
        double bonus = Math.min(extraTypes * 10.0, 20.0);

        // Kill-chain escalation
        double escalation = isKillChainPattern(distinctTypes) ? 15.0 : 0.0;

        return Math.min(base + bonus + escalation, 100.0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Kill-chain pattern recognition
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Known multi-stage kill-chain patterns (data-analytic observation only —
     * no attack generation):
     * <ul>
     *   <li>Recon + Exploit  : PORT_SCAN → WEB_ANOMALY / BRUTE_FORCE</li>
     *   <li>Recon + DoS      : PORT_SCAN → SYN_FLOOD / ICMP_FLOOD</li>
     *   <li>Auth + Exploit   : BRUTE_FORCE → WEB_ANOMALY</li>
     *   <li>Any 3+ distinct  : always escalated</li>
     * </ul>
     */
    private boolean isKillChainPattern(Set<ThreatType> types) {
        if (types.size() >= 3) return true;

        boolean hasScan  = types.contains(ThreatType.PORT_SCAN);
        boolean hasFlood = types.contains(ThreatType.SYN_FLOOD)
                        || types.contains(ThreatType.ICMP_FLOOD);
        boolean hasExploit = types.contains(ThreatType.WEB_ANOMALY);
        boolean hasBrute   = types.contains(ThreatType.BRUTE_FORCE);

        return (hasScan && hasFlood)
            || (hasScan && hasExploit)
            || (hasScan && hasBrute)
            || (hasBrute && hasExploit);
    }

    /**
     * Escalates to {@link ThreatType#MULTI_STAGE_SUSPICIOUS_ACTIVITY} when a
     * kill-chain pattern is recognised; otherwise returns the highest-priority
     * threat type from the distinct set.
     */
    private ThreatType resolveCorrelatedThreatType(Set<ThreatType> types) {
        if (isKillChainPattern(types)) {
            return ThreatType.MULTI_STAGE_SUSPICIOUS_ACTIVITY;
        }
        // Priority order: WEB > BRUTE > SYN_FLOOD > ICMP_FLOOD > PORT_SCAN > ANOMALOUS
        for (ThreatType candidate : List.of(
                ThreatType.WEB_ANOMALY, ThreatType.BRUTE_FORCE,
                ThreatType.SYN_FLOOD, ThreatType.ICMP_FLOOD,
                ThreatType.PORT_SCAN, ThreatType.ANOMALOUS_TRAFFIC)) {
            if (types.contains(candidate)) return candidate;
        }
        return ThreatType.ANOMALOUS_TRAFFIC;
    }

    /**
     * Selects the strongest defense action across the correlated event group.
     */
    private DefenseAction selectGroupAction(List<DetectionEvent> events) {
        return events.stream()
                .map(DetectionEvent::getRecommendedAction)
                .max(Comparator.comparingInt(Enum::ordinal))
                .orElse(DefenseAction.MONITOR);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pruning
    // ─────────────────────────────────────────────────────────────────────────

    /** Removes events outside the configured time window. Must be called under list's monitor. */
    private void pruneStale(List<DetectionEvent> list) {
        Instant cutoff = Instant.now().minusSeconds(correlationWindowSeconds);
        list.removeIf(e -> e.getTimestamp().isBefore(cutoff));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Narrative builders
    // ─────────────────────────────────────────────────────────────────────────

    private String buildMitreReason(Set<ThreatType> types) {
        String typeNames = types.stream()
                .map(Enum::name)
                .collect(Collectors.joining(", "));
        return "Correlated types from single source: " + typeNames;
    }

    private String buildNarrative(String sourceIp,
                                   List<DetectionEvent> events,
                                   Set<ThreatType> distinctTypes,
                                   double compositeScore,
                                   ThreatType correlatedType,
                                   MitreMapping mitre) {

        String typeList = distinctTypes.stream()
                .map(Enum::name)
                .collect(Collectors.joining(", "));

        String topExplanations = events.stream()
                .filter(e -> e.getThreatScore() >= 40)
                .sorted(Comparator.comparingDouble(DetectionEvent::getThreatScore).reversed())
                .limit(3)
                .map(e -> String.format("%s(score=%d)", e.getThreatType().name(),
                        (int) e.getThreatScore()))
                .collect(Collectors.joining("; "));

        boolean killChain = isKillChainPattern(distinctTypes);

        return String.format(
                "[ThreatCorrelation] src=%s | events=%d | types=[%s] | compositeScore=%.1f/100 | " +
                "correlatedType=%s | killChain=%s | MITRE=%s '%s' | topSignals=[%s] | %s",
                sourceIp,
                events.size(),
                typeList,
                compositeScore,
                correlatedType.name(),
                killChain ? "YES" : "NO",
                mitre.getTechniqueId(),
                mitre.getTechniqueName(),
                topExplanations.isEmpty() ? "none above threshold" : topExplanations,
                DefenseAction.SAFETY_DISCLAIMER
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner result type
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Immutable result of correlating multiple {@link DetectionEvent} objects
     * from the same source IP within the time window.
     */
    public static final class CorrelationResult {

        private final String sourceIp;
        private final ThreatType correlatedThreatType;
        private final String severity;
        private final double compositeScore;
        private final List<ThreatType> observedThreatTypes;
        private final int eventCount;
        private final Instant windowStart;
        private final Instant windowEnd;
        private final DefenseAction recommendedAction;
        private final MitreMapping mitreMapping;
        private final String narrative;

        public CorrelationResult(String sourceIp, ThreatType correlatedThreatType,
                                 String severity, double compositeScore,
                                 List<ThreatType> observedThreatTypes, int eventCount,
                                 Instant windowStart, Instant windowEnd,
                                 DefenseAction recommendedAction, MitreMapping mitreMapping,
                                 String narrative) {
            this.sourceIp             = sourceIp;
            this.correlatedThreatType = correlatedThreatType;
            this.severity             = severity;
            this.compositeScore       = compositeScore;
            this.observedThreatTypes  = Collections.unmodifiableList(observedThreatTypes);
            this.eventCount           = eventCount;
            this.windowStart          = windowStart;
            this.windowEnd            = windowEnd;
            this.recommendedAction    = recommendedAction;
            this.mitreMapping         = mitreMapping;
            this.narrative            = narrative;
        }

        public String getSourceIp()                     { return sourceIp; }
        public ThreatType getCorrelatedThreatType()     { return correlatedThreatType; }
        public String getSeverity()                     { return severity; }
        public double getCompositeScore()               { return compositeScore; }
        public List<ThreatType> getObservedThreatTypes(){ return observedThreatTypes; }
        public int getEventCount()                      { return eventCount; }
        public Instant getWindowStart()                 { return windowStart; }
        public Instant getWindowEnd()                   { return windowEnd; }
        public DefenseAction getRecommendedAction()     { return recommendedAction; }
        public MitreMapping getMitreMapping()           { return mitreMapping; }
        public String getNarrative()                    { return narrative; }
    }
}
