package com.nids.threat3d.simulation;

import com.nids.threat3d.ingestion.SyntheticTrafficSource;
import com.nids.threat3d.ingestion.TrafficRecord;
import com.nids.threat3d.pipeline.NidsDetectionPipeline;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.PipelineResult;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.SimulationSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Simulation Orchestrator — Phase 2.
 *
 * <p>Manages the lifecycle of named simulation runs through
 * {@link NidsDetectionPipeline}. Supports start, stop, reset, and progress
 * queries with full thread-safety. At most one simulation runs at a time.</p>
 *
 * <h3>Lifecycle states</h3>
 * <pre>
 *   IDLE ──► RUNNING ──► COMPLETED
 *              │
 *              └──► STOPPED   (user-requested stop)
 *              └──► FAILED    (unhandled exception)
 * </pre>
 *
 * <h3>Safety contract</h3>
 * <ul>
 *   <li>All traffic is generated in-memory by {@link SyntheticTrafficSource} — no
 *       real packets are sent on any network interface.</li>
 *   <li>No firewall rules, routing tables, or OS network settings are modified.</li>
 *   <li>Simulated actions carry the mandatory
 *       {@code "SIMULATION ONLY — NO REAL NETWORK CHANGES"} disclaimer.</li>
 * </ul>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@Service
public class SimulationOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(SimulationOrchestrator.class);

    // ── Configurable limits ───────────────────────────────────────────────────
    @Value("${nids.simulation.default-records:100}")
    private int defaultRecordCount;

    @Value("${nids.simulation.max-records:500}")
    private int maxRecordCount;

    // ── Single-thread executor: enforces one simulation at a time ─────────────
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "nids-sim-orchestrator");
                t.setDaemon(true);
                return t;
            });

    // ── Shared mutable state — all access via AtomicReference or volatile ─────
    private final AtomicReference<SimulationState> state =
            new AtomicReference<>(SimulationState.IDLE);

    private volatile Future<SimulationSummary> activeFuture = null;
    private volatile SimulationProgress        currentProgress = SimulationProgress.idle();
    private volatile SimulationSummary         lastSummary     = null;
    private volatile String                    lastError       = null;

    private final NidsDetectionPipeline pipeline;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.nids.threat3d.service.RealtimeEventPublisher realtimePublisher;

    public SimulationOrchestrator(NidsDetectionPipeline pipeline) {
        this.pipeline = pipeline;
    }

    public void setRealtimePublisher(com.nids.threat3d.service.RealtimeEventPublisher realtimePublisher) {
        this.realtimePublisher = realtimePublisher;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — control
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Start a simulation with the given scenario and record count.
     *
     * <p>The simulation runs asynchronously on a dedicated daemon thread.
     * Use {@link #getProgress()} to poll status and {@link #getLastSummary()}
     * once the state reaches {@link SimulationState#COMPLETED}.</p>
     *
     * @param scenarioType  the scenario to run (must not be null)
     * @param recordCount   number of synthetic records ({@code ≤ max-records})
     * @return a {@link StartResult} indicating whether the run was accepted
     */
    public StartResult startSimulation(ScenarioType scenarioType, int recordCount) {
        if (scenarioType == null) {
            return StartResult.rejected("ScenarioType must not be null");
        }

        // Enforce: only one simulation at a time
        if (!state.compareAndSet(SimulationState.IDLE, SimulationState.RUNNING)
                && !state.compareAndSet(SimulationState.COMPLETED, SimulationState.RUNNING)
                && !state.compareAndSet(SimulationState.STOPPED, SimulationState.RUNNING)
                && !state.compareAndSet(SimulationState.FAILED, SimulationState.RUNNING)) {
            return StartResult.rejected(
                    "A simulation is already RUNNING. Call stopSimulation() first.");
        }

        int clampedCount = Math.min(Math.max(1, recordCount), maxRecordCount);
        lastError   = null;
        lastSummary = null;
        currentProgress = SimulationProgress.starting(scenarioType, clampedCount);

        log.info("[SimOrchestrator] Starting simulation: scenario={} records={}",
                scenarioType, clampedCount);

        activeFuture = executor.submit(() -> runSimulationTask(scenarioType, clampedCount));

        return StartResult.accepted(scenarioType, clampedCount);
    }

    /**
     * Convenience overload — uses {@code nids.simulation.default-records}.
     */
    public StartResult startSimulation(ScenarioType scenarioType) {
        return startSimulation(scenarioType, defaultRecordCount);
    }

    /**
     * Request a cooperative stop of the currently running simulation.
     *
     * <p>The running task checks {@link SimulationState} between batches and
     * will exit cleanly on next check. Already-processed results are preserved
     * in {@link #getLastSummary()} if available.</p>
     *
     * @return true if a simulation was running and has been asked to stop
     */
    public boolean stopSimulation() {
        if (state.compareAndSet(SimulationState.RUNNING, SimulationState.STOPPED)) {
            log.info("[SimOrchestrator] Stop requested — simulation will halt after current batch.");
            if (activeFuture != null) {
                activeFuture.cancel(false); // cooperative — don't interrupt mid-batch
            }
            return true;
        }
        return false;
    }

    /**
     * Reset the orchestrator to {@link SimulationState#IDLE} and clear all state.
     * Also resets the underlying pipeline (flow tracker, anomaly baseline, correlation buffer).
     *
     * @throws IllegalStateException if a simulation is actively RUNNING
     */
    public void reset() {
        SimulationState current = state.get();
        if (current == SimulationState.RUNNING) {
            throw new IllegalStateException(
                    "Cannot reset while a simulation is RUNNING. Call stopSimulation() first.");
        }
        state.set(SimulationState.IDLE);
        lastSummary     = null;
        lastError       = null;
        currentProgress = SimulationProgress.idle();
        pipeline.resetPipeline();
        log.info("[SimOrchestrator] Reset complete — state=IDLE, pipeline cleared.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — observation
    // ─────────────────────────────────────────────────────────────────────────

    /** Current lifecycle state of the orchestrator. */
    public SimulationState getState() {
        return state.get();
    }

    /**
     * Live progress snapshot. Updated at the end of each pipeline batch.
     * Safe to call from any thread at any time.
     */
    public SimulationProgress getProgress() {
        return currentProgress;
    }

    /**
     * The full {@link SimulationSummary} from the last completed run,
     * or {@code null} if no run has completed yet.
     */
    public SimulationSummary getLastSummary() {
        return lastSummary;
    }

    /**
     * Error message from the last failed run, or {@code null} if no failure occurred.
     */
    public String getLastError() {
        return lastError;
    }

    /** All available scenario types (convenience for REST controllers). */
    public List<ScenarioType> getAvailableScenarios() {
        return Arrays.asList(ScenarioType.values());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal simulation task
    // ─────────────────────────────────────────────────────────────────────────

    private SimulationSummary runSimulationTask(ScenarioType scenarioType, int totalRecords) {
        Instant startedAt = Instant.now();
        log.info("[SimOrchestrator] Task started: scenario={} total={}", scenarioType, totalRecords);

        try {
            int batchSize  = Math.min(25, totalRecords);
            int processed  = 0;
            int eventsOk   = 0;
            int highCrit   = 0;
            int errors     = 0;

            SyntheticTrafficSource source =
                    new SyntheticTrafficSource(scenarioType, totalRecords);

            List<PipelineResult> allResults = new ArrayList<>(totalRecords);

            while (source.hasMore()) {
                // Cooperative stop check between batches
                if (state.get() == SimulationState.STOPPED) {
                    log.info("[SimOrchestrator] Stop acknowledged after {} records.", processed);
                    break;
                }

                List<com.nids.threat3d.ingestion.TrafficRecord> batch =
                        source.pollBatch(batchSize);
                if (batch.isEmpty()) break;

                List<PipelineResult> batchResults = pipeline.processBatch(batch);
                allResults.addAll(batchResults);

                // Tally batch stats
                for (PipelineResult r : batchResults) {
                    processed++;
                    if (r.hasError()) {
                        errors++;
                    } else {
                        eventsOk++;
                        String sev = r.getDetectionEvent().getSeverity();
                        if ("HIGH".equals(sev) || "CRITICAL".equals(sev) || "MEDIUM".equals(sev)) {
                            highCrit++;
                        }
                    }
                }

                // Publish live progress
                long elapsed = Math.max(1, java.time.Duration.between(startedAt, Instant.now()).toMillis());
                currentProgress = new SimulationProgress(
                        scenarioType, totalRecords, processed, eventsOk,
                        highCrit, errors, startedAt, null,
                        state.get() == SimulationState.RUNNING
                                ? SimulationState.RUNNING : SimulationState.STOPPED,
                        elapsed);

                if (realtimePublisher != null) {
                    realtimePublisher.publishSimulationProgress(
                            com.nids.threat3d.dto.SimulationProgressResponse.from(currentProgress));
                }

                log.debug("[SimOrchestrator] Progress: {}/{} records, events={}, highCrit={}",
                        processed, totalRecords, eventsOk, highCrit);

                // Small pacing delay between batches so frontend UI can observe live telemetry progression
                if (source.hasMore() && state.get() == SimulationState.RUNNING) {
                    try {
                        Thread.sleep(70);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            // Build final summary from locally collected results
            SimulationSummary summary = buildFinalSummary(scenarioType, totalRecords, allResults, startedAt);

            lastSummary = summary;

            // Transition state only if we weren't stopped
            state.compareAndSet(SimulationState.RUNNING, SimulationState.COMPLETED);

            currentProgress = new SimulationProgress(
                    scenarioType, totalRecords, processed, eventsOk,
                    highCrit, errors, startedAt, Instant.now(), state.get(), summary.getDurationMs());

            if (realtimePublisher != null) {
                realtimePublisher.publishSimulationProgress(
                        com.nids.threat3d.dto.SimulationProgressResponse.from(currentProgress));
                realtimePublisher.publishSimulationSummary(
                        com.nids.threat3d.dto.SimulationSummaryResponse.from(summary, false));
            }

            log.info("[SimOrchestrator] Task finished: state={} processed={} events={} highCrit={} errors={}",
                    state.get(), processed, eventsOk, highCrit, errors);

            return summary;

        } catch (Exception ex) {
            lastError = ex.getMessage();
            state.set(SimulationState.FAILED);
            log.error("[SimOrchestrator] Task FAILED for scenario={}: {}", scenarioType, ex.getMessage(), ex);
            currentProgress = SimulationProgress.failed(scenarioType, ex.getMessage());
            return null;
        }
    }

    private SimulationSummary buildFinalSummary(ScenarioType scenario, int requested,
                                                List<PipelineResult> results,
                                                Instant startedAt) {
        int processed    = 0;
        int eventsOk     = 0;
        int highCrit     = 0;
        int correlated   = 0;
        int errors       = 0;

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
            eventsOk++;
            String sev = r.getDetectionEvent().getSeverity();
            severityCounts.merge(sev, 1, Integer::sum);
            if ("HIGH".equals(sev) || "CRITICAL".equals(sev) || "MEDIUM".equals(sev)) {
                highCrit++;
            }
            if (r.getCorrelationResult() != null) correlated++;
        }

        long durationMs = Math.max(1, java.time.Duration.between(startedAt, Instant.now()).toMillis());
        return new SimulationSummary(
                scenario, requested, processed, eventsOk,
                highCrit, correlated, errors,
                Collections.unmodifiableMap(severityCounts),
                Collections.unmodifiableList(results),
                durationMs
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner types
    // ─────────────────────────────────────────────────────────────────────────

    /** Lifecycle state of the simulation orchestrator. */
    public enum SimulationState {
        /** No simulation is running or has ever run. */
        IDLE,
        /** A simulation task is actively executing. */
        RUNNING,
        /** The last simulation completed normally. */
        COMPLETED,
        /** The user requested a stop; the task exited cleanly. */
        STOPPED,
        /** An unhandled exception aborted the simulation. */
        FAILED
    }

    /** Result of a {@link #startSimulation} call. */
    public static final class StartResult {
        private final boolean      accepted;
        private final ScenarioType scenarioType;
        private final int          recordCount;
        private final String       message;

        private StartResult(boolean accepted, ScenarioType scenarioType,
                            int recordCount, String message) {
            this.accepted     = accepted;
            this.scenarioType = scenarioType;
            this.recordCount  = recordCount;
            this.message      = message;
        }

        public static StartResult accepted(ScenarioType t, int n) {
            return new StartResult(true, t, n,
                    "Simulation accepted: scenario=" + t.name() + " records=" + n);
        }

        public static StartResult rejected(String reason) {
            return new StartResult(false, null, 0, reason);
        }

        public boolean isAccepted()          { return accepted; }
        public ScenarioType getScenarioType(){ return scenarioType; }
        public int getRecordCount()          { return recordCount; }
        public String getMessage()           { return message; }
    }

    /**
     * Immutable progress snapshot — safe to serialize and return in REST responses.
     *
     * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
     */
    public static final class SimulationProgress {
        private final ScenarioType    scenarioType;
        private final int             totalRequested;
        private final int             recordsProcessed;
        private final int             eventsGenerated;
        private final int             highCriticalCount;
        private final int             errorCount;
        private final Instant         startedAt;
        private final Instant         completedAt;  // null while running
        private final SimulationState currentState;
        private final long            durationMs;
        private final String          safetyDisclaimer =
                "SIMULATION ONLY — NO REAL NETWORK CHANGES";

        public SimulationProgress(ScenarioType scenarioType, int totalRequested,
                                  int recordsProcessed, int eventsGenerated,
                                  int highCriticalCount, int errorCount,
                                  Instant startedAt, Instant completedAt,
                                  SimulationState currentState) {
            this(scenarioType, totalRequested, recordsProcessed, eventsGenerated,
                    highCriticalCount, errorCount, startedAt, completedAt, currentState, 0);
        }

        public SimulationProgress(ScenarioType scenarioType, int totalRequested,
                                  int recordsProcessed, int eventsGenerated,
                                  int highCriticalCount, int errorCount,
                                  Instant startedAt, Instant completedAt,
                                  SimulationState currentState,
                                  long durationMs) {
            this.scenarioType      = scenarioType;
            this.totalRequested    = totalRequested;
            this.recordsProcessed  = recordsProcessed;
            this.eventsGenerated   = eventsGenerated;
            this.highCriticalCount = highCriticalCount;
            this.errorCount        = errorCount;
            this.startedAt         = startedAt;
            this.completedAt       = completedAt;
            this.currentState      = currentState;
            this.durationMs        = durationMs;
        }

        static SimulationProgress idle() {
            return new SimulationProgress(null, 0, 0, 0, 0, 0,
                    null, null, SimulationState.IDLE, 0);
        }

        static SimulationProgress starting(ScenarioType t, int total) {
            return new SimulationProgress(t, total, 0, 0, 0, 0,
                    Instant.now(), null, SimulationState.RUNNING, 0);
        }

        static SimulationProgress failed(ScenarioType t, String reason) {
            return new SimulationProgress(t, 0, 0, 0, 0, 1,
                    null, Instant.now(), SimulationState.FAILED, 0);
        }

        /** Completion percentage (0–100). */
        public int getPercentComplete() {
            if (totalRequested == 0) return 0;
            return Math.min(100, (recordsProcessed * 100) / totalRequested);
        }

        public ScenarioType getScenarioType()  { return scenarioType; }
        public int getTotalRequested()         { return totalRequested; }
        public int getRecordsProcessed()       { return recordsProcessed; }
        public int getEventsGenerated()        { return eventsGenerated; }
        public int getHighCriticalCount()      { return highCriticalCount; }
        public int getErrorCount()             { return errorCount; }
        public Instant getStartedAt()          { return startedAt; }
        public Instant getCompletedAt()        { return completedAt; }
        public SimulationState getCurrentState(){ return currentState; }
        public long getDurationMs() {
            if (durationMs > 0) return durationMs;
            if (startedAt != null) {
                Instant end = completedAt != null ? completedAt : Instant.now();
                long elapsed = java.time.Duration.between(startedAt, end).toMillis();
                return (currentState == SimulationState.COMPLETED || currentState == SimulationState.STOPPED)
                        ? Math.max(1, elapsed) : Math.max(0, elapsed);
            }
            return 0;
        }
        public String getSafetyDisclaimer()    { return safetyDisclaimer; }

        @Override
        public String toString() {
            return String.format(
                    "SimulationProgress[state=%s scenario=%s %d/%d (%d%%) " +
                    "events=%d highCrit=%d errors=%d]",
                    currentState, scenarioType, recordsProcessed, totalRequested,
                    getPercentComplete(), eventsGenerated, highCriticalCount, errorCount);
        }
    }
}
