package com.nids.threat3d.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nids.threat3d.simulation.SimulationOrchestrator.SimulationProgress;
import com.nids.threat3d.simulation.SimulationOrchestrator.SimulationState;
import com.nids.threat3d.simulation.ScenarioType;

import java.time.Instant;

/**
 * Response DTO exposing live simulation progress to REST clients.
 *
 * <p>Returned by {@code GET /api/v2/simulation/status}.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
public final class SimulationProgressResponse {

    @JsonProperty("scenarioType")
    private final String  scenarioType;       // null when IDLE
    @JsonProperty("totalRequested")
    private final int     totalRequested;
    @JsonProperty("recordsTotal")
    private final int     recordsTotal;
    @JsonProperty("recordsProcessed")
    private final int     recordsProcessed;
    @JsonProperty("eventsGenerated")
    private final int     eventsGenerated;
    @JsonProperty("highCriticalCount")
    private final int     highCriticalCount;
    @JsonProperty("highCriticalAlerts")
    private final int     highCriticalAlerts;
    @JsonProperty("errorCount")
    private final int     errorCount;
    @JsonProperty("percentComplete")
    private final int     percentComplete;    // 0–100
    @JsonProperty("completionPercent")
    private final int     completionPercent;
    @JsonProperty("startedAt")
    private final Instant startedAt;
    @JsonProperty("startTime")
    private final Instant startTime;
    @JsonProperty("completedAt")
    private final Instant completedAt;
    @JsonProperty("currentState")
    private final String  currentState;       // SimulationState.name()
    @JsonProperty("state")
    private final String  state;
    @JsonProperty("durationMs")
    private final long    durationMs;
    @JsonProperty("safetyDisclaimer")
    private final String  safetyDisclaimer;

    @com.fasterxml.jackson.annotation.JsonCreator
    public SimulationProgressResponse(
            @JsonProperty("scenarioType") String scenarioType,
            @JsonProperty("totalRequested") int totalRequested,
            @JsonProperty("recordsTotal") int recordsTotal,
            @JsonProperty("recordsProcessed") int recordsProcessed,
            @JsonProperty("eventsGenerated") int eventsGenerated,
            @JsonProperty("highCriticalCount") int highCriticalCount,
            @JsonProperty("highCriticalAlerts") int highCriticalAlerts,
            @JsonProperty("errorCount") int errorCount,
            @JsonProperty("percentComplete") int percentComplete,
            @JsonProperty("completionPercent") int completionPercent,
            @JsonProperty("startedAt") Instant startedAt,
            @JsonProperty("startTime") Instant startTime,
            @JsonProperty("completedAt") Instant completedAt,
            @JsonProperty("currentState") String currentState,
            @JsonProperty("state") String state,
            @JsonProperty("durationMs") long durationMs,
            @JsonProperty("safetyDisclaimer") String safetyDisclaimer) {
        this.scenarioType       = scenarioType;
        this.totalRequested     = totalRequested > 0 ? totalRequested : recordsTotal;
        this.recordsTotal       = this.totalRequested;
        this.recordsProcessed   = recordsProcessed;
        this.eventsGenerated    = eventsGenerated;
        this.highCriticalCount  = highCriticalCount > 0 ? highCriticalCount : highCriticalAlerts;
        this.highCriticalAlerts = this.highCriticalCount;
        this.errorCount         = errorCount;
        this.percentComplete    = percentComplete > 0 ? percentComplete : completionPercent;
        this.completionPercent  = this.percentComplete;
        this.startedAt          = startedAt != null ? startedAt : startTime;
        this.startTime          = this.startedAt;
        this.completedAt        = completedAt;
        this.currentState       = currentState != null ? currentState : (state != null ? state : "IDLE");
        this.state              = this.currentState;
        if (durationMs > 0) {
            this.durationMs     = durationMs;
        } else if (this.startedAt != null) {
            Instant end = this.completedAt != null ? this.completedAt : Instant.now();
            long elapsed = java.time.Duration.between(this.startedAt, end).toMillis();
            this.durationMs     = ("COMPLETED".equalsIgnoreCase(this.currentState) || "STOPPED".equalsIgnoreCase(this.currentState))
                    ? Math.max(1, elapsed) : Math.max(0, elapsed);
        } else {
            this.durationMs     = 0;
        }
        this.safetyDisclaimer   = safetyDisclaimer != null ? safetyDisclaimer : "SIMULATION ONLY — NO REAL NETWORK CHANGES";
    }

    private SimulationProgressResponse(SimulationProgress p) {
        this.scenarioType       = p.getScenarioType() != null ? p.getScenarioType().name() : null;
        this.totalRequested     = p.getTotalRequested();
        this.recordsTotal       = p.getTotalRequested();
        this.recordsProcessed   = p.getRecordsProcessed();
        this.eventsGenerated    = p.getEventsGenerated();
        this.highCriticalCount  = p.getHighCriticalCount();
        this.highCriticalAlerts = p.getHighCriticalCount();
        this.errorCount         = p.getErrorCount();
        this.percentComplete    = p.getPercentComplete();
        this.completionPercent  = p.getPercentComplete();
        this.startedAt          = p.getStartedAt();
        this.startTime          = p.getStartedAt();
        this.completedAt        = p.getCompletedAt();
        this.currentState       = p.getCurrentState().name();
        this.state              = p.getCurrentState().name();
        this.safetyDisclaimer   = p.getSafetyDisclaimer();

        if (p.getDurationMs() > 0) {
            this.durationMs = p.getDurationMs();
        } else if (p.getStartedAt() != null) {
            Instant end = p.getCompletedAt() != null ? p.getCompletedAt() : Instant.now();
            long elapsed = java.time.Duration.between(p.getStartedAt(), end).toMillis();
            this.durationMs = (p.getCurrentState() == SimulationState.COMPLETED || p.getCurrentState() == SimulationState.STOPPED)
                    ? Math.max(1, elapsed) : Math.max(0, elapsed);
        } else {
            this.durationMs = 0;
        }
    }

    /** Map a {@link SimulationProgress} snapshot to this DTO. */
    public static SimulationProgressResponse from(SimulationProgress progress) {
        return progress == null ? null : new SimulationProgressResponse(progress);
    }

    public String  getScenarioType()      { return scenarioType; }
    public int     getTotalRequested()    { return totalRequested; }
    public int     getRecordsTotal()      { return recordsTotal; }
    public int     getRecordsProcessed()  { return recordsProcessed; }
    public int     getEventsGenerated()   { return eventsGenerated; }
    public int     getHighCriticalCount() { return highCriticalCount; }
    public int     getHighCriticalAlerts(){ return highCriticalAlerts; }
    public int     getErrorCount()        { return errorCount; }
    public int     getPercentComplete()   { return percentComplete; }
    public int     getCompletionPercent() { return completionPercent; }
    public Instant getStartedAt()         { return startedAt; }
    public Instant getStartTime()         { return startTime; }
    public Instant getCompletedAt()       { return completedAt; }
    public String  getCurrentState()      { return currentState; }
    public String  getState()             { return state; }
    public long    getDurationMs()        { return durationMs; }
    public String  getSafetyDisclaimer()  { return safetyDisclaimer; }
}
