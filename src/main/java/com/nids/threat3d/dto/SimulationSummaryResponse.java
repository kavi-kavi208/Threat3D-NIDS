package com.nids.threat3d.dto;
 
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.SimulationSummary;

import java.util.List;
import java.util.Map;

/**
 * Response DTO for a completed simulation run.
 *
 * <p>Returned by {@code GET /api/v2/simulation/summary} once the state
 * reaches {@code COMPLETED} or {@code STOPPED}.</p>
 *
 * <p>The {@code results} list contains one {@link PipelineResultResponse}
 * per processed record and may be large. Clients may choose to request the
 * summary only (without results) via a query param in the controller.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
public final class SimulationSummaryResponse {

    @JsonProperty("scenarioType")
    private final String                    scenarioType;
    @JsonProperty("requestedRecords")
    private final int                       requestedRecords;
    @JsonProperty("totalRecordsProcessed")
    private final int                       totalRecordsProcessed;
    @JsonProperty("totalEventsGenerated")
    private final int                       totalEventsGenerated;
    @JsonProperty("totalHighCriticalAlerts")
    private final int                       totalHighCriticalAlerts;
    @JsonProperty("totalCorrelated")
    private final int                       totalCorrelated;
    @JsonProperty("correlationsDetected")
    private final int                       correlationsDetected;
    @JsonProperty("totalErrors")
    private final int                       totalErrors;
    @JsonProperty("fullySuccessful")
    private final boolean                   fullySuccessful;
    @JsonProperty("severityBreakdown")
    private final Map<String, Integer>      severityBreakdown;
    @JsonProperty("threatDistribution")
    private final Map<String, Integer>      threatDistribution;
    @JsonProperty("results")
    private final List<PipelineResultResponse> results;  // may be empty when includeResults=false
    @JsonProperty("durationMs")
    private final long                      durationMs;
    @JsonProperty("throughputRecordsPerSec")
    private final double                    throughputRecordsPerSec;
    @JsonProperty("safetyNotice")
    private final String                    safetyNotice =
            "SIMULATION ONLY — NO REAL NETWORK CHANGES";
    @JsonProperty("safetyDisclaimer")
    private final String                    safetyDisclaimer =
            "SIMULATION ONLY — NO REAL NETWORK CHANGES";

    @com.fasterxml.jackson.annotation.JsonCreator
    public SimulationSummaryResponse(
            @JsonProperty("scenarioType") String scenarioType,
            @JsonProperty("requestedRecords") int requestedRecords,
            @JsonProperty("totalRecordsProcessed") int totalRecordsProcessed,
            @JsonProperty("totalEventsGenerated") int totalEventsGenerated,
            @JsonProperty("totalHighCriticalAlerts") int totalHighCriticalAlerts,
            @JsonProperty("totalCorrelated") int totalCorrelated,
            @JsonProperty("correlationsDetected") int correlationsDetected,
            @JsonProperty("totalErrors") int totalErrors,
            @JsonProperty("fullySuccessful") boolean fullySuccessful,
            @JsonProperty("severityBreakdown") Map<String, Integer> severityBreakdown,
            @JsonProperty("threatDistribution") Map<String, Integer> threatDistribution,
            @JsonProperty("results") List<PipelineResultResponse> results,
            @JsonProperty("durationMs") long durationMs,
            @JsonProperty("throughputRecordsPerSec") double throughputRecordsPerSec) {
        this.scenarioType            = scenarioType;
        this.requestedRecords        = requestedRecords;
        this.totalRecordsProcessed   = totalRecordsProcessed;
        this.totalEventsGenerated    = totalEventsGenerated;
        this.totalHighCriticalAlerts = totalHighCriticalAlerts;
        this.totalCorrelated         = totalCorrelated;
        this.correlationsDetected    = correlationsDetected > 0 ? correlationsDetected : totalCorrelated;
        this.totalErrors             = totalErrors;
        this.fullySuccessful         = fullySuccessful;
        this.severityBreakdown       = severityBreakdown != null ? severityBreakdown : Map.of();
        this.threatDistribution      = threatDistribution != null ? threatDistribution : this.severityBreakdown;
        this.results                 = results != null ? results : List.of();
        this.durationMs              = durationMs;
        this.throughputRecordsPerSec = throughputRecordsPerSec;
    }

    private SimulationSummaryResponse(SimulationSummary s, boolean includeResults) {
        this.scenarioType            = s.getScenarioType().name();
        this.requestedRecords        = s.getRequestedRecords();
        this.totalRecordsProcessed   = s.getTotalRecordsProcessed();
        this.totalEventsGenerated    = s.getTotalEventsGenerated();
        this.totalHighCriticalAlerts = s.getTotalHighCriticalAlerts();
        this.totalCorrelated         = s.getTotalCorrelated();
        this.correlationsDetected    = s.getTotalCorrelated();
        this.totalErrors             = s.getTotalErrors();
        this.fullySuccessful         = s.isFullySuccessful();
        this.severityBreakdown       = s.getSeverityBreakdown();
        this.threatDistribution      = s.getSeverityBreakdown();
        this.durationMs              = s.getDurationMs();
        this.throughputRecordsPerSec = s.getThroughputRecordsPerSec();
        this.results = includeResults
                ? s.getResults().stream()
                     .map(PipelineResultResponse::from)
                     .toList()
                : List.of();
    }

    /**
     * Map a {@link SimulationSummary} to this DTO.
     *
     * @param summary        the completed summary
     * @param includeResults whether to embed per-record results (may be large)
     */
    public static SimulationSummaryResponse from(SimulationSummary summary,
                                                  boolean includeResults) {
        return summary == null ? null : new SimulationSummaryResponse(summary, includeResults);
    }

    /** Convenience factory — excludes per-record results. */
    public static SimulationSummaryResponse from(SimulationSummary summary) {
        return from(summary, false);
    }

    public String                       getScenarioType()            { return scenarioType; }
    public int                          getRequestedRecords()        { return requestedRecords; }
    public int                          getTotalRecordsProcessed()   { return totalRecordsProcessed; }
    public int                          getTotalEventsGenerated()    { return totalEventsGenerated; }
    public int                          getTotalHighCriticalAlerts() { return totalHighCriticalAlerts; }
    public int                          getTotalCorrelated()         { return totalCorrelated; }
    public int                          getTotalErrors()             { return totalErrors; }
    public boolean                      isFullySuccessful()          { return fullySuccessful; }
    public Map<String, Integer>         getSeverityBreakdown()       { return severityBreakdown; }
    public List<PipelineResultResponse> getResults()                 { return results; }
    public long                         getDurationMs()              { return durationMs; }
    public double                       getThroughputRecordsPerSec() { return throughputRecordsPerSec; }
    public Map<String, Integer>         getThreatDistribution()       { return severityBreakdown; }
    public int                          getCorrelationsDetected()    { return totalCorrelated; }
    public String                       getSafetyNotice()            { return safetyNotice; }
    public String                       getSafetyDisclaimer()        { return safetyDisclaimer; }
}
