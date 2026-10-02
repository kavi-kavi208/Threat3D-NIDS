package com.nids.threat3d.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * Response DTO summarising threat alert statistics from the H2 database.
 *
 * <p>Returned by {@code GET /api/v2/threats/summary}.</p>
 */
public final class ThreatSummaryResponse {

    @JsonProperty("totalAlerts")
    private final long              totalAlerts;
    @JsonProperty("activeAlerts")
    private final long              activeAlerts;
    @JsonProperty("mitigatedAlerts")
    private final long              mitigatedAlerts;
    @JsonProperty("countBySeverity")
    private final Map<String, Long> countBySeverity;    // LOW/MEDIUM/HIGH/CRITICAL → count
    @JsonProperty("severityCounts")
    private final Map<String, Long> severityCounts;
    @JsonProperty("countByAttackType")
    private final Map<String, Long> countByAttackType;  // threatType.name() → count
    @JsonProperty("attackTypeCounts")
    private final Map<String, Long> attackTypeCounts;

    @JsonCreator
    public ThreatSummaryResponse(
            @JsonProperty("totalAlerts") long totalAlerts,
            @JsonProperty("activeAlerts") long activeAlerts,
            @JsonProperty("mitigatedAlerts") long mitigatedAlerts,
            @JsonProperty("countBySeverity") Map<String, Long> countBySeverity,
            @JsonProperty("severityCounts") Map<String, Long> severityCounts,
            @JsonProperty("countByAttackType") Map<String, Long> countByAttackType,
            @JsonProperty("attackTypeCounts") Map<String, Long> attackTypeCounts) {
        this.totalAlerts       = totalAlerts;
        this.activeAlerts      = activeAlerts;
        this.mitigatedAlerts   = mitigatedAlerts;
        this.countBySeverity   = countBySeverity != null ? countBySeverity : (severityCounts != null ? severityCounts : Map.of());
        this.severityCounts    = this.countBySeverity;
        this.countByAttackType = countByAttackType != null ? countByAttackType : (attackTypeCounts != null ? attackTypeCounts : Map.of());
        this.attackTypeCounts  = this.countByAttackType;
    }

    public ThreatSummaryResponse(long totalAlerts, long activeAlerts, long mitigatedAlerts,
                                 Map<String, Long> countBySeverity,
                                 Map<String, Long> countByAttackType) {
        this(totalAlerts, activeAlerts, mitigatedAlerts, countBySeverity, countBySeverity, countByAttackType, countByAttackType);
    }

    public long              getTotalAlerts()       { return totalAlerts; }
    public long              getActiveAlerts()      { return activeAlerts; }
    public long              getMitigatedAlerts()   { return mitigatedAlerts; }
    public Map<String, Long> getCountBySeverity()   { return countBySeverity; }
    public Map<String, Long> getSeverityCounts()    { return severityCounts; }
    public Map<String, Long> getCountByAttackType() { return countByAttackType; }
    public Map<String, Long> getAttackTypeCounts()  { return attackTypeCounts; }
}
