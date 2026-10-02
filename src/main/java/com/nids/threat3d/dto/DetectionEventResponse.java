package com.nids.threat3d.dto;

import com.nids.threat3d.threat.DetectionEvent;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.ThreatType;

import java.time.Instant;

/**
 * Response DTO representing a single scored {@link DetectionEvent}.
 *
 * <p>Returned by {@code POST /api/v2/traffic/analyze} and from
 * simulation result lists.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
public final class DetectionEventResponse {

    private final String  eventId;
    private final Instant timestamp;
    private final String  sourceIp;
    private final String  destinationIp;
    private final int     sourcePort;
    private final int     destinationPort;
    private final String  protocol;
    private final String  threatType;
    private final int     threatScore;        // 0–100
    private final String  severity;           // LOW / MEDIUM / HIGH / CRITICAL
    private final String  mitreTechnique;
    private final String  recommendedAction;  // [SIMULATED] prefixed label
    private final String  explanation;
    private final String  safetyDisclaimer = "SIMULATION ONLY — NO REAL NETWORK CHANGES";

    private DetectionEventResponse(Builder b) {
        this.eventId         = b.eventId;
        this.timestamp       = b.timestamp;
        this.sourceIp        = b.sourceIp;
        this.destinationIp   = b.destinationIp;
        this.sourcePort      = b.sourcePort;
        this.destinationPort = b.destinationPort;
        this.protocol        = b.protocol;
        this.threatType      = b.threatType;
        this.threatScore     = b.threatScore;
        this.severity        = b.severity;
        this.mitreTechnique  = b.mitreTechnique;
        this.recommendedAction = b.recommendedAction;
        this.explanation     = b.explanation;
    }

    /** Map a {@link DetectionEvent} to this response DTO. */
    public static DetectionEventResponse from(DetectionEvent event) {
        if (event == null) return null;
        return new Builder()
                .eventId(event.getEventId())
                .timestamp(event.getTimestamp())
                .sourceIp(event.getSourceIp())
                .destinationIp(event.getDestinationIp())
                .sourcePort(event.getSourcePort())
                .destinationPort(event.getDestinationPort())
                .protocol(event.getProtocol())
                .threatType(event.getThreatType().name())
                .threatScore((int) event.getThreatScore())
                .severity(event.getSeverity())
                .mitreTechnique(event.getMitreTechnique())
                .recommendedAction("[SIMULATED] " + event.getRecommendedAction().name())
                .explanation(event.getExplanation())
                .build();
    }

    public String  getEventId()          { return eventId; }
    public Instant getTimestamp()        { return timestamp; }
    public String  getSourceIp()         { return sourceIp; }
    public String  getDestinationIp()    { return destinationIp; }
    public int     getSourcePort()       { return sourcePort; }
    public int     getDestinationPort()  { return destinationPort; }
    public String  getProtocol()         { return protocol; }
    public String  getThreatType()       { return threatType; }
    public int     getThreatScore()      { return threatScore; }
    public String  getSeverity()         { return severity; }
    public String  getMitreTechnique()   { return mitreTechnique; }
    public String  getRecommendedAction(){ return recommendedAction; }
    public String  getExplanation()      { return explanation; }
    public String  getSafetyDisclaimer() { return safetyDisclaimer; }

    // ── Builder ───────────────────────────────────────────────────────────────
    private static final class Builder {
        private String  eventId;
        private Instant timestamp;
        private String  sourceIp;
        private String  destinationIp;
        private int     sourcePort;
        private int     destinationPort;
        private String  protocol;
        private String  threatType;
        private int     threatScore;
        private String  severity;
        private String  mitreTechnique;
        private String  recommendedAction;
        private String  explanation;

        Builder eventId(String v)           { this.eventId = v;          return this; }
        Builder timestamp(Instant v)        { this.timestamp = v;        return this; }
        Builder sourceIp(String v)          { this.sourceIp = v;         return this; }
        Builder destinationIp(String v)     { this.destinationIp = v;    return this; }
        Builder sourcePort(int v)           { this.sourcePort = v;       return this; }
        Builder destinationPort(int v)      { this.destinationPort = v;  return this; }
        Builder protocol(String v)          { this.protocol = v;         return this; }
        Builder threatType(String v)        { this.threatType = v;       return this; }
        Builder threatScore(int v)          { this.threatScore = v;      return this; }
        Builder severity(String v)          { this.severity = v;         return this; }
        Builder mitreTechnique(String v)    { this.mitreTechnique = v;   return this; }
        Builder recommendedAction(String v) { this.recommendedAction = v;return this; }
        Builder explanation(String v)       { this.explanation = v;      return this; }
        DetectionEventResponse build()      { return new DetectionEventResponse(this); }
    }
}
