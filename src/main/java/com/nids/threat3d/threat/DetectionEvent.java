package com.nids.threat3d.threat;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal real-time detection event published whenever a threat is evaluated.
 * Prepared for WebSocket/STOMP streaming in Phase 3.
 */
public class DetectionEvent {

    private final String eventId;
    private final Instant timestamp;
    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;
    private final ThreatType threatType;
    private final double threatScore;
    private final String severity;
    private final String mitreTechnique;
    private final DefenseAction recommendedAction;
    private final String explanation;

    public DetectionEvent(String sourceIp, String destinationIp, int sourcePort, int destinationPort,
                          String protocol, ThreatType threatType, double threatScore,
                          String severity, String mitreTechnique,
                          DefenseAction recommendedAction, String explanation) {
        this.eventId = UUID.randomUUID().toString();
        this.timestamp = Instant.now();
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.threatType = threatType;
        this.threatScore = threatScore;
        this.severity = severity;
        this.mitreTechnique = mitreTechnique;
        this.recommendedAction = recommendedAction;
        this.explanation = explanation;
    }

    public DetectionEvent(String sourceIp, String destinationIp, int destinationPort,
                          String protocol, ThreatType threatType, double threatScore,
                          String severity, String mitreTechnique,
                          DefenseAction recommendedAction, String explanation) {
        this(sourceIp, destinationIp, 0, destinationPort, protocol, threatType, threatScore,
                severity, mitreTechnique, recommendedAction, explanation);
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public ThreatType getThreatType() {
        return threatType;
    }

    public double getThreatScore() {
        return threatScore;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }

    public DefenseAction getRecommendedAction() {
        return recommendedAction;
    }

    public String getExplanation() {
        return explanation;
    }
}
