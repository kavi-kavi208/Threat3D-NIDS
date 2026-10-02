package com.nids.threat3d.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nids.threat3d.model.ThreatAlert;

import java.time.LocalDateTime;

/**
 * Response DTO for a persisted {@link ThreatAlert} entity from the H2 database.
 *
 * <p>Returned by {@code GET /api/v2/threats} and related endpoints.</p>
 */
public final class ThreatAlertResponse {

    @JsonProperty("id")
    private final Long          id;
    @JsonProperty("timestamp")
    private final LocalDateTime timestamp;
    @JsonProperty("ruleId")
    private final String        ruleId;
    @JsonProperty("signatureRule")
    private final String        signatureRule;
    @JsonProperty("srcIp")
    private final String        srcIp;
    @JsonProperty("sourceIp")
    private final String        sourceIp;
    @JsonProperty("dstIp")
    private final String        dstIp;
    @JsonProperty("destinationIp")
    private final String        destinationIp;
    @JsonProperty("srcPort")
    private final int           srcPort;
    @JsonProperty("sourcePort")
    private final int           sourcePort;
    @JsonProperty("dstPort")
    private final int           dstPort;
    @JsonProperty("destinationPort")
    private final int           destinationPort;
    @JsonProperty("protocol")
    private final String        protocol;
    @JsonProperty("attackType")
    private final String        attackType;
    @JsonProperty("severity")
    private final String        severity;
    @JsonProperty("confidenceScore")
    private final float         confidenceScore;  // 0.0 – 1.0
    @JsonProperty("threatScore")
    private final int           threatScore;      // 0 – 100
    @JsonProperty("mitigationStatus")
    private final String        mitigationStatus;
    @JsonProperty("mitreTechnique")
    private final String        mitreTechnique;
    @JsonProperty("mitreTechniqueId")
    private final String        mitreTechniqueId;
    @JsonProperty("details")
    private final String        details;
    @JsonProperty("description")
    private final String        description;

    @JsonCreator
    public ThreatAlertResponse(
            @JsonProperty("id") Long id,
            @JsonProperty("timestamp") LocalDateTime timestamp,
            @JsonProperty("ruleId") String ruleId,
            @JsonProperty("signatureRule") String signatureRule,
            @JsonProperty("srcIp") String srcIp,
            @JsonProperty("sourceIp") String sourceIp,
            @JsonProperty("dstIp") String dstIp,
            @JsonProperty("destinationIp") String destinationIp,
            @JsonProperty("srcPort") Integer srcPort,
            @JsonProperty("sourcePort") Integer sourcePort,
            @JsonProperty("dstPort") Integer dstPort,
            @JsonProperty("destinationPort") Integer destinationPort,
            @JsonProperty("protocol") String protocol,
            @JsonProperty("attackType") String attackType,
            @JsonProperty("severity") String severity,
            @JsonProperty("confidenceScore") Float confidenceScore,
            @JsonProperty("threatScore") Integer threatScore,
            @JsonProperty("mitigationStatus") String mitigationStatus,
            @JsonProperty("mitreTechnique") String mitreTechnique,
            @JsonProperty("mitreTechniqueId") String mitreTechniqueId,
            @JsonProperty("details") String details,
            @JsonProperty("description") String description) {
        this.id               = id;
        this.timestamp        = timestamp;
        this.ruleId           = ruleId != null ? ruleId : signatureRule;
        this.signatureRule    = this.ruleId;
        this.srcIp            = srcIp != null ? srcIp : sourceIp;
        this.sourceIp         = this.srcIp;
        this.dstIp            = dstIp != null ? dstIp : destinationIp;
        this.destinationIp    = this.dstIp;
        this.srcPort          = srcPort != null ? srcPort : (sourcePort != null ? sourcePort : 0);
        this.sourcePort       = this.srcPort;
        this.dstPort          = dstPort != null ? dstPort : (destinationPort != null ? destinationPort : 0);
        this.destinationPort  = this.dstPort;
        this.protocol         = protocol != null ? protocol : "TCP";
        this.attackType       = attackType;
        this.severity         = severity;
        if (confidenceScore != null) {
            this.confidenceScore = confidenceScore;
            this.threatScore = threatScore != null ? threatScore : Math.round(confidenceScore * 100.0f);
        } else if (threatScore != null) {
            this.threatScore = threatScore;
            this.confidenceScore = threatScore / 100.0f;
        } else {
            this.confidenceScore = 0.0f;
            this.threatScore = 0;
        }
        this.mitigationStatus = mitigationStatus;
        this.mitreTechnique   = mitreTechnique != null ? mitreTechnique : mitreTechniqueId;
        this.mitreTechniqueId = this.mitreTechnique;
        this.details          = details != null ? details : description;
        this.description      = this.details;
    }

    private ThreatAlertResponse(ThreatAlert a) {
        this.id               = a.getId();
        this.timestamp        = a.getTimestamp();
        this.ruleId           = a.getRuleId();
        this.signatureRule    = a.getRuleId();
        this.srcIp            = a.getSrcIp();
        this.sourceIp         = a.getSrcIp();
        this.dstIp            = a.getDstIp();
        this.destinationIp    = a.getDstIp();
        this.srcPort          = a.getSrcPort() != null ? a.getSrcPort() : 0;
        this.sourcePort       = this.srcPort;
        this.dstPort          = a.getDstPort() != null ? a.getDstPort() : 0;
        this.destinationPort  = this.dstPort;
        this.protocol         = a.getProtocol() != null ? a.getProtocol() : "TCP";
        this.attackType       = a.getAttackType();
        this.severity         = a.getSeverity();
        this.confidenceScore  = a.getConfidenceScore();
        this.threatScore      = Math.round(a.getConfidenceScore() * 100.0f);
        this.mitigationStatus = a.getMitigationStatus();
        this.mitreTechnique   = a.getMitreTechnique();
        this.mitreTechniqueId = a.getMitreTechnique();
        this.details          = a.getDetails();
        this.description      = a.getDetails();
    }

    /** Map a {@link ThreatAlert} JPA entity to this response DTO. */
    public static ThreatAlertResponse from(ThreatAlert alert) {
        return alert == null ? null : new ThreatAlertResponse(alert);
    }

    public Long          getId()               { return id; }
    public LocalDateTime getTimestamp()        { return timestamp; }
    public String        getRuleId()           { return ruleId; }
    public String        getSignatureRule()    { return signatureRule; }
    public String        getSrcIp()            { return srcIp; }
    public String        getSourceIp()         { return sourceIp; }
    public String        getDstIp()            { return dstIp; }
    public String        getDestinationIp()    { return destinationIp; }
    public int           getSrcPort()          { return srcPort; }
    public int           getSourcePort()       { return sourcePort; }
    public int           getDstPort()          { return dstPort; }
    public int           getDestinationPort()  { return destinationPort; }
    public String        getProtocol()         { return protocol; }
    public String        getAttackType()       { return attackType; }
    public String        getSeverity()         { return severity; }
    public float         getConfidenceScore()  { return confidenceScore; }
    public int           getThreatScore()      { return threatScore; }
    public String        getMitigationStatus() { return mitigationStatus; }
    public String        getMitreTechnique()   { return mitreTechnique; }
    public String        getMitreTechniqueId() { return mitreTechniqueId; }
    public String        getDetails()          { return details; }
    public String        getDescription()      { return description; }
}
