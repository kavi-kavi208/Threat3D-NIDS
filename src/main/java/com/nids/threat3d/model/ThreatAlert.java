package com.nids.threat3d.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_alerts")
public class ThreatAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now();

    @Column(length = 64)
    private String ruleId;

    @Column(nullable = false, length = 64)
    private String srcIp;

    @Column(nullable = false, length = 64)
    private String dstIp;

    @Column(name = "src_port")
    private Integer srcPort;

    @Column(name = "dst_port")
    private Integer dstPort;

    @Column(length = 16)
    private String protocol;

    @Column(nullable = false, length = 128)
    private String attackType;

    @Column(nullable = false, length = 32)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(nullable = false)
    private float confidenceScore; // 0.0 to 1.0

    @Column(nullable = false, length = 32)
    private String mitigationStatus; // ACTIVE, MITIGATED, BLOCKED, IGNORED

    @Column(length = 64)
    private String mitreTechnique; // e.g. T1498, T1046, T1190

    @Column(length = 1024)
    private String details;

    public ThreatAlert() {
    }

    public ThreatAlert(String ruleId, String srcIp, String dstIp, String attackType,
                       String severity, float confidenceScore, String mitigationStatus,
                       String mitreTechnique, String details) {
        this(ruleId, srcIp, dstIp, null, null, null, attackType, severity, confidenceScore, mitigationStatus, mitreTechnique, details);
    }

    public ThreatAlert(String ruleId, String srcIp, String dstIp,
                       Integer srcPort, Integer dstPort, String protocol,
                       String attackType, String severity, float confidenceScore,
                       String mitigationStatus, String mitreTechnique, String details) {
        this.ruleId = ruleId;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.attackType = attackType;
        this.severity = severity;
        this.confidenceScore = confidenceScore;
        this.mitigationStatus = mitigationStatus;
        this.mitreTechnique = mitreTechnique;
        this.details = details;
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public float getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(float confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public String getMitigationStatus() {
        return mitigationStatus;
    }

    public void setMitigationStatus(String mitigationStatus) {
        this.mitigationStatus = mitigationStatus;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }

    public void setMitreTechnique(String mitreTechnique) {
        this.mitreTechnique = mitreTechnique;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Integer getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(Integer srcPort) {
        this.srcPort = srcPort;
    }

    public Integer getDstPort() {
        return dstPort;
    }

    public void setDstPort(Integer dstPort) {
        this.dstPort = dstPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
}
