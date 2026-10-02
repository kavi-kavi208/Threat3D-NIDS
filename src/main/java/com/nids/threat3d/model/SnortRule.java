package com.nids.threat3d.model;

import jakarta.persistence.*;

@Entity
@Table(name = "snort_rules")
public class SnortRule {

    @Id
    @Column(nullable = false, length = 64)
    private String id;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false, length = 64)
    private String attackCategory; // DOS, PROBE, EXPLOIT, BRUTE_FORCE, MALWARE

    @Column(nullable = false, length = 32)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(nullable = false, length = 512)
    private String signaturePattern;

    @Column(length = 64)
    private String mitreTechnique;

    @Column(nullable = false)
    private boolean enabled = true;

    public SnortRule() {
    }

    public SnortRule(String id, String name, String attackCategory, String severity,
                     String signaturePattern, String mitreTechnique, boolean enabled) {
        this.id = id;
        this.name = name;
        this.attackCategory = attackCategory;
        this.severity = severity;
        this.signaturePattern = signaturePattern;
        this.mitreTechnique = mitreTechnique;
        this.enabled = enabled;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAttackCategory() {
        return attackCategory;
    }

    public void setAttackCategory(String attackCategory) {
        this.attackCategory = attackCategory;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getSignaturePattern() {
        return signaturePattern;
    }

    public void setSignaturePattern(String signaturePattern) {
        this.signaturePattern = signaturePattern;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }

    public void setMitreTechnique(String mitreTechnique) {
        this.mitreTechnique = mitreTechnique;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
