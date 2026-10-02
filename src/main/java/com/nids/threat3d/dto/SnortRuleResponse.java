package com.nids.threat3d.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nids.threat3d.model.SnortRule;

/**
 * Dedicated response DTO for Snort detection rules returned by {@code GET /api/v2/detection/rules}.
 *
 * <p>Exposes frontend contract fields: numeric {@code sid}, protocol, port mappings,
 * description, severity, attack category, and the exact {@code mitreTechniqueId}.</p>
 */
public final class SnortRuleResponse {

    @JsonProperty("id")
    private final String id;

    @JsonProperty("sid")
    private final int sid;

    @JsonProperty("name")
    private final String name;

    @JsonProperty("description")
    private final String description;

    @JsonProperty("signaturePattern")
    private final String signaturePattern;

    @JsonProperty("protocol")
    private final String protocol;

    @JsonProperty("sourcePort")
    private final String sourcePort;

    @JsonProperty("destPort")
    private final String destPort;

    @JsonProperty("severity")
    private final String severity;

    @JsonProperty("attackCategory")
    private final String attackCategory;

    @JsonProperty("mitreTechniqueId")
    private final String mitreTechniqueId;

    @JsonProperty("mitreTechnique")
    private final String mitreTechnique;

    @JsonProperty("enabled")
    private final boolean enabled;

    @JsonCreator
    public SnortRuleResponse(
            @JsonProperty("id") String id,
            @JsonProperty("sid") Integer sid,
            @JsonProperty("name") String name,
            @JsonProperty("description") String description,
            @JsonProperty("signaturePattern") String signaturePattern,
            @JsonProperty("protocol") String protocol,
            @JsonProperty("sourcePort") String sourcePort,
            @JsonProperty("destPort") String destPort,
            @JsonProperty("severity") String severity,
            @JsonProperty("attackCategory") String attackCategory,
            @JsonProperty("mitreTechniqueId") String mitreTechniqueId,
            @JsonProperty("mitreTechnique") String mitreTechnique,
            @JsonProperty("enabled") Boolean enabled) {
        this.id = id;
        this.sid = sid != null ? sid : parseSid(id);
        this.name = name;
        this.description = description != null ? description : signaturePattern;
        this.signaturePattern = signaturePattern != null ? signaturePattern : this.description;
        this.protocol = protocol != null ? protocol : "TCP";
        this.sourcePort = sourcePort != null ? sourcePort : "any";
        this.destPort = destPort != null ? destPort : "any";
        this.severity = severity;
        this.attackCategory = attackCategory;
        this.mitreTechniqueId = mitreTechniqueId != null ? mitreTechniqueId : mitreTechnique;
        this.mitreTechnique = this.mitreTechniqueId;
        this.enabled = enabled != null ? enabled : true;
    }

    /** Map a {@link SnortRule} JPA entity to this response DTO with semantic network specs. */
    public static SnortRuleResponse from(SnortRule rule) {
        if (rule == null) return null;
        int sid = parseSid(rule.getId());
        String protocol = "TCP";
        String sourcePort = "any";
        String destPort = "any";

        if ("SID-1001".equalsIgnoreCase(rule.getId())) {
            protocol = "TCP";
            sourcePort = "any";
            destPort = "80,443";
        } else if ("SID-1002".equalsIgnoreCase(rule.getId())) {
            protocol = "TCP";
            sourcePort = "any";
            destPort = "any";
        } else if ("SID-1003".equalsIgnoreCase(rule.getId())) {
            protocol = "TCP";
            sourcePort = "any";
            destPort = "80,8080";
        } else if ("SID-1004".equalsIgnoreCase(rule.getId())) {
            protocol = "TCP";
            sourcePort = "any";
            destPort = "22";
        } else if ("SID-1005".equalsIgnoreCase(rule.getId())) {
            protocol = "ICMP";
            sourcePort = "any";
            destPort = "any";
        }

        return new SnortRuleResponse(
                rule.getId(),
                sid,
                rule.getName(),
                rule.getSignaturePattern(),
                rule.getSignaturePattern(),
                protocol,
                sourcePort,
                destPort,
                rule.getSeverity(),
                rule.getAttackCategory(),
                rule.getMitreTechnique(),
                rule.getMitreTechnique(),
                rule.isEnabled()
        );
    }

    private static int parseSid(String id) {
        if (id == null) return 0;
        String digits = id.replaceAll("[^0-9]", "");
        if (digits.isEmpty()) return 0;
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public String getId() { return id; }
    public int getSid() { return sid; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getSignaturePattern() { return signaturePattern; }
    public String getProtocol() { return protocol; }
    public String getSourcePort() { return sourcePort; }
    public String getDestPort() { return destPort; }
    public String getSeverity() { return severity; }
    public String getAttackCategory() { return attackCategory; }
    public String getMitreTechniqueId() { return mitreTechniqueId; }
    public String getMitreTechnique() { return mitreTechnique; }
    public boolean isEnabled() { return enabled; }
}
