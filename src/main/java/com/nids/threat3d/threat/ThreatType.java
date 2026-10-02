package com.nids.threat3d.threat;

/**
 * Defensive threat taxonomy for network intrusion classification.
 */
public enum ThreatType {
    NORMAL("Normal baseline network activity", "T0000"),
    PORT_SCAN("Reconnaissance probing across multiple ports", "T1046"),
    SYN_FLOOD("High-rate unacknowledged TCP SYN flooding", "T1498"),
    ICMP_FLOOD("High-bandwidth ICMP echo request flooding", "T1498.001"),
    BRUTE_FORCE("Repeated failed authentication against services", "T1110"),
    WEB_ANOMALY("Suspicious application-layer exploit pattern (SQLi/Path traversal)", "T1190"),
    ANOMALOUS_TRAFFIC("Statistical deviation from normal traffic baseline", "T1205"),
    MULTI_STAGE_SUSPICIOUS_ACTIVITY("Correlated multi-vector malicious sequence", "T1595");

    private final String description;
    private final String defaultMitreId;

    ThreatType(String description, String defaultMitreId) {
        this.description = description;
        this.defaultMitreId = defaultMitreId;
    }

    public String getDescription() {
        return description;
    }

    public String getDefaultMitreId() {
        return defaultMitreId;
    }
}
