package com.nids.threat3d.threat;

/**
 * Associates detected suspicious behavior with MITRE ATT&CK enterprise techniques.
 */
public class MitreMapping {

    private final String techniqueId;
    private final String techniqueName;
    private final String reason;
    private final boolean isPotentialMapping;

    public MitreMapping(String techniqueId, String techniqueName, String reason, boolean isPotentialMapping) {
        this.techniqueId = techniqueId;
        this.techniqueName = techniqueName;
        this.reason = reason;
        this.isPotentialMapping = isPotentialMapping;
    }

    public static MitreMapping forThreatType(ThreatType type, String customReason) {
        switch (type) {
            case PORT_SCAN:
                return new MitreMapping("T1046", "Network Service Discovery", customReason != null ? customReason : "Rapid probing across destination ports", false);
            case SYN_FLOOD:
                return new MitreMapping("T1498", "Network Denial of Service: Direct Network Flood", customReason != null ? customReason : "Unacknowledged SYN packet flood exhausting server resources", false);
            case ICMP_FLOOD:
                return new MitreMapping("T1498.001", "Network Denial of Service: Direct Flood", customReason != null ? customReason : "Oversized ICMP echo burst flooding bandwidth", false);
            case BRUTE_FORCE:
                return new MitreMapping("T1110", "Brute Force: Password Guessing", customReason != null ? customReason : "Repeated authentication failures against service port", false);
            case WEB_ANOMALY:
                return new MitreMapping("T1190", "Exploit Public-Facing Application", customReason != null ? customReason : "Application-layer signature tokens detected in URI payload", false);
            case MULTI_STAGE_SUSPICIOUS_ACTIVITY:
                return new MitreMapping("T1595", "Active Scanning & Multi-Stage Attack Sequence", customReason != null ? customReason : "Correlated reconnaissance and exploitation indicators from same source", true);
            case ANOMALOUS_TRAFFIC:
                return new MitreMapping("T1205", "Traffic Signaling / Statistical Anomaly", customReason != null ? customReason : "Unusual feature deviation from normal baseline", true);
            case NORMAL:
            default:
                return new MitreMapping("T0000", "None - Normal Traffic", "Normal operational traffic", false);
        }
    }

    public String getTechniqueId() {
        return techniqueId;
    }

    public String getTechniqueName() {
        return techniqueName;
    }

    public String getReason() {
        return reason;
    }

    public boolean isPotentialMapping() {
        return isPotentialMapping;
    }
}
