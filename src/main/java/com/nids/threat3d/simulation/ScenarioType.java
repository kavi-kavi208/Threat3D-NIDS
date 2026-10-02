package com.nids.threat3d.simulation;

/**
 * Defensive simulation scenario types for testing and demonstrating NIDS capabilities.
 * All scenarios are safe, internal synthetic data streams.
 */
public enum ScenarioType {
    NORMAL_TRAFFIC("Normal baseline internal network traffic (HTTP, DNS, DB)", false),
    PORT_SCAN_PATTERN("Reconnaissance port scan across multiple destination ports", true),
    SYN_FLOOD_PATTERN("Denial-of-Service TCP SYN flood pattern with unacknowledged handshakes", true),
    ICMP_FLOOD_PATTERN("Oversized high-rate ICMP Echo ping flood pattern", true),
    BRUTE_FORCE_PATTERN("Repeated failed authentication attempts against SSH service", true),
    WEB_ANOMALY_PATTERN("Suspicious SQL injection-like web request patterns", true),
    MIXED_SUSPICIOUS_ACTIVITY("Multi-stage attack pattern combining scan, brute force, and flood", true);

    private final String description;
    private final boolean suspicious;

    ScenarioType(String description, boolean suspicious) {
        this.description = description;
        this.suspicious = suspicious;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSuspicious() {
        return suspicious;
    }
}
