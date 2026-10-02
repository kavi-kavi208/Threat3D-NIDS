package com.nids.threat3d.threat;

/**
 * Defensive simulated countermeasures.
 * strictly simulations only — NEVER modifies real firewall or network settings.
 */
public enum DefenseAction {
    MONITOR("Monitor flow without intervention"),
    ALERT("Raise security alert for analyst inspection"),
    RECOMMEND_RATE_LIMIT("Recommend applying simulated rate limiting to source IP"),
    RECOMMEND_BLOCK("Recommend adding simulated IP drop rule to perimeter firewall"),
    ISOLATE_SIMULATION_NODE("Recommend isolating simulated compromised node in topology");

    public static final String SAFETY_DISCLAIMER = "SIMULATION ONLY — NO REAL NETWORK CHANGES";

    private final String description;

    DefenseAction(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
