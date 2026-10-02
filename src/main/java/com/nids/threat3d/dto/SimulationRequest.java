package com.nids.threat3d.dto;

import com.nids.threat3d.simulation.ScenarioType;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * Request DTO — start a named simulation scenario through the NIDS pipeline.
 *
 * <p>Sent as JSON body to {@code POST /api/v2/simulation/start}.</p>
 *
 * <h3>Example</h3>
 * <pre>
 * {
 *   "scenarioType": "SYN_FLOOD_PATTERN",
 *   "recordCount":  100
 * }
 * </pre>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong><br>
 * All traffic is generated in-memory from {@code SyntheticTrafficSource}.
 * No packets are transmitted on any real network interface.</p>
 */
public final class SimulationRequest {

    @NotNull(message = "scenarioType is required")
    private ScenarioType scenarioType;

    @Min(value = 1,   message = "recordCount must be at least 1")
    @Max(value = 500, message = "recordCount must not exceed 500")
    private int recordCount = 100;

    /** Default constructor for Jackson. */
    public SimulationRequest() {}

    public SimulationRequest(ScenarioType scenarioType, int recordCount) {
        this.scenarioType = scenarioType;
        this.recordCount  = recordCount;
    }

    public ScenarioType getScenarioType()        { return scenarioType; }
    public void setScenarioType(ScenarioType v)  { this.scenarioType = v; }

    public int  getRecordCount()                 { return recordCount; }
    public void setRecordCount(int v)            { this.recordCount = v; }
}
