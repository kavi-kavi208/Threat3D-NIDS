package com.nids.threat3d.controller;

import com.nids.threat3d.dto.ApiResponse;
import com.nids.threat3d.dto.SimulationProgressResponse;
import com.nids.threat3d.dto.SimulationRequest;
import com.nids.threat3d.dto.SimulationSummaryResponse;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.SimulationSummary;
import com.nids.threat3d.simulation.ScenarioType;
import com.nids.threat3d.simulation.SimulationOrchestrator;
import com.nids.threat3d.simulation.SimulationOrchestrator.SimulationProgress;
import com.nids.threat3d.simulation.SimulationOrchestrator.StartResult;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Safe Simulation Orchestration Controller — Phase 2 REST API.
 *
 * <p>Provides endpoints to list scenarios, launch/stop/reset asynchronous
 * synthetic traffic simulations, and poll real-time progress and summaries.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong><br>
 * All traffic is generated in-memory and evaluated defensively. No actual packets
 * are injected into any live interface or external network.</p>
 */
@RestController
@RequestMapping({"/api/v2/simulation", "/api/v1/simulation"})
public class SimulationController {

    private static final Logger log = LoggerFactory.getLogger(SimulationController.class);

    private final SimulationOrchestrator orchestrator;

    public SimulationController(SimulationOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    /**
     * List all available safe synthetic simulation scenarios.
     */
    @GetMapping("/scenarios")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getScenarios() {
        List<Map<String, Object>> scenarios = new ArrayList<>();
        for (ScenarioType type : orchestrator.getAvailableScenarios()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("type", type.name());
            item.put("description", getScenarioDescription(type));
            scenarios.add(item);
        }

        return ResponseEntity.ok(ApiResponse.ok(scenarios));
    }

    /**
     * Start an asynchronous simulation run.
     */
    @PostMapping("/start")
    public ResponseEntity<ApiResponse<StartResult>> startSimulation(
            @Valid @RequestBody SimulationRequest request) {

        log.info("[SimulationController] Start request: scenario={}, records={}",
                request.getScenarioType(), request.getRecordCount());

        StartResult result = orchestrator.startSimulation(
                request.getScenarioType(), request.getRecordCount());

        if (!result.isAccepted()) {
            log.warn("[SimulationController] Simulation rejected: {}", result.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.error(result.getMessage()));
        }

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ApiResponse.ok(result.getMessage(), result));
    }

    /**
     * Cooperatively stop the currently running simulation.
     */
    @PostMapping("/stop")
    public ResponseEntity<ApiResponse<String>> stopSimulation() {
        boolean stopped = orchestrator.stopSimulation();
        if (stopped) {
            log.info("[SimulationController] Stop requested for active simulation");
            return ResponseEntity.ok(ApiResponse.ok("Simulation stop requested successfully", "STOPPING"));
        } else {
            return ResponseEntity.ok(ApiResponse.ok("No active simulation to stop", "IDLE"));
        }
    }

    /**
     * Reset the simulation orchestrator and detection pipeline state (ADMIN or ANALYST only).
     */
    @PostMapping("/reset")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYST')")
    public ResponseEntity<ApiResponse<String>> resetSimulation() {
        try {
            orchestrator.reset();
            log.info("[SimulationController] Simulation and pipeline state reset");
            return ResponseEntity.ok(ApiResponse.ok("Simulation orchestrator and pipeline reset successfully", "IDLE"));
        } catch (IllegalStateException ex) {
            log.warn("[SimulationController] Cannot reset active simulation: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.error(ex.getMessage()));
        }
    }

    /**
     * Poll real-time progress and status of the current or most recent simulation.
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<SimulationProgressResponse>> getSimulationStatus() {
        SimulationProgress progress = orchestrator.getProgress();
        return ResponseEntity.ok(ApiResponse.ok(SimulationProgressResponse.from(progress)));
    }

    /**
     * Retrieve the comprehensive summary of the last completed simulation run.
     */
    @GetMapping("/summary")
    public ResponseEntity<ApiResponse<SimulationSummaryResponse>> getSimulationSummary(
            @RequestParam(required = false, defaultValue = "false") boolean includeResults) {

        SimulationSummary summary = orchestrator.getLastSummary();
        if (summary == null) {
            return ResponseEntity.ok(ApiResponse.ok("No completed simulation summary available", null));
        }

        return ResponseEntity.ok(ApiResponse.ok(SimulationSummaryResponse.from(summary, includeResults)));
    }

    private String getScenarioDescription(ScenarioType type) {
        return switch (type) {
            case NORMAL_TRAFFIC -> "Simulated baseline HTTP, DNS, and database enterprise traffic";
            case PORT_SCAN_PATTERN -> "Rapid sequential and random port probing pattern against target host";
            case SYN_FLOOD_PATTERN -> "High-volume unacknowledged TCP SYN packets targeting HTTP port";
            case ICMP_FLOOD_PATTERN -> "Burst of oversized ICMP echo request packets exhausting bandwidth";
            case BRUTE_FORCE_PATTERN -> "Repeated SSH authentication failure bursts against port 22";
            case WEB_ANOMALY_PATTERN -> "Suspicious SQL injection and directory traversal application tokens";
            case MIXED_SUSPICIOUS_ACTIVITY -> "Multi-stage sequence: port scan reconnaissance followed by brute-force and flood";
        };
    }
}
