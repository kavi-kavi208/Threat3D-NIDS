package com.nids.threat3d.controller;

import com.nids.threat3d.dto.ApiResponse;
import com.nids.threat3d.dto.ThreatAlertResponse;
import com.nids.threat3d.dto.ThreatSummaryResponse;
import com.nids.threat3d.exception.ResourceNotFoundException;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.repository.ThreatAlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Threat & Alert Management Controller — Phase 2 REST API.
 *
 * <p>Provides endpoints to query threat alerts, inspect alert details, view
 * summary statistics, and manage alert mitigation states.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@RestController
@RequestMapping({"/api/v2/threats", "/api/v1/threats"})
public class ThreatController {

    private static final Logger log = LoggerFactory.getLogger(ThreatController.class);

    private final ThreatAlertRepository alertRepository;

    public ThreatController(ThreatAlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    /**
     * Retrieve persisted threat alerts with optional severity filtering.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ThreatAlertResponse>>> getAlerts(
            @RequestParam(required = false) String severity) {

        List<ThreatAlert> alerts;
        if (severity != null && !severity.isBlank()) {
            alerts = alertRepository.findBySeverity(severity.trim().toUpperCase());
        } else {
            alerts = alertRepository.findTop50ByOrderByTimestampDesc();
        }

        List<ThreatAlertResponse> responseList = alerts.stream()
                .map(ThreatAlertResponse::from)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(responseList));
    }

    /**
     * Retrieve a specific threat alert by its primary key ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ThreatAlertResponse>> getAlertById(@PathVariable Long id) {
        ThreatAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat alert not found with ID: " + id));

        return ResponseEntity.ok(ApiResponse.ok(ThreatAlertResponse.from(alert)));
    }

    /**
     * Retrieve statistical summary of alerts grouped by severity and attack type.
     */
    @GetMapping("/summary")
    public ResponseEntity<ApiResponse<ThreatSummaryResponse>> getThreatSummary() {
        long totalAlerts = alertRepository.count();
        long activeAlerts = alertRepository.countByMitigationStatus("ACTIVE");
        long mitigatedAlerts = alertRepository.countByMitigationStatus("MITIGATED");

        Map<String, Long> severityCounts = new LinkedHashMap<>();
        severityCounts.put("LOW", (long) alertRepository.findBySeverity("LOW").size());
        severityCounts.put("MEDIUM", (long) alertRepository.findBySeverity("MEDIUM").size());
        severityCounts.put("HIGH", (long) alertRepository.findBySeverity("HIGH").size());
        severityCounts.put("CRITICAL", (long) alertRepository.findBySeverity("CRITICAL").size());

        List<ThreatAlert> allAlerts = alertRepository.findAll();
        Map<String, Long> attackTypeCounts = allAlerts.stream()
                .collect(Collectors.groupingBy(ThreatAlert::getAttackType, Collectors.counting()));

        ThreatSummaryResponse summary = new ThreatSummaryResponse(
                totalAlerts, activeAlerts, mitigatedAlerts, severityCounts, attackTypeCounts
        );

        return ResponseEntity.ok(ApiResponse.ok(summary));
    }

    /**
     * Update the mitigation status of a threat alert (ADMIN or ANALYST only).
     */
    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYST')")
    public ResponseEntity<ApiResponse<ThreatAlertResponse>> updateMitigationStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> payload) {

        String newStatus = payload != null ? payload.get("status") : null;
        if (newStatus == null || newStatus.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Status field is required (e.g. MITIGATED, BLOCKED, ACTIVE, IGNORED)"));
        }

        ThreatAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat alert not found with ID: " + id));

        String sanitizedStatus = newStatus.trim().toUpperCase();
        alert.setMitigationStatus(sanitizedStatus);
        ThreatAlert saved = alertRepository.save(alert);

        log.info("[ThreatController] Updated alert ID {} mitigation status to {}", id, sanitizedStatus);

        return ResponseEntity.ok(ApiResponse.ok("Alert mitigation status updated successfully",
                ThreatAlertResponse.from(saved)));
    }
}
