package com.nids.threat3d.controller;

import com.nids.threat3d.dto.ApiResponse;
import com.nids.threat3d.dto.PipelineResultResponse;
import com.nids.threat3d.dto.SnortRuleResponse;
import com.nids.threat3d.engine.anomaly.AnomalyDetectionEngine;
import com.nids.threat3d.model.SnortRule;
import com.nids.threat3d.repository.SnortRuleRepository;
import com.nids.threat3d.service.DefenseRecommendationService;
import com.nids.threat3d.service.ThreatCorrelationService;
import com.nids.threat3d.service.ThreatCorrelationService.CorrelationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Detection & Correlation Controller — Phase 2 REST API.
 *
 * <p>Provides endpoints to query threat correlation results, defensive
 * recommendations, Snort detection rules, and inspection engine status.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@RestController
@RequestMapping({"/api/v2/detection", "/api/v1/detection"})
public class DetectionController {

    private static final Logger log = LoggerFactory.getLogger(DetectionController.class);

    private final ThreatCorrelationService correlationService;
    private final DefenseRecommendationService recommendationService;
    private final SnortRuleRepository snortRuleRepository;
    private final AnomalyDetectionEngine anomalyEngine;

    public DetectionController(ThreatCorrelationService correlationService,
                               DefenseRecommendationService recommendationService,
                               SnortRuleRepository snortRuleRepository,
                               AnomalyDetectionEngine anomalyEngine) {
        this.correlationService = correlationService;
        this.recommendationService = recommendationService;
        this.snortRuleRepository = snortRuleRepository;
        this.anomalyEngine = anomalyEngine;
    }

    /**
     * Retrieve active multi-stage and cross-flow threat correlations.
     */
    @GetMapping("/correlations")
    public ResponseEntity<ApiResponse<List<PipelineResultResponse.CorrelationSummary>>> getCorrelations() {
        List<CorrelationResult> correlations = correlationService.correlateAll();
        List<PipelineResultResponse.CorrelationSummary> summaries = correlations.stream()
                .map(PipelineResultResponse.CorrelationSummary::from)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(summaries));
    }

    /**
     * Retrieve correlation buffer memory and source IP tracking summary.
     */
    @GetMapping("/correlations/buffer")
    public ResponseEntity<ApiResponse<Map<String, Integer>>> getCorrelationBufferSummary() {
        Map<String, Integer> summary = correlationService.getBufferSummary();
        return ResponseEntity.ok(ApiResponse.ok(summary));
    }

    /**
     * Retrieve simulated defense recommendations derived from active correlations.
     */
    @GetMapping("/recommendations")
    public ResponseEntity<ApiResponse<List<PipelineResultResponse.RecommendationSummary>>> getRecommendations() {
        List<CorrelationResult> correlations = correlationService.correlateAll();
        List<PipelineResultResponse.RecommendationSummary> recommendations = correlations.stream()
                .map(recommendationService::recommendFromCorrelation)
                .map(PipelineResultResponse.RecommendationSummary::from)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(recommendations));
    }

    /**
     * Retrieve Snort detection rules configured in the system.
     */
    @GetMapping("/rules")
    public ResponseEntity<ApiResponse<List<SnortRuleResponse>>> getSnortRules(
            @RequestParam(required = false, defaultValue = "false") boolean enabledOnly) {

        List<SnortRule> rules = enabledOnly
                ? snortRuleRepository.findByEnabledTrue()
                : snortRuleRepository.findAll();

        List<SnortRuleResponse> responses = rules.stream()
                .map(SnortRuleResponse::from)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(responses));
    }

    /**
     * Retrieve runtime status of detection engines (Signature + Statistical Anomaly).
     */
    @GetMapping("/engine/status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getEngineStatus() {
        Map<String, Object> status = new LinkedHashMap<>();

        Map<String, Object> signatureStatus = new LinkedHashMap<>();
        signatureStatus.put("activeRulesCount", snortRuleRepository.findByEnabledTrue().size());
        signatureStatus.put("totalRulesCount", snortRuleRepository.count());
        status.put("signatureEngine", signatureStatus);

        Map<String, Object> anomalyStatus = new LinkedHashMap<>();
        anomalyStatus.put("detectorName", "Java Statistical Anomaly Detection");
        anomalyStatus.put("isMachineLearning", false);
        anomalyStatus.put("algorithm", "Welford Online Mean & Variance with Z-Score Deviation");
        anomalyStatus.put("featureDimensions", 41);
        anomalyStatus.put("warmupSamplesThreshold", 50);
        anomalyStatus.put("sampleCount", anomalyEngine.getSampleCount());
        anomalyStatus.put("baselineReady", anomalyEngine.isBaselineReady());
        status.put("anomalyEngine", anomalyStatus);

        status.put("safetyDisclaimer", "SIMULATION ONLY — NO REAL NETWORK CHANGES");

        return ResponseEntity.ok(ApiResponse.ok(status));
    }
}
