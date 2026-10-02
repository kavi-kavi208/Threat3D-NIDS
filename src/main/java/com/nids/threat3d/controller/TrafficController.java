package com.nids.threat3d.controller;

import com.nids.threat3d.dto.ApiResponse;
import com.nids.threat3d.dto.NetworkFlowResponse;
import com.nids.threat3d.dto.PipelineResultResponse;
import com.nids.threat3d.dto.TrafficRecordRequest;
import com.nids.threat3d.engine.anomaly.AnomalyDetectionEngine;
import com.nids.threat3d.flow.FlowTracker;
import com.nids.threat3d.ingestion.TrafficRecord;
import com.nids.threat3d.model.NetworkFlow;
import com.nids.threat3d.pipeline.NidsDetectionPipeline;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.PipelineResult;
import com.nids.threat3d.repository.NetworkFlowRepository;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Traffic Ingestion & Analysis Controller — Phase 2 REST API.
 *
 * <p>Provides endpoints to ingest single or batch network traffic records into
 * the NIDS detection pipeline, query recent flows, and retrieve telemetry statistics.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@RestController
@RequestMapping({"/api/v2/traffic", "/api/v1/traffic"})
public class TrafficController {

    private static final Logger log = LoggerFactory.getLogger(TrafficController.class);

    private final NidsDetectionPipeline pipeline;
    private final NetworkFlowRepository flowRepository;
    private final FlowTracker flowTracker;
    private final AnomalyDetectionEngine anomalyEngine;

    public TrafficController(NidsDetectionPipeline pipeline,
                             NetworkFlowRepository flowRepository,
                             FlowTracker flowTracker,
                             AnomalyDetectionEngine anomalyEngine) {
        this.pipeline = pipeline;
        this.flowRepository = flowRepository;
        this.flowTracker = flowTracker;
        this.anomalyEngine = anomalyEngine;
    }

    /**
     * Ingest and evaluate a single traffic record through the full detection pipeline.
     */
    @PostMapping("/analyze")
    public ResponseEntity<ApiResponse<PipelineResultResponse>> analyzeTraffic(
            @Valid @RequestBody TrafficRecordRequest request) {

        log.debug("[TrafficController] Analyzing record: {}:{} -> {}:{} ({})",
                request.getSourceIp(), request.getSourcePort(),
                request.getDestinationIp(), request.getDestinationPort(),
                request.getProtocol());

        TrafficRecord record = toTrafficRecord(request);
        PipelineResult result = pipeline.processRecord(record);

        if (result.hasError()) {
            log.warn("[TrafficController] Pipeline processing error: {}", result.getErrorMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(result.getErrorMessage()));
        }

        return ResponseEntity.ok(ApiResponse.ok("Traffic record analyzed successfully",
                PipelineResultResponse.from(result)));
    }

    /**
     * Ingest and evaluate a batch of traffic records through the detection pipeline.
     */
    @PostMapping("/batch")
    public ResponseEntity<ApiResponse<List<PipelineResultResponse>>> analyzeBatch(
            @RequestBody List<@Valid TrafficRecordRequest> requests) {

        if (requests == null || requests.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Batch request list cannot be null or empty"));
        }

        if (requests.size() > 500) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Batch size exceeds maximum limit of 500 records"));
        }

        log.info("[TrafficController] Ingesting batch of {} traffic records", requests.size());

        List<TrafficRecord> records = requests.stream()
                .map(this::toTrafficRecord)
                .toList();

        List<PipelineResult> results = pipeline.processBatch(records);
        List<PipelineResultResponse> responseList = results.stream()
                .map(PipelineResultResponse::from)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(
                String.format("Batch of %d records processed successfully", responseList.size()),
                responseList));
    }

    /**
     * Retrieve the most recent flows persisted in the database.
     */
    @GetMapping("/recent")
    public ResponseEntity<ApiResponse<List<NetworkFlowResponse>>> getRecentFlows() {
        List<NetworkFlow> flows = flowRepository.findTop100ByOrderByFlowStartDesc();
        List<NetworkFlowResponse> responses = flows.stream()
                .map(NetworkFlowResponse::from)
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(responses));
    }

    /**
     * Retrieve aggregate pipeline and traffic engine statistics.
     */
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getTrafficStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalRecordsProcessed", pipeline.getTotalRecordsProcessed());
        stats.put("totalEventsGenerated", pipeline.getTotalEventsGenerated());
        stats.put("totalAlertsPersistedDb", pipeline.getTotalAlertsPersistedDb());
        stats.put("totalPipelineErrors", pipeline.getTotalPipelineErrors());
        stats.put("activeFlowCount", flowTracker.getActiveFlowCount());
        stats.put("anomalyBaselineReady", anomalyEngine.isBaselineReady());
        stats.put("anomalySampleCount", anomalyEngine.getSampleCount());
        stats.put("safetyDisclaimer", "SIMULATION ONLY — NO REAL NETWORK CHANGES");

        return ResponseEntity.ok(ApiResponse.ok(stats));
    }

    private TrafficRecord toTrafficRecord(TrafficRecordRequest req) {
        return new TrafficRecord(
                Instant.now(),
                req.getSourceIp(),
                req.getDestinationIp(),
                req.getSourcePort(),
                req.getDestinationPort(),
                req.getProtocol(),
                req.getPacketSize(),
                req.getTcpFlags(),
                req.getPayloadLength(),
                req.getDirection(),
                req.getApplicationProtocol(),
                req.getConnectionStatus(),
                req.getSimulatedPayloadSnippet()
        );
    }
}
