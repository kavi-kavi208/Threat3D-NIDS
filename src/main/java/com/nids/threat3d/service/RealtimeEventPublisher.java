package com.nids.threat3d.service;

import com.nids.threat3d.dto.DetectionEventResponse;
import com.nids.threat3d.dto.SimulationProgressResponse;
import com.nids.threat3d.dto.SimulationSummaryResponse;
import com.nids.threat3d.dto.ThreatAlertResponse;
import com.nids.threat3d.model.NetworkNode;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.threat.DetectionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Real-time Event Publisher — Phase 3 STOMP/WebSocket Telemetry Service.
 *
 * <p>Publishes live detection events, persisted threat alerts, simulation progress,
 * and topological node status updates to connected WebSocket subscribers.</p>
 */
@Service
public class RealtimeEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(RealtimeEventPublisher.class);

    private final SimpMessagingTemplate messagingTemplate;

    public RealtimeEventPublisher(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }

    /**
     * Publish a scored detection event to /topic/telemetry and /topic/events.
     */
    public void publishDetectionEvent(DetectionEvent event) {
        if (event == null) return;
        try {
            DetectionEventResponse response = DetectionEventResponse.from(event);
            messagingTemplate.convertAndSend("/topic/telemetry", response);
            messagingTemplate.convertAndSend("/topic/events", response);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast detection event: {}", ex.getMessage());
        }
    }

    /**
     * Publish a persisted threat alert to /topic/alerts.
     */
    public void publishThreatAlert(ThreatAlert alert) {
        if (alert == null) return;
        try {
            ThreatAlertResponse response = ThreatAlertResponse.from(alert);
            messagingTemplate.convertAndSend("/topic/alerts", response);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast threat alert: {}", ex.getMessage());
        }
    }

    /**
     * Publish simulation execution progress to /topic/simulation.
     */
    public void publishSimulationProgress(SimulationProgressResponse progress) {
        if (progress == null) return;
        try {
            messagingTemplate.convertAndSend("/topic/simulation", progress);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast simulation progress: {}", ex.getMessage());
        }
    }

    /**
     * Publish completed simulation summary to /topic/simulation/summary.
     */
    public void publishSimulationSummary(SimulationSummaryResponse summary) {
        if (summary == null) return;
        try {
            messagingTemplate.convertAndSend("/topic/simulation/summary", summary);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast simulation summary: {}", ex.getMessage());
        }
    }

    /**
     * Publish updated node state to /topic/nodes.
     */
    public void publishNodeUpdate(NetworkNode node) {
        if (node == null) return;
        try {
            messagingTemplate.convertAndSend("/topic/nodes", node);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast node update: {}", ex.getMessage());
        }
    }

    /**
     * Publish general pipeline metric updates to /topic/stats.
     */
    public void publishStats(long processed, long events, long alerts, int activeFlows) {
        try {
            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("totalRecordsProcessed", processed);
            stats.put("totalEventsGenerated", events);
            stats.put("totalAlertsPersistedDb", alerts);
            stats.put("activeFlowCount", activeFlows);
            messagingTemplate.convertAndSend("/topic/stats", stats);
        } catch (Exception ex) {
            log.debug("[RealtimePublisher] Failed to broadcast stats: {}", ex.getMessage());
        }
    }
}
