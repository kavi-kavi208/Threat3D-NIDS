package com.nids.threat3d;

import com.nids.threat3d.dto.SimulationProgressResponse;
import com.nids.threat3d.dto.SimulationSummaryResponse;
import com.nids.threat3d.model.NetworkNode;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.SimulationSummary;
import com.nids.threat3d.service.RealtimeEventPublisher;
import com.nids.threat3d.simulation.ScenarioType;
import com.nids.threat3d.simulation.SimulationOrchestrator.SimulationProgress;
import com.nids.threat3d.simulation.SimulationOrchestrator.SimulationState;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.DetectionEvent;
import com.nids.threat3d.threat.ThreatType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WebSocketIntegrationTests {

    @Autowired
    private RealtimeEventPublisher realtimeEventPublisher;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Test
    @DisplayName("WebSocket: RealtimeEventPublisher and SimpMessagingTemplate beans are loaded")
    void testBeansLoaded() {
        assertNotNull(realtimeEventPublisher, "RealtimeEventPublisher must be loaded");
        assertNotNull(messagingTemplate, "SimpMessagingTemplate must be loaded");
    }

    @Test
    @DisplayName("WebSocket: RealtimeEventPublisher broadcasts detection event safely")
    void testPublishDetectionEvent() {
        DetectionEvent event = new DetectionEvent(
                "192.168.1.105",
                "192.168.1.10",
                80,
                "TCP",
                ThreatType.SYN_FLOOD,
                88.5,
                "HIGH",
                "T1498",
                DefenseAction.RECOMMEND_BLOCK,
                "Explainable test event"
        );

        assertDoesNotThrow(() -> realtimeEventPublisher.publishDetectionEvent(event));
    }

    @Test
    @DisplayName("WebSocket: RealtimeEventPublisher broadcasts threat alert safely")
    void testPublishThreatAlert() {
        ThreatAlert alert = new ThreatAlert(
                "SID-1001",
                "192.168.1.105",
                "192.168.1.10",
                "PORT_SCAN",
                "HIGH",
                0.85f,
                "ACTIVE",
                "T1046",
                "Test port scan alert"
        );

        assertDoesNotThrow(() -> realtimeEventPublisher.publishThreatAlert(alert));
    }

    @Test
    @DisplayName("WebSocket: RealtimeEventPublisher broadcasts simulation progress & summary")
    void testPublishSimulationProgressAndSummary() {
        SimulationProgress progress = new SimulationProgress(
                ScenarioType.SYN_FLOOD_PATTERN,
                100,
                50,
                50,
                5,
                0,
                Instant.now(),
                null,
                SimulationState.RUNNING
        );

        SimulationProgressResponse progressResponse = SimulationProgressResponse.from(progress);
        assertDoesNotThrow(() -> realtimeEventPublisher.publishSimulationProgress(progressResponse));

        SimulationSummary summary = new SimulationSummary(
                ScenarioType.SYN_FLOOD_PATTERN,
                100,
                100,
                100,
                15,
                2,
                0,
                Map.of("HIGH", 15),
                Collections.emptyList()
        );

        SimulationSummaryResponse summaryResponse = SimulationSummaryResponse.from(summary, false);
        assertDoesNotThrow(() -> realtimeEventPublisher.publishSimulationSummary(summaryResponse));
    }

    @Test
    @DisplayName("WebSocket: RealtimeEventPublisher broadcasts node state and metrics")
    void testPublishNodeUpdateAndStats() {
        NetworkNode node = new NetworkNode(
                "node-fw-1",
                "Perimeter Firewall",
                "192.168.1.1",
                "00:1A:2B:3C:4D:01",
                "FIREWALL",
                "192.168.1.0/24",
                0f, 0f, 0f,
                "HEALTHY",
                "80,443"
        );

        assertDoesNotThrow(() -> realtimeEventPublisher.publishNodeUpdate(node));
        assertDoesNotThrow(() -> realtimeEventPublisher.publishStats(100, 95, 10, 8));
    }
}
