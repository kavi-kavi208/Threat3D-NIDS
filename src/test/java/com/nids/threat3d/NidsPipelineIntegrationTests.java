package com.nids.threat3d;

import com.nids.threat3d.ingestion.SyntheticTrafficSource;
import com.nids.threat3d.ingestion.TrafficRecord;
import com.nids.threat3d.model.NetworkFlow;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.pipeline.NidsDetectionPipeline;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.PipelineResult;
import com.nids.threat3d.pipeline.NidsDetectionPipeline.SimulationSummary;
import com.nids.threat3d.repository.NetworkFlowRepository;
import com.nids.threat3d.repository.ThreatAlertRepository;
import com.nids.threat3d.simulation.ScenarioType;
import com.nids.threat3d.simulation.SimulationOrchestrator;
import com.nids.threat3d.simulation.SimulationOrchestrator.StartResult;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.ThreatType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("h2")
@Transactional
class NidsPipelineIntegrationTests {

    @Autowired
    private NidsDetectionPipeline pipeline;

    @Autowired
    private SimulationOrchestrator simulationOrchestrator;

    @Autowired
    private ThreatAlertRepository alertRepository;

    @Autowired
    private NetworkFlowRepository flowRepository;

    @BeforeEach
    void setUp() {
        pipeline.resetPipeline();
    }

    @Test
    void testNormalTrafficProcessing() {
        TrafficRecord record = new TrafficRecord(
                Instant.now(), "192.168.1.51", "192.168.1.10",
                50000, 80, "TCP",
                512, Set.of("ACK", "PSH"), 256,
                "INTERNAL", "HTTP", "ESTABLISHED",
                "GET /dashboard HTTP/1.1"
        );

        PipelineResult result = pipeline.processRecord(record);

        assertNotNull(result);
        assertFalse(result.hasError());
        assertNotNull(result.getDetectionEvent());
        assertTrue(result.getDetectionEvent().getThreatScore() < 50.0,
                "Normal traffic score should be below 50");
        assertEquals(DefenseAction.MONITOR, result.getRecommendation().getAction());

        // Flow should be persisted
        List<NetworkFlow> flows = flowRepository.findBySrcIpOrDstIp("192.168.1.51", "192.168.1.51");
        assertFalse(flows.isEmpty(), "Aggregated flow should be saved to database");
    }

    @Test
    void testSynFloodDetectionAndAlertPersistence() {
        // Feed a burst of 30 SYN packets with no ACKs targeting port 80
        String attackerIp = "203.0.113.199";
        PipelineResult lastResult = null;

        for (int i = 0; i < 30; i++) {
            TrafficRecord synPacket = new TrafficRecord(
                    Instant.now(), attackerIp, "192.168.1.10",
                    40000, 80, "TCP",
                    64, Set.of("SYN"), 0,
                    "INBOUND", "HTTP", "SYN_SENT", ""
            );
            lastResult = pipeline.processRecord(synPacket);
        }

        assertNotNull(lastResult);
        assertFalse(lastResult.hasError());
        assertEquals("CRITICAL", lastResult.getDetectionEvent().getSeverity());
        assertEquals(ThreatType.SYN_FLOOD, lastResult.getDetectionEvent().getThreatType());
        assertTrue(lastResult.getDetectionEvent().getThreatScore() >= 75.0);
        assertTrue(lastResult.getRecommendation().requiresNodeIsolation()
                || lastResult.getRecommendation().getAction() == DefenseAction.RECOMMEND_BLOCK);

        // Verify alert was persisted in H2 database
        List<ThreatAlert> criticalAlerts = alertRepository.findBySeverity("CRITICAL");
        assertFalse(criticalAlerts.isEmpty(), "Critical alert should be stored in H2 database");
    }

    @Test
    void testSqlInjectionWebAnomalyDetection() {
        TrafficRecord sqliRecord = new TrafficRecord(
                Instant.now(), "203.0.113.55", "192.168.1.10",
                49200, 80, "TCP",
                480, Set.of("ACK", "PSH"), 220,
                "INBOUND", "HTTP", "ESTABLISHED",
                "GET /catalog?id=1 UNION SELECT 1,username,password FROM accounts--"
        );

        PipelineResult result = pipeline.processRecord(sqliRecord);

        assertNotNull(result);
        assertFalse(result.hasError());
        assertEquals(ThreatType.WEB_ANOMALY, result.getDetectionEvent().getThreatType());
        assertTrue(result.getDetectionEvent().getThreatScore() >= 50.0);
        assertEquals("HIGH", result.getDetectionEvent().getSeverity());
        assertEquals("T1190", result.getDetectionEvent().getMitreTechnique());
    }

    @Test
    void testSshBruteForceDetection() {
        String attackerIp = "203.0.113.77";
        PipelineResult result = null;

        // Feed SSH authentication failure records to the same SSH connection flow
        for (int i = 0; i < 5; i++) {
            TrafficRecord sshFail = new TrafficRecord(
                    Instant.now(), attackerIp, "192.168.1.10",
                    48000, 22, "TCP",
                    112, Set.of("RST", "ACK"), 44,
                    "INBOUND", "SSH", "FAILED",
                    "SSH-2.0-OpenSSH Auth Failed User=root"
            );
            result = pipeline.processRecord(sshFail);
        }

        assertNotNull(result);
        assertFalse(result.hasError());
        assertEquals(ThreatType.BRUTE_FORCE, result.getDetectionEvent().getThreatType());
        assertEquals("T1110", result.getDetectionEvent().getMitreTechnique());
    }

    @Test
    void testIcmpFloodDetection() {
        TrafficRecord icmpRecord = new TrafficRecord(
                Instant.now(), "203.0.113.99", "192.168.1.1",
                0, 0, "ICMP",
                1450, Set.of(), 1400,
                "INBOUND", "ICMP", "ESTABLISHED",
                "ECHO_REQUEST_OVERSIZED"
        );

        PipelineResult result = pipeline.processRecord(icmpRecord);

        assertNotNull(result);
        assertFalse(result.hasError());
        assertEquals(ThreatType.ICMP_FLOOD, result.getDetectionEvent().getThreatType());
        assertEquals("T1498.001", result.getDetectionEvent().getMitreTechnique());
    }

    @Test
    void testMultiStageThreatCorrelation() {
        String attackerIp = "203.0.113.200";

        // Stage 1: Port scan probing multiple ports
        int[] ports = {21, 22, 80, 443, 3306, 5432, 8080, 9000, 3389};
        for (int port : ports) {
            TrafficRecord scan = new TrafficRecord(
                    Instant.now(), attackerIp, "192.168.1.10",
                    55000 + port, port, "TCP",
                    60, Set.of("SYN"), 0,
                    "INBOUND", "OTHER", "SYN_SENT", ""
            );
            pipeline.processRecord(scan);
        }

        // Stage 2: Web injection attack from the same source
        TrafficRecord exploit = new TrafficRecord(
                Instant.now(), attackerIp, "192.168.1.10",
                56000, 80, "TCP",
                480, Set.of("ACK", "PSH"), 220,
                "INBOUND", "HTTP", "ESTABLISHED",
                "POST /auth/login HTTP/1.1 payload: ' OR '1'='1' --"
        );
        PipelineResult correlatedResult = pipeline.processRecord(exploit);

        assertNotNull(correlatedResult);
        assertNotNull(correlatedResult.getCorrelationResult(),
                "Threat correlation should trigger when distinct threat types originate from same IP");
        assertEquals(attackerIp, correlatedResult.getCorrelationResult().getSourceIp());
        assertTrue(correlatedResult.getCorrelationResult().getObservedThreatTypes().size() >= 2);
    }

    @Test
    void testFullSimulationRunViaPipeline() {
        SimulationSummary summary = pipeline.runSimulation(ScenarioType.PORT_SCAN_PATTERN, 25);

        assertNotNull(summary);
        assertTrue(summary.isFullySuccessful());
        assertEquals(25, summary.getTotalRecordsProcessed());
        assertEquals(25, summary.getTotalEventsGenerated());
        assertFalse(summary.getResults().isEmpty());
    }

    @Test
    void testPortScanSimulationGeneratesAlerts() {
        SimulationSummary summary = pipeline.runSimulation(ScenarioType.PORT_SCAN_PATTERN, 180);

        assertNotNull(summary);
        assertTrue(summary.isFullySuccessful());
        assertEquals(180, summary.getTotalRecordsProcessed());
        assertEquals(180, summary.getTotalEventsGenerated());
        assertTrue(summary.getTotalHighCriticalAlerts() > 0, "Port scan should produce alerts");
        assertTrue(summary.getDurationMs() >= 0);
        assertTrue(alertRepository.count() > 0, "Threat alerts must be persisted for port scan");
    }

    @Test
    void testSimulationOrchestratorLifecycle() throws Exception {
        StartResult startResult = simulationOrchestrator.startSimulation(ScenarioType.NORMAL_TRAFFIC, 15);
        assertTrue(startResult.isAccepted());

        // Wait brief moment for background task to complete 15 in-memory records
        int retries = 0;
        while (simulationOrchestrator.getState() == SimulationOrchestrator.SimulationState.RUNNING && retries < 20) {
            Thread.sleep(100);
            retries++;
        }

        assertEquals(SimulationOrchestrator.SimulationState.COMPLETED, simulationOrchestrator.getState());
        assertNotNull(simulationOrchestrator.getLastSummary());
        assertEquals(15, simulationOrchestrator.getLastSummary().getTotalRecordsProcessed());
    }
}
