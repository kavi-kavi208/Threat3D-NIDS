package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.dto.ApiResponse;
import com.nids.threat3d.dto.SimulationProgressResponse;
import com.nids.threat3d.dto.SimulationRequest;
import com.nids.threat3d.dto.SimulationSummaryResponse;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
import com.nids.threat3d.simulation.ScenarioType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
public class SimulationScenarioOutcomesTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        AuthRequest req = new AuthRequest("admin", "Admin@12345");
        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();
        adminToken = objectMapper.readValue(res.getResponse().getContentAsString(), AuthResponse.class).getToken();
    }

    private SimulationSummaryResponse runScenario(ScenarioType scenario, int count) throws Exception {
        // Reset first to ensure clean state
        mockMvc.perform(post("/api/v2/simulation/reset")
                .header("Authorization", "Bearer " + adminToken));

        SimulationRequest req = new SimulationRequest(scenario, count);
        mockMvc.perform(post("/api/v2/simulation/start")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted());

        // Wait for completion
        for (int i = 0; i < 40; i++) {
            Thread.sleep(100);
            MvcResult res = mockMvc.perform(get("/api/v2/simulation/status")
                            .header("Authorization", "Bearer " + adminToken))
                    .andReturn();
            String json = res.getResponse().getContentAsString();
            if (json.contains("\"COMPLETED\"")) break;
        }

        MvcResult sumRes = mockMvc.perform(get("/api/v2/simulation/summary")
                        .header("Authorization", "Bearer " + adminToken))
                .andReturn();

        ApiResponse<SimulationSummaryResponse> apiRes = objectMapper.readValue(
                sumRes.getResponse().getContentAsString(),
                objectMapper.getTypeFactory().constructParametricType(ApiResponse.class, SimulationSummaryResponse.class)
        );

        return apiRes.getData();
    }

    @Test
    void testAllScenariosProduceDistinctOutcomes() throws Exception {
        SimulationSummaryResponse normal = runScenario(ScenarioType.NORMAL_TRAFFIC, 50);
        System.out.println("NORMAL_TRAFFIC: processed=" + normal.getTotalRecordsProcessed() +
                ", alerts=" + normal.getTotalHighCriticalAlerts() +
                ", duration=" + normal.getDurationMs() +
                ", dist=" + normal.getThreatDistribution());

        SimulationSummaryResponse portScan = runScenario(ScenarioType.PORT_SCAN_PATTERN, 50);
        System.out.println("PORT_SCAN_PATTERN: processed=" + portScan.getTotalRecordsProcessed() +
                ", alerts=" + portScan.getTotalHighCriticalAlerts() +
                ", duration=" + portScan.getDurationMs() +
                ", dist=" + portScan.getThreatDistribution());

        SimulationSummaryResponse synFlood = runScenario(ScenarioType.SYN_FLOOD_PATTERN, 50);
        System.out.println("SYN_FLOOD_PATTERN: processed=" + synFlood.getTotalRecordsProcessed() +
                ", alerts=" + synFlood.getTotalHighCriticalAlerts() +
                ", duration=" + synFlood.getDurationMs() +
                ", dist=" + synFlood.getThreatDistribution());

        SimulationSummaryResponse icmpFlood = runScenario(ScenarioType.ICMP_FLOOD_PATTERN, 50);
        System.out.println("ICMP_FLOOD_PATTERN: processed=" + icmpFlood.getTotalRecordsProcessed() +
                ", alerts=" + icmpFlood.getTotalHighCriticalAlerts() +
                ", duration=" + icmpFlood.getDurationMs() +
                ", dist=" + icmpFlood.getThreatDistribution());

        SimulationSummaryResponse bruteForce = runScenario(ScenarioType.BRUTE_FORCE_PATTERN, 50);
        System.out.println("BRUTE_FORCE_PATTERN: processed=" + bruteForce.getTotalRecordsProcessed() +
                ", alerts=" + bruteForce.getTotalHighCriticalAlerts() +
                ", duration=" + bruteForce.getDurationMs() +
                ", dist=" + bruteForce.getThreatDistribution());

        SimulationSummaryResponse webAnomaly = runScenario(ScenarioType.WEB_ANOMALY_PATTERN, 50);
        System.out.println("WEB_ANOMALY_PATTERN: processed=" + webAnomaly.getTotalRecordsProcessed() +
                ", alerts=" + webAnomaly.getTotalHighCriticalAlerts() +
                ", duration=" + webAnomaly.getDurationMs() +
                ", dist=" + webAnomaly.getThreatDistribution());

        // Assertions for each scenario
        assertEquals(50, normal.getTotalRecordsProcessed());
        assertEquals(0, normal.getTotalHighCriticalAlerts(), "NORMAL_TRAFFIC should produce 0 high/critical alerts");
        assertTrue(normal.getDurationMs() > 0, "NORMAL_TRAFFIC duration should be measured > 0");

        assertEquals(50, portScan.getTotalRecordsProcessed());
        assertTrue(portScan.getTotalHighCriticalAlerts() > 0, "PORT_SCAN_PATTERN should trigger port scan alerts");
        assertTrue(portScan.getDurationMs() > 0);

        assertEquals(50, synFlood.getTotalRecordsProcessed());
        assertTrue(synFlood.getTotalHighCriticalAlerts() > 0, "SYN_FLOOD_PATTERN should trigger CRITICAL SYN flood alerts");
        assertEquals(31, (int) synFlood.getThreatDistribution().getOrDefault("CRITICAL", 0));
        assertTrue(synFlood.getDurationMs() > 0);

        assertEquals(50, icmpFlood.getTotalRecordsProcessed());
        assertTrue(icmpFlood.getTotalHighCriticalAlerts() > 0, "ICMP_FLOOD_PATTERN should trigger ICMP flood alerts");
        assertTrue(icmpFlood.getDurationMs() > 0);

        assertEquals(50, bruteForce.getTotalRecordsProcessed());
        assertTrue(bruteForce.getTotalHighCriticalAlerts() > 0, "BRUTE_FORCE_PATTERN should trigger SSH brute force alerts");
        assertTrue(bruteForce.getDurationMs() > 0);

        assertEquals(50, webAnomaly.getTotalRecordsProcessed());
        assertTrue(webAnomaly.getTotalHighCriticalAlerts() > 0, "WEB_ANOMALY_PATTERN should trigger SQLi/web alerts");
        assertTrue(webAnomaly.getDurationMs() > 0);
    }
}
