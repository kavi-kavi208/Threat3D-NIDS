package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.dto.SimulationRequest;
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
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@Transactional
class SimulationControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminToken;
    private String studentToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = obtainToken("admin", "Admin@12345");
        studentToken = obtainToken("student", "Student@12345");
    }

    private String obtainToken(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest(username, password);
        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readValue(res.getResponse().getContentAsString(), AuthResponse.class).getToken();
    }

    @Test
    void testGetAvailableScenarios() throws Exception {
        mockMvc.perform(get("/api/v2/simulation/scenarios")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data.length()").value(7));
    }

    @Test
    void testStartSimulationAccepted() throws Exception {
        SimulationRequest req = new SimulationRequest(ScenarioType.NORMAL_TRAFFIC, 20);

        mockMvc.perform(post("/api/v2/simulation/start")
                        .header("Authorization", "Bearer " + studentToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accepted").value(true));
    }

    @Test
    void testStartSimulationValidationFailure() throws Exception {
        SimulationRequest req = new SimulationRequest(null, -5);

        mockMvc.perform(post("/api/v2/simulation/start")
                        .header("Authorization", "Bearer " + studentToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetSimulationStatus() throws Exception {
        mockMvc.perform(get("/api/v2/simulation/status")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.currentState").exists())
                .andExpect(jsonPath("$.data.safetyDisclaimer").value(containsString("SIMULATION ONLY")));
    }

    @Test
    void testStopSimulation() throws Exception {
        mockMvc.perform(post("/api/v2/simulation/stop")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testResetSimulationAsAdminSuccess() throws Exception {
        mockMvc.perform(post("/api/v2/simulation/reset")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testResetSimulationAsStudentForbidden() throws Exception {
        mockMvc.perform(post("/api/v2/simulation/reset")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testGetSimulationSummary() throws Exception {
        mockMvc.perform(get("/api/v2/simulation/summary")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testPortScanSimulationStatusAndSummary() throws Exception {
        SimulationRequest req = new SimulationRequest(ScenarioType.PORT_SCAN_PATTERN, 50);

        mockMvc.perform(post("/api/v2/simulation/start")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted());

        String statusJson = "";
        for (int i = 0; i < 30; i++) {
            Thread.sleep(100);
            MvcResult res = mockMvc.perform(get("/api/v2/simulation/status")
                            .header("Authorization", "Bearer " + adminToken))
                    .andReturn();
            statusJson = res.getResponse().getContentAsString();
            if (statusJson.contains("\"COMPLETED\"")) break;
        }

        MvcResult sumRes = mockMvc.perform(get("/api/v2/simulation/summary")
                        .header("Authorization", "Bearer " + adminToken))
                .andReturn();
        String summaryJson = sumRes.getResponse().getContentAsString();

        assertTrue(statusJson.contains("\"recordsTotal\":50"));
        assertTrue(statusJson.contains("\"recordsProcessed\":50"));
        assertTrue(statusJson.contains("\"state\":\"COMPLETED\""));
        assertTrue(statusJson.contains("\"durationMs\":"));
        assertTrue(summaryJson.contains("\"totalRecordsProcessed\":50"));
        assertTrue(summaryJson.contains("\"totalHighCriticalAlerts\":"));
        assertTrue(summaryJson.contains("\"durationMs\":"));
    }
}
