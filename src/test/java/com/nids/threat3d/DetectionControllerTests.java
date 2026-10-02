package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
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
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@Transactional
class DetectionControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String studentToken;

    @BeforeEach
    void setUp() throws Exception {
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
    void testGetCorrelations() throws Exception {
        mockMvc.perform(get("/api/v2/detection/correlations")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    void testGetCorrelationBufferSummary() throws Exception {
        mockMvc.perform(get("/api/v2/detection/correlations/buffer")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void testGetRecommendations() throws Exception {
        mockMvc.perform(get("/api/v2/detection/recommendations")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    void testGetSnortRulesAll() throws Exception {
        mockMvc.perform(get("/api/v2/detection/rules")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data.length()", greaterThanOrEqualTo(5)))
                // Rule 1: SID-1001 (SYN Flood)
                .andExpect(jsonPath("$.data[0].sid").value(1001))
                .andExpect(jsonPath("$.data[0].name").value("TCP SYN Flood Denial-of-Service"))
                .andExpect(jsonPath("$.data[0].protocol").value("TCP"))
                .andExpect(jsonPath("$.data[0].sourcePort").value("any"))
                .andExpect(jsonPath("$.data[0].destPort").value("80,443"))
                .andExpect(jsonPath("$.data[0].severity").value("CRITICAL"))
                .andExpect(jsonPath("$.data[0].attackCategory").value("DOS"))
                .andExpect(jsonPath("$.data[0].mitreTechniqueId").value("T1498"))
                // Rule 2: SID-1002 (Port Scan)
                .andExpect(jsonPath("$.data[1].sid").value(1002))
                .andExpect(jsonPath("$.data[1].name").value("Rapid Port Scanning Reconnaissance"))
                .andExpect(jsonPath("$.data[1].protocol").value("TCP"))
                .andExpect(jsonPath("$.data[1].sourcePort").value("any"))
                .andExpect(jsonPath("$.data[1].destPort").value("any"))
                .andExpect(jsonPath("$.data[1].severity").value("MEDIUM"))
                .andExpect(jsonPath("$.data[1].attackCategory").value("PROBE"))
                .andExpect(jsonPath("$.data[1].mitreTechniqueId").value("T1046"))
                // Rule 3: SID-1003 (SQL Injection)
                .andExpect(jsonPath("$.data[2].sid").value(1003))
                .andExpect(jsonPath("$.data[2].name").value("SQL Injection UNION SELECT in HTTP Payload"))
                .andExpect(jsonPath("$.data[2].protocol").value("TCP"))
                .andExpect(jsonPath("$.data[2].sourcePort").value("any"))
                .andExpect(jsonPath("$.data[2].destPort").value("80,8080"))
                .andExpect(jsonPath("$.data[2].severity").value("HIGH"))
                .andExpect(jsonPath("$.data[2].attackCategory").value("EXPLOIT"))
                .andExpect(jsonPath("$.data[2].mitreTechniqueId").value("T1190"))
                // Rule 4: SID-1004 (SSH Brute Force)
                .andExpect(jsonPath("$.data[3].sid").value(1004))
                .andExpect(jsonPath("$.data[3].name").value("SSH Rapid Authentication Failure Brute Force"))
                .andExpect(jsonPath("$.data[3].protocol").value("TCP"))
                .andExpect(jsonPath("$.data[3].sourcePort").value("any"))
                .andExpect(jsonPath("$.data[3].destPort").value("22"))
                .andExpect(jsonPath("$.data[3].severity").value("HIGH"))
                .andExpect(jsonPath("$.data[3].attackCategory").value("BRUTE_FORCE"))
                .andExpect(jsonPath("$.data[3].mitreTechniqueId").value("T1110"))
                // Rule 5: SID-1005 (Ping of Death)
                .andExpect(jsonPath("$.data[4].sid").value(1005))
                .andExpect(jsonPath("$.data[4].name").value("ICMP Ping of Death Oversized Packet"))
                .andExpect(jsonPath("$.data[4].protocol").value("ICMP"))
                .andExpect(jsonPath("$.data[4].sourcePort").value("any"))
                .andExpect(jsonPath("$.data[4].destPort").value("any"))
                .andExpect(jsonPath("$.data[4].severity").value("HIGH"))
                .andExpect(jsonPath("$.data[4].attackCategory").value("DOS"))
                .andExpect(jsonPath("$.data[4].mitreTechniqueId").value("T1498.001"));
    }

    @Test
    void testGetSnortRulesEnabledOnly() throws Exception {
        mockMvc.perform(get("/api/v2/detection/rules?enabledOnly=true")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data.length()", greaterThanOrEqualTo(5)));
    }

    @Test
    void testGetEngineStatus() throws Exception {
        mockMvc.perform(get("/api/v2/detection/engine/status")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.anomalyEngine.detectorName").value("Java Statistical Anomaly Detection"))
                .andExpect(jsonPath("$.data.anomalyEngine.isMachineLearning").value(false))
                .andExpect(jsonPath("$.data.anomalyEngine.featureDimensions").value(41))
                .andExpect(jsonPath("$.data.signatureEngine.activeRulesCount", greaterThanOrEqualTo(5)))
                .andExpect(jsonPath("$.data.safetyDisclaimer").value(containsString("SIMULATION ONLY")));
    }
}
