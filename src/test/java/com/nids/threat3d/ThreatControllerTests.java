package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
import com.nids.threat3d.repository.ThreatAlertRepository;
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

import java.util.Map;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@Transactional
class ThreatControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ThreatAlertRepository alertRepository;

    private String adminToken;
    private String analystToken;
    private String studentToken;
    private Long existingAlertId;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = obtainToken("admin", "Admin@12345");
        analystToken = obtainToken("analyst", "Analyst@12345");
        studentToken = obtainToken("student", "Student@12345");

        // Seed a test alert if none exist
        ThreatAlert testAlert = new ThreatAlert(
                "SID-1001", "203.0.113.88", "192.168.1.10",
                44321, 80, "TCP",
                "SYN_FLOOD", "CRITICAL", 0.95f, "ACTIVE",
                "T1498", "Simulated TCP SYN flood test alert"
        );
        ThreatAlert saved = alertRepository.save(testAlert);
        existingAlertId = saved.getId();
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
    void testGetAlertsDefault() throws Exception {
        mockMvc.perform(get("/api/v2/threats")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data.length()", greaterThanOrEqualTo(1)));
    }

    @Test
    void testGetAlertsWithSeverityFilter() throws Exception {
        mockMvc.perform(get("/api/v2/threats?severity=CRITICAL")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    void testGetAlertByIdSuccess() throws Exception {
        mockMvc.perform(get("/api/v2/threats/" + existingAlertId)
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(existingAlertId))
                .andExpect(jsonPath("$.data.srcIp").value("203.0.113.88"))
                .andExpect(jsonPath("$.data.sourceIp").value("203.0.113.88"))
                .andExpect(jsonPath("$.data.dstIp").value("192.168.1.10"))
                .andExpect(jsonPath("$.data.destinationIp").value("192.168.1.10"))
                .andExpect(jsonPath("$.data.threatScore").value(95))
                .andExpect(jsonPath("$.data.confidenceScore").value(0.95))
                .andExpect(jsonPath("$.data.description").value("Simulated TCP SYN flood test alert"))
                .andExpect(jsonPath("$.data.signatureRule").value("SID-1001"))
                .andExpect(jsonPath("$.data.mitreTechniqueId").value("T1498"))
                .andExpect(jsonPath("$.data.attackType").value("SYN_FLOOD"))
                .andExpect(jsonPath("$.data.sourcePort").value(44321))
                .andExpect(jsonPath("$.data.destinationPort").value(80))
                .andExpect(jsonPath("$.data.protocol").value("TCP"));
    }

    @Test
    void testGetAlertsContainsFrontendContractFields() throws Exception {
        mockMvc.perform(get("/api/v2/threats")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0].sourceIp").exists())
                .andExpect(jsonPath("$.data[0].destinationIp").exists())
                .andExpect(jsonPath("$.data[0].sourcePort").exists())
                .andExpect(jsonPath("$.data[0].destinationPort").exists())
                .andExpect(jsonPath("$.data[0].protocol").exists())
                .andExpect(jsonPath("$.data[0].threatScore").exists())
                .andExpect(jsonPath("$.data[0].description").exists())
                .andExpect(jsonPath("$.data[0].signatureRule").exists())
                .andExpect(jsonPath("$.data[0].mitreTechniqueId").exists());
    }

    @Test
    void testGetAlertByIdNotFound() throws Exception {
        mockMvc.perform(get("/api/v2/threats/999999")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void testGetThreatSummary() throws Exception {
        mockMvc.perform(get("/api/v2/threats/summary")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.totalAlerts", greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.data.severityCounts").exists())
                .andExpect(jsonPath("$.data.attackTypeCounts").exists())
                .andExpect(jsonPath("$.data.countBySeverity").exists())
                .andExpect(jsonPath("$.data.countByAttackType").exists());
    }

    @Test
    void testUpdateMitigationStatusAsAnalystSuccess() throws Exception {
        mockMvc.perform(patch("/api/v2/threats/" + existingAlertId + "/status")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "MITIGATED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.mitigationStatus").value("MITIGATED"));

        ThreatAlert updated = alertRepository.findById(existingAlertId).orElseThrow();
        assertEquals("MITIGATED", updated.getMitigationStatus());
    }

    @Test
    void testUpdateMitigationStatusAsAdminSuccess() throws Exception {
        mockMvc.perform(patch("/api/v2/threats/" + existingAlertId + "/status")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "BLOCKED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.mitigationStatus").value("BLOCKED"));
    }

    @Test
    void testUpdateMitigationStatusAsStudentForbidden() throws Exception {
        mockMvc.perform(patch("/api/v2/threats/" + existingAlertId + "/status")
                        .header("Authorization", "Bearer " + studentToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("status", "MITIGATED"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void testUpdateMitigationStatusInvalidBody() throws Exception {
        mockMvc.perform(patch("/api/v2/threats/" + existingAlertId + "/status")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("wrongField", "VALUE"))))
                .andExpect(status().isBadRequest());
    }
}
