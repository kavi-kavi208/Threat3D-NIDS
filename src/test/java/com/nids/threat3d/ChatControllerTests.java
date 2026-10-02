package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.dto.ChatRequest;
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

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@Transactional
class ChatControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ThreatAlertRepository alertRepository;

    private String userToken;
    private Long alertId;

    @BeforeEach
    void setUp() throws Exception {
        userToken = obtainToken("admin", "Admin@12345");

        ThreatAlert testAlert = new ThreatAlert(
                "SID-1001", "203.0.113.88", "192.168.1.10",
                "SYN_FLOOD", "CRITICAL", 0.92f, "ACTIVE",
                "T1498", "Simulated TCP SYN flood test alert"
        );
        ThreatAlert saved = alertRepository.save(testAlert);
        alertId = saved.getId();
    }

    private String obtainToken(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest(username, password);
        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();
        AuthResponse authRes = objectMapper.readValue(res.getResponse().getContentAsString(), AuthResponse.class);
        return authRes.getToken();
    }

    @Test
    void testExplainWithRealThreatAlert() throws Exception {
        ChatRequest req = new ChatRequest("Explain this threat", alertId.toString());

        mockMvc.perform(post("/api/v2/chat/explain")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.answer", containsString("Threat Alert #" + alertId)))
                .andExpect(jsonPath("$.severity", is("CRITICAL")))
                .andExpect(jsonPath("$.score", is(92)))
                .andExpect(jsonPath("$.mitre", hasItem(containsString("T1498"))))
                .andExpect(jsonPath("$.recommendations", not(empty())));
    }

    @Test
    void testExplainWithTamilLanguage() throws Exception {
        ChatRequest req = new ChatRequest("இந்த அச்சுறுத்தலை விளக்குங்கள்", alertId.toString());

        mockMvc.perform(post("/api/v2/chat/explain")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.answer", containsString("அச்சுறுத்தல் #" + alertId)))
                .andExpect(jsonPath("$.severity", is("CRITICAL")))
                .andExpect(jsonPath("$.recommendations", not(empty())));
    }

    @Test
    void testOfflineExpertFallbackPublicAccess() throws Exception {
        // Offline expert is accessible without JWT token
        ChatRequest req = new ChatRequest("What is Welford anomaly detection?", null);

        mockMvc.perform(post("/api/offline-expert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.answer", containsString("Welford")))
                .andExpect(jsonPath("$.severity", notNullValue()))
                .andExpect(jsonPath("$.score", notNullValue()))
                .andExpect(jsonPath("$.recommendations", not(empty())));
    }

    @Test
    void testOfflineExpertTamilQuery() throws Exception {
        ChatRequest req = new ChatRequest("NIDS என்றால் என்ன?", null);

        mockMvc.perform(post("/api/offline-expert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.answer", containsString("NIDS")))
                .andExpect(jsonPath("$.recommendations", not(empty())));
    }
}
