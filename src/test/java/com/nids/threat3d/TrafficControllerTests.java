package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.dto.TrafficRecordRequest;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
import com.nids.threat3d.model.NetworkFlow;
import com.nids.threat3d.repository.NetworkFlowRepository;
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

import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@Transactional
class TrafficControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private NetworkFlowRepository flowRepository;

    private String analystToken;
    private String studentToken;

    @BeforeEach
    void setUp() throws Exception {
        analystToken = obtainToken("analyst", "Analyst@12345");
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
    void testAnalyzeTrafficNormalSuccess() throws Exception {
        TrafficRecordRequest req = new TrafficRecordRequest();
        req.setSourceIp("192.168.1.50");
        req.setDestinationIp("192.168.1.10");
        req.setSourcePort(54321);
        req.setDestinationPort(80);
        req.setProtocol("TCP");
        req.setPacketSize(256);
        req.setTcpFlags(Set.of("ACK"));
        req.setDirection("INTERNAL");
        req.setApplicationProtocol("HTTP");
        req.setConnectionStatus("ESTABLISHED");
        req.setSimulatedPayloadSnippet("GET /index.html HTTP/1.1");

        mockMvc.perform(post("/api/v2/traffic/analyze")
                        .header("Authorization", "Bearer " + studentToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.detectionEvent.sourceIp").value("192.168.1.50"))
                .andExpect(jsonPath("$.data.detectionEvent.threatType").exists())
                .andExpect(jsonPath("$.data.detectionEvent.threatScore").isNumber())
                .andExpect(jsonPath("$.data.recommendation").exists())
                .andExpect(jsonPath("$.data.safetyDisclaimer").value(containsString("SIMULATION ONLY")));
    }

    @Test
    void testAnalyzeTrafficValidationFailureInvalidIp() throws Exception {
        TrafficRecordRequest req = new TrafficRecordRequest();
        req.setSourceIp("not-an-ip");
        req.setDestinationIp("192.168.1.10");
        req.setSourcePort(1000);
        req.setDestinationPort(80);
        req.setProtocol("TCP");

        mockMvc.perform(post("/api/v2/traffic/analyze")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testAnalyzeTrafficValidationFailureInvalidPort() throws Exception {
        TrafficRecordRequest req = new TrafficRecordRequest();
        req.setSourceIp("192.168.1.50");
        req.setDestinationIp("192.168.1.10");
        req.setSourcePort(-1);
        req.setDestinationPort(70000); // Exceeds 65535
        req.setProtocol("TCP");

        mockMvc.perform(post("/api/v2/traffic/analyze")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testAnalyzeBatchSuccess() throws Exception {
        TrafficRecordRequest r1 = new TrafficRecordRequest();
        r1.setSourceIp("192.168.1.60");
        r1.setDestinationIp("192.168.1.10");
        r1.setSourcePort(49152);
        r1.setDestinationPort(80);
        r1.setProtocol("TCP");

        TrafficRecordRequest r2 = new TrafficRecordRequest();
        r2.setSourceIp("192.168.1.61");
        r2.setDestinationIp("192.168.1.10");
        r2.setSourcePort(49153);
        r2.setDestinationPort(443);
        r2.setProtocol("TCP");

        mockMvc.perform(post("/api/v2/traffic/batch")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(List.of(r1, r2))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data.length()").value(2));
    }

    @Test
    void testAnalyzeBatchEmptyFails() throws Exception {
        mockMvc.perform(post("/api/v2/traffic/batch")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(List.of())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetRecentFlows() throws Exception {
        NetworkFlow testFlow = new NetworkFlow(
                "192.168.1.105",
                "192.168.1.10",
                44321,
                80,
                "TCP",
                4096L,
                32L,
                0.125f,
                "SYN:2,ACK:15,FIN:1,RST:0",
                "HTTP"
        );
        flowRepository.save(testFlow);

        mockMvc.perform(get("/api/v2/traffic/recent")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data[0].sourceIp").value("192.168.1.105"))
                .andExpect(jsonPath("$.data[0].sourcePort").value(44321))
                .andExpect(jsonPath("$.data[0].destinationIp").value("192.168.1.10"))
                .andExpect(jsonPath("$.data[0].destinationPort").value(80))
                .andExpect(jsonPath("$.data[0].protocol").value("TCP"))
                .andExpect(jsonPath("$.data[0].packetCount").value(32))
                .andExpect(jsonPath("$.data[0].byteCount").value(4096))
                .andExpect(jsonPath("$.data[0].durationMs").value(125))
                .andExpect(jsonPath("$.data[0].synCount").value(2))
                .andExpect(jsonPath("$.data[0].ackCount").value(15))
                .andExpect(jsonPath("$.data[0].finCount").value(1))
                .andExpect(jsonPath("$.data[0].rstCount").value(0))
                .andExpect(jsonPath("$.data[0].flowStart").exists());
    }

    @Test
    void testGetTrafficStats() throws Exception {
        mockMvc.perform(get("/api/v2/traffic/stats")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.totalRecordsProcessed").exists())
                .andExpect(jsonPath("$.data.safetyDisclaimer").value(containsString("SIMULATION ONLY")));
    }

    @Test
    void testUnauthorizedRequestWithoutTokenRejected() throws Exception {
        mockMvc.perform(get("/api/v2/traffic/stats"))
                .andExpect(status().isForbidden());
    }
}
