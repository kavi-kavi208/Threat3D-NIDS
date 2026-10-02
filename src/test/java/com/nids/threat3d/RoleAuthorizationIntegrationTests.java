package com.nids.threat3d;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
class RoleAuthorizationIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String obtainToken(String username, String password) throws Exception {
        AuthRequest loginRequest = new AuthRequest(username, password);
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse authResponse = objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
        return authResponse.getToken();
    }

    @Test
    void testAdminCanAccessAdminAndAnalystEndpoints() throws Exception {
        String adminToken = obtainToken("admin", "Admin@12345");

        // Admin accessing /admin/status
        mockMvc.perform(get("/api/v1/admin/status")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHORIZED"));

        // Admin accessing /analyst/status
        mockMvc.perform(get("/api/v1/analyst/status")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHORIZED"));
    }

    @Test
    void testAnalystCanAccessAnalystEndpointButDeniedAdminEndpoint() throws Exception {
        String analystToken = obtainToken("analyst", "Analyst@12345");

        // Analyst accessing /analyst/status -> OK
        mockMvc.perform(get("/api/v1/analyst/status")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHORIZED"));

        // Analyst accessing /admin/status -> FORBIDDEN (403)
        mockMvc.perform(get("/api/v1/admin/status")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testStudentDeniedBothAdminAndAnalystEndpoints() throws Exception {
        String studentToken = obtainToken("student", "Student@12345");

        // Student accessing /admin/status -> FORBIDDEN (403)
        mockMvc.perform(get("/api/v1/admin/status")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isForbidden());

        // Student accessing /analyst/status -> FORBIDDEN (403)
        mockMvc.perform(get("/api/v1/analyst/status")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void testAuthenticatedUserCanAccessTelemetryNodes() throws Exception {
        String studentToken = obtainToken("student", "Student@12345");

        mockMvc.perform(get("/api/v1/telemetry/nodes")
                        .header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(8));
    }
}
