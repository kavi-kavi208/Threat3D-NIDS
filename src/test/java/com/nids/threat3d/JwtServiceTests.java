package com.nids.threat3d;

import com.nids.threat3d.model.Role;
import com.nids.threat3d.model.User;
import com.nids.threat3d.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTests {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        // Set test secret (256-bit hex) and 1-hour expiration
        ReflectionTestUtils.setField(jwtService, "secretKey", "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970");
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", 3600000L);
    }

    @Test
    void testTokenGenerationAndUsernameExtraction() {
        User user = new User("sec_analyst", "hashed", "Security Analyst", "analyst@test.com", Role.ROLE_ANALYST);

        String token = jwtService.generateToken(user, user.getRole().name());
        assertNotNull(token);
        assertFalse(token.isBlank());

        String extractedUsername = jwtService.extractUsername(token);
        assertEquals("sec_analyst", extractedUsername);

        String role = jwtService.extractClaim(token, claims -> claims.get("role", String.class));
        assertEquals("ROLE_ANALYST", role);
    }

    @Test
    void testTokenValidationSuccess() {
        User user = new User("admin_user", "hashed", "Admin User", "admin@test.com", Role.ROLE_ADMIN);
        String token = jwtService.generateToken(user, user.getRole().name());

        assertTrue(jwtService.isTokenValid(token, user));
    }

    @Test
    void testTokenValidationFailsForDifferentUser() {
        User user1 = new User("user1", "hashed", "User One", "user1@test.com", Role.ROLE_STUDENT);
        User user2 = new User("user2", "hashed", "User Two", "user2@test.com", Role.ROLE_STUDENT);

        String token1 = jwtService.generateToken(user1, user1.getRole().name());

        assertFalse(jwtService.isTokenValid(token1, user2));
    }

    @Test
    void testTamperedTokenFails() {
        User user = new User("user1", "hashed", "User One", "user1@test.com", Role.ROLE_STUDENT);
        String token = jwtService.generateToken(user, user.getRole().name());

        String tamperedToken = token + "xyz";
        assertFalse(jwtService.isTokenValid(tamperedToken, user));
    }
}
