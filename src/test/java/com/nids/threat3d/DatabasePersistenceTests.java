package com.nids.threat3d;

import com.nids.threat3d.model.*;
import com.nids.threat3d.repository.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("h2")
@Transactional
class DatabasePersistenceTests {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private NetworkNodeRepository networkNodeRepository;

    @Autowired
    private NetworkFlowRepository networkFlowRepository;

    @Autowired
    private ThreatAlertRepository threatAlertRepository;

    @Autowired
    private SnortRuleRepository snortRuleRepository;

    @Test
    void testSeededUsersExist() {
        Optional<User> admin = userRepository.findByUsername("admin");
        assertTrue(admin.isPresent(), "Admin user should be seeded");
        assertEquals(Role.ROLE_ADMIN, admin.get().getRole());

        Optional<User> analyst = userRepository.findByUsername("analyst");
        assertTrue(analyst.isPresent(), "Analyst user should be seeded");
        assertEquals(Role.ROLE_ANALYST, analyst.get().getRole());

        Optional<User> student = userRepository.findByUsername("student");
        assertTrue(student.isPresent(), "Student user should be seeded");
        assertEquals(Role.ROLE_STUDENT, student.get().getRole());
    }

    @Test
    void testSeeded3DNodesExist() {
        List<NetworkNode> nodes = networkNodeRepository.findAll();
        assertFalse(nodes.isEmpty(), "Topology nodes should be seeded");
        assertTrue(nodes.stream().anyMatch(n -> "node-firewall".equals(n.getId())));
        assertTrue(nodes.stream().anyMatch(n -> "node-web".equals(n.getId())));
        assertTrue(nodes.stream().anyMatch(n -> "node-attacker".equals(n.getId())));
    }

    @Test
    void testNetworkFlowPersistence() {
        NetworkFlow flow = new NetworkFlow(
                "192.168.1.50", "192.168.1.10",
                49200, 80, "TCP", 1024L, 12L,
                0.45f, "SYN,ACK", "HTTP"
        );

        NetworkFlow saved = networkFlowRepository.save(flow);
        assertNotNull(saved.getId(), "Generated ID should not be null");

        List<NetworkFlow> retrieved = networkFlowRepository.findBySrcIpOrDstIp("192.168.1.50", "192.168.1.50");
        assertEquals(1, retrieved.size());
        assertEquals(80, retrieved.get(0).getDstPort());
    }

    @Test
    void testThreatAlertPersistence() {
        ThreatAlert alert = new ThreatAlert(
                "SID-1001", "203.0.113.88", "192.168.1.10",
                "TCP SYN Flood Denial-of-Service", "CRITICAL", 0.98f,
                "ACTIVE", "T1498", "High packet volume SYN flood without ACK completion"
        );

        ThreatAlert saved = threatAlertRepository.save(alert);
        assertNotNull(saved.getId());

        List<ThreatAlert> criticalAlerts = threatAlertRepository.findBySeverity("CRITICAL");
        assertFalse(criticalAlerts.isEmpty());
        assertEquals("CRITICAL", criticalAlerts.get(0).getSeverity());
    }

    @Test
    void testSnortRulePersistence() {
        List<SnortRule> activeRules = snortRuleRepository.findByEnabledTrue();
        assertFalse(activeRules.isEmpty(), "Seeded rules should be active");
        assertTrue(activeRules.stream().anyMatch(r -> "SID-1001".equals(r.getId())));
    }
}
