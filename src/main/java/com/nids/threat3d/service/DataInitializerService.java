package com.nids.threat3d.service;

import com.nids.threat3d.model.NetworkNode;
import com.nids.threat3d.model.Role;
import com.nids.threat3d.model.SnortRule;
import com.nids.threat3d.model.User;
import com.nids.threat3d.repository.NetworkNodeRepository;
import com.nids.threat3d.repository.SnortRuleRepository;
import com.nids.threat3d.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class DataInitializerService implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializerService.class);

    private final UserRepository userRepository;
    private final NetworkNodeRepository networkNodeRepository;
    private final SnortRuleRepository snortRuleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${threat3d.default-admin-password:Admin@12345}")
    private String defaultAdminPassword;

    @Value("${threat3d.default-analyst-password:Analyst@12345}")
    private String defaultAnalystPassword;

    @Value("${threat3d.default-student-password:Student@12345}")
    private String defaultStudentPassword;

    public DataInitializerService(UserRepository userRepository,
                                  NetworkNodeRepository networkNodeRepository,
                                  SnortRuleRepository snortRuleRepository,
                                  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.networkNodeRepository = networkNodeRepository;
        this.snortRuleRepository = snortRuleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        seedUsers();
        seedNetworkNodes();
        seedSnortRules();
    }

    private void seedUsers() {
        if (userRepository.count() == 0) {
            log.info("Seeding default demonstration users for RBAC...");

            User admin = new User(
                    "admin",
                    passwordEncoder.encode(defaultAdminPassword),
                    "System Administrator",
                    "admin@threat3d.local",
                    Role.ROLE_ADMIN
            );

            User analyst = new User(
                    "analyst",
                    passwordEncoder.encode(defaultAnalystPassword),
                    "SOC Security Analyst",
                    "analyst@threat3d.local",
                    Role.ROLE_ANALYST
            );

            User student = new User(
                    "student",
                    passwordEncoder.encode(defaultStudentPassword),
                    "Cybersecurity Student",
                    "student@college.edu",
                    Role.ROLE_STUDENT
            );

            userRepository.saveAll(List.of(admin, analyst, student));
            log.info("Created 3 initial demonstration users: admin, analyst, student.");
        } else {
            log.info("Synchronizing existing demonstration users' passwords...");
            syncUserPassword("admin", defaultAdminPassword);
            syncUserPassword("analyst", defaultAnalystPassword);
            syncUserPassword("student", defaultStudentPassword);
        }
    }

    private void syncUserPassword(String username, String rawPassword) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setPassword(passwordEncoder.encode(rawPassword));
            userRepository.save(user);
        });
    }

    private void seedNetworkNodes() {
        if (networkNodeRepository.count() == 0) {
            log.info("Seeding 3D SOC network topology nodes...");

            List<NetworkNode> nodes = List.of(
                    new NetworkNode(
                            "node-firewall",
                            "Perimeter Firewall",
                            "192.168.1.1",
                            "00:0C:29:1A:2B:01",
                            "FIREWALL",
                            "Perimeter DMZ",
                            0.0f, 0.0f, 0.0f,
                            "HEALTHY",
                            "80,443,22"
                    ),
                    new NetworkNode(
                            "node-router",
                            "Core Gateway Router",
                            "192.168.1.2",
                            "00:0C:29:1A:2B:02",
                            "ROUTER",
                            "192.168.1.0/24",
                            0.0f, 12.0f, -25.0f,
                            "HEALTHY",
                            "179,80"
                    ),
                    new NetworkNode(
                            "node-web",
                            "Apache Web Server",
                            "192.168.1.10",
                            "00:0C:29:1A:2B:10",
                            "WEB_SERVER",
                            "Server Subnet",
                            -35.0f, 0.0f, -40.0f,
                            "HEALTHY",
                            "80,443,8080"
                    ),
                    new NetworkNode(
                            "node-db",
                            "PostgreSQL Database",
                            "192.168.1.20",
                            "00:0C:29:1A:2B:20",
                            "DB_SERVER",
                            "Server Subnet",
                            35.0f, 0.0f, -40.0f,
                            "HEALTHY",
                            "5432"
                    ),
                    new NetworkNode(
                            "node-auth",
                            "OAuth Identity Server",
                            "192.168.1.30",
                            "00:0C:29:1A:2B:30",
                            "AUTH_SERVER",
                            "Server Subnet",
                            0.0f, -15.0f, -40.0f,
                            "HEALTHY",
                            "8443,389"
                    ),
                    new NetworkNode(
                            "node-client-1",
                            "Finance Workstation #1",
                            "192.168.1.51",
                            "00:0C:29:1A:2B:51",
                            "WORKSTATION",
                            "Client Subnet",
                            -50.0f, 10.0f, -10.0f,
                            "HEALTHY",
                            "445,139"
                    ),
                    new NetworkNode(
                            "node-client-2",
                            "Engineering Workstation #2",
                            "192.168.1.52",
                            "00:0C:29:1A:2B:52",
                            "WORKSTATION",
                            "Client Subnet",
                            50.0f, 10.0f, -10.0f,
                            "HEALTHY",
                            "445,139"
                    ),
                    new NetworkNode(
                            "node-attacker",
                            "External Adversary [WAN]",
                            "203.0.113.88",
                            "AA:BB:CC:DD:EE:FF",
                            "ATTACKER",
                            "External WAN",
                            0.0f, 25.0f, 60.0f,
                            "SUSPICIOUS",
                            "4444,5555"
                    )
            );

            networkNodeRepository.saveAll(nodes);
            log.info("Created {} 3D network topology nodes.", nodes.size());
        }
    }

    private void seedSnortRules() {
        if (snortRuleRepository.count() == 0) {
            log.info("Seeding baseline Snort signature rules...");

            List<SnortRule> rules = List.of(
                    new SnortRule(
                            "SID-1001",
                            "TCP SYN Flood Denial-of-Service",
                            "DOS",
                            "CRITICAL",
                            "flags:S; threshold:type both, track by_src, count 200, seconds 1",
                            "T1498",
                            true
                    ),
                    new SnortRule(
                            "SID-1002",
                            "Rapid Port Scanning Reconnaissance",
                            "PROBE",
                            "MEDIUM",
                            "threshold:type threshold, track by_src, count 20, seconds 2",
                            "T1046",
                            true
                    ),
                    new SnortRule(
                            "SID-1003",
                            "SQL Injection UNION SELECT in HTTP Payload",
                            "EXPLOIT",
                            "HIGH",
                            "content:\"UNION SELECT\"; nocase; http_uri",
                            "T1190",
                            true
                    ),
                    new SnortRule(
                            "SID-1004",
                            "SSH Rapid Authentication Failure Brute Force",
                            "BRUTE_FORCE",
                            "HIGH",
                            "dst_port:22; threshold:type both, track by_src, count 5, seconds 30",
                            "T1110",
                            true
                    ),
                    new SnortRule(
                            "SID-1005",
                            "ICMP Ping of Death Oversized Packet",
                            "DOS",
                            "HIGH",
                            "dsize:>1024; itype:8",
                            "T1498.001",
                            true
                    )
            );

            snortRuleRepository.saveAll(rules);
            log.info("Created {} Snort signature inspection rules.", rules.size());
        }
    }
}
