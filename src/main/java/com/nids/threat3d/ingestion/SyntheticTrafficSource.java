package com.nids.threat3d.ingestion;

import com.nids.threat3d.simulation.ScenarioType;

import java.time.Instant;
import java.util.*;

/**
 * High-performance, safe synthetic traffic generator.
 * Produces structured in-memory TrafficRecord objects simulating realistic normal and anomalous flows.
 * Does NOT generate real-world network packets or exploit systems.
 */
public class SyntheticTrafficSource implements TrafficSource {

    private final ScenarioType scenarioType;
    private final int totalRecords;
    private int generatedCount = 0;
    private final Random random = new Random(42); // Deterministic seed for reproducible tests

    public SyntheticTrafficSource(ScenarioType scenarioType, int totalRecords) {
        this.scenarioType = scenarioType != null ? scenarioType : ScenarioType.NORMAL_TRAFFIC;
        this.totalRecords = Math.max(1, totalRecords);
    }

    @Override
    public String getSourceType() {
        return "SYNTHETIC:" + scenarioType.name();
    }

    @Override
    public synchronized List<TrafficRecord> pollBatch(int batchSize) {
        int countToGenerate = Math.min(batchSize, totalRecords - generatedCount);
        if (countToGenerate <= 0) {
            return Collections.emptyList();
        }

        List<TrafficRecord> batch = new ArrayList<>(countToGenerate);
        for (int i = 0; i < countToGenerate; i++) {
            batch.add(generateRecord(generatedCount++));
        }
        return batch;
    }

    @Override
    public synchronized boolean hasMore() {
        return generatedCount < totalRecords;
    }

    @Override
    public synchronized void reset() {
        this.generatedCount = 0;
    }

    private TrafficRecord generateRecord(int index) {
        Instant now = Instant.now().minusMillis((totalRecords - index) * 50L);

        switch (scenarioType) {
            case PORT_SCAN_PATTERN:
                return generatePortScanRecord(now, index);
            case SYN_FLOOD_PATTERN:
                return generateSynFloodRecord(now, index);
            case ICMP_FLOOD_PATTERN:
                return generateIcmpFloodRecord(now, index);
            case BRUTE_FORCE_PATTERN:
                return generateBruteForceRecord(now, index);
            case WEB_ANOMALY_PATTERN:
                return generateWebAnomalyRecord(now, index);
            case MIXED_SUSPICIOUS_ACTIVITY:
                return generateMixedRecord(now, index);
            case NORMAL_TRAFFIC:
            default:
                return generateNormalRecord(now, index);
        }
    }

    private TrafficRecord generateNormalRecord(Instant timestamp, int index) {
        String[] clients = {"192.168.1.51", "192.168.1.52"};
        String clientIp = clients[index % clients.length];
        int clientPort = 49152 + (index % 1000);

        if (index % 3 == 0) {
            // Normal HTTP browse
            return new TrafficRecord(
                    timestamp, clientIp, "192.168.1.10",
                    clientPort, 80, "TCP",
                    512 + random.nextInt(512),
                    Set.of("ACK", "PSH"),
                    256, "INTERNAL", "HTTP", "ESTABLISHED",
                    "GET /dashboard/metrics HTTP/1.1"
            );
        } else if (index % 3 == 1) {
            // Normal DNS lookup
            return new TrafficRecord(
                    timestamp, clientIp, "192.168.1.1",
                    clientPort, 53, "UDP",
                    68,
                    Collections.emptySet(),
                    48, "INTERNAL", "DNS", "ESTABLISHED",
                    "QUERY api.internal.local A"
            );
        } else {
            // Normal DB query
            return new TrafficRecord(
                    timestamp, "192.168.1.10", "192.168.1.20",
                    50000 + (index % 100), 5432, "TCP",
                    256 + random.nextInt(128),
                    Set.of("ACK"),
                    128, "INTERNAL", "SQL", "ESTABLISHED",
                    "SELECT count(*) FROM telemetry"
            );
        }
    }

    private TrafficRecord generatePortScanRecord(Instant timestamp, int index) {
        int[] targetPorts = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9000};
        int targetPort = targetPorts[index % targetPorts.length];

        return new TrafficRecord(
                timestamp, "203.0.113.88", "192.168.1.10",
                55000 + (index % 500), targetPort, "TCP",
                60,
                Set.of("SYN"),
                0, "INBOUND", "OTHER", "SYN_SENT",
                ""
        );
    }

    private TrafficRecord generateSynFloodRecord(Instant timestamp, int index) {
        return new TrafficRecord(
                timestamp, "203.0.113.88", "192.168.1.10",
                40000, 80, "TCP",
                64,
                Set.of("SYN"),
                0, "INBOUND", "HTTP", "SYN_SENT",
                ""
        );
    }

    private TrafficRecord generateIcmpFloodRecord(Instant timestamp, int index) {
        return new TrafficRecord(
                timestamp, "203.0.113.88", "192.168.1.1",
                0, 0, "ICMP",
                1450, // Oversized echo request
                Collections.emptySet(),
                1400, "INBOUND", "ICMP", "ESTABLISHED",
                "ECHO_REQUEST_OVERSIZED"
        );
    }

    private TrafficRecord generateBruteForceRecord(Instant timestamp, int index) {
        return new TrafficRecord(
                timestamp, "203.0.113.88", "192.168.1.10",
                48000, 22, "TCP",
                112,
                Set.of("RST", "ACK"),
                44, "INBOUND", "SSH", "FAILED",
                "SSH-2.0-OpenSSH Auth Failed User=root"
        );
    }

    private TrafficRecord generateWebAnomalyRecord(Instant timestamp, int index) {
        String[] payloads = {
                "GET /catalog?id=1 UNION SELECT 1,username,password FROM accounts--",
                "POST /auth/login HTTP/1.1 payload: ' OR '1'='1' --",
                "GET /cgi-bin/test.cgi?path=../../../etc/passwd"
        };
        String snippet = payloads[index % payloads.length];

        return new TrafficRecord(
                timestamp, "203.0.113.88", "192.168.1.10",
                49200 + index, 80, "TCP",
                480,
                Set.of("ACK", "PSH"),
                220, "INBOUND", "HTTP", "ESTABLISHED",
                snippet
        );
    }

    private TrafficRecord generateMixedRecord(Instant timestamp, int index) {
        if (index < totalRecords * 0.3) {
            return generatePortScanRecord(timestamp, index);
        } else if (index < totalRecords * 0.6) {
            return generateBruteForceRecord(timestamp, index);
        } else {
            return generateSynFloodRecord(timestamp, index);
        }
    }
}
