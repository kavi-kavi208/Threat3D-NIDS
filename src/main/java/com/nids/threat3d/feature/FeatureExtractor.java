package com.nids.threat3d.feature;

import com.nids.threat3d.flow.AggregatedFlow;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;

/**
 * Deterministic feature extractor computing the 41-dimensional vector from active flows.
 */
@Component
public class FeatureExtractor {

    public FeatureVector extract(AggregatedFlow flow, Set<Integer> contactedPorts, Set<String> contactedDestIps) {
        if (flow == null) {
            throw new IllegalArgumentException("AggregatedFlow cannot be null");
        }

        double[] f = new double[41];

        // 1. Basic Flow Metrics
        f[0] = flow.getDurationSec();
        f[1] = encodeProtocol(flow.getKey().getProtocol());
        f[2] = encodeService(flow.getService(), flow.getKey().getDestinationPort());
        f[3] = flow.getSrcBytes();
        f[4] = flow.getDstBytes();
        f[5] = flow.getSrcPackets();
        f[6] = flow.getDstPackets();

        // 2. Traffic Rates & Dynamics
        f[7] = flow.getPacketRate();
        f[8] = flow.getByteRate();
        f[9] = flow.getAvgPacketSize();
        f[10] = flow.getPacketSizeStdDev();

        // 3. Protocol Flag Distributions
        f[11] = flow.getSynCount();
        f[12] = flow.getAckCount();
        f[13] = flow.getFinCount();
        f[14] = flow.getRstCount();
        f[15] = flow.getPshCount();
        f[16] = flow.getUrgCount();
        f[17] = flow.getAckCount() > 0 ? (double) flow.getSynCount() / flow.getAckCount() : flow.getSynCount();
        f[18] = flow.getPacketCount() > 0 ? (double) flow.getRstCount() / flow.getPacketCount() : 0.0;

        // 4. Connection State & Reliability
        f[19] = flow.getPacketCount() > 0 ? (double) flow.getFailedConnectionCount() / flow.getPacketCount() : 0.0;
        f[20] = encodeConnectionStatus(flow.getLastConnectionStatus());
        f[21] = flow.getByteCount() > 0 ? (double) (flow.getSrcBytes() + flow.getDstBytes()) / flow.getByteCount() : 0.0;

        // 5. Host & Port Aggregation Behaviors
        int portCount = contactedPorts != null ? contactedPorts.size() : 1;
        int destIpCount = contactedDestIps != null ? contactedDestIps.size() : 1;

        f[22] = flow.getPacketCount(); // destination host contact count in window
        f[23] = flow.getPacketCount(); // same service contact count
        f[24] = portCount == 1 ? 1.0 : 1.0 / portCount; // same service rate
        f[25] = portCount > 1 ? (double) (portCount - 1) / portCount : 0.0; // diff service rate
        f[26] = portCount; // unique destination ports probed
        f[27] = (flow.getSynCount() > 0 && flow.getAckCount() == 0) ? 1.0 : (double) flow.getSynCount() / Math.max(1, flow.getSynCount() + flow.getAckCount());
        f[28] = (double) flow.getRstCount() / Math.max(1, flow.getPacketCount());

        // 6. Source Host Behavioral Profile
        f[29] = flow.getPacketCount();
        f[30] = destIpCount;
        f[31] = flow.getDstBytes() > 0 ? (double) flow.getSrcBytes() / flow.getDstBytes() : flow.getSrcBytes();
        f[32] = flow.getKey().getDestinationPort() < 1024 ? 1.0 : 0.0;
        f[33] = flow.getKey().getSourcePort() >= 49152 ? 1.0 : 0.0;

        // 7. Time Distribution & Entropy Metrics
        f[34] = flow.getMeanInterArrivalTime();
        f[35] = flow.getInterArrivalTimeStdDev();
        f[36] = flow.getPacketRate() > 0 && flow.getMeanInterArrivalTime() > 0 ?
                Math.min(10.0, 1000.0 / (flow.getMeanInterArrivalTime() * flow.getPacketRate() + 1)) : 1.0;
        f[37] = calculatePortEntropy(contactedPorts);

        // 8. Security Heuristics
        f[38] = encodeDirection(flow.getKey().getSourceIp());
        f[39] = isHighRiskPort(flow.getKey().getDestinationPort()) ? 1.0 : 0.0;
        f[40] = evaluatePayloadSuspicion(flow.getLatestPayloadSnippet());

        return new FeatureVector(f);
    }

    private double encodeProtocol(String protocol) {
        if ("TCP".equalsIgnoreCase(protocol)) return 0.0;
        if ("UDP".equalsIgnoreCase(protocol)) return 1.0;
        if ("ICMP".equalsIgnoreCase(protocol)) return 2.0;
        return 3.0;
    }

    private double encodeService(String service, int port) {
        if ("HTTP".equalsIgnoreCase(service) || port == 80 || port == 8080) return 0.0;
        if ("HTTPS".equalsIgnoreCase(service) || port == 443) return 1.0;
        if ("DNS".equalsIgnoreCase(service) || port == 53) return 2.0;
        if ("SSH".equalsIgnoreCase(service) || port == 22) return 3.0;
        if ("SQL".equalsIgnoreCase(service) || port == 3306 || port == 5432) return 4.0;
        if ("ICMP".equalsIgnoreCase(service)) return 5.0;
        return 6.0;
    }

    private double encodeConnectionStatus(String status) {
        if ("ESTABLISHED".equalsIgnoreCase(status)) return 0.0;
        if ("SYN_SENT".equalsIgnoreCase(status)) return 1.0;
        if ("FAILED".equalsIgnoreCase(status)) return 2.0;
        if ("RESET".equalsIgnoreCase(status)) return 3.0;
        return 0.0;
    }

    private double encodeDirection(String sourceIp) {
        if (sourceIp.startsWith("192.168.") || sourceIp.startsWith("10.") || sourceIp.startsWith("127.")) {
            return 0.0; // INTERNAL
        }
        return 1.0; // INBOUND from External WAN
    }

    private boolean isHighRiskPort(int port) {
        return port == 22 || port == 3389 || port == 1433 || port == 3306 || port == 5432 || port == 445;
    }

    private double calculatePortEntropy(Collection<Integer> ports) {
        if (ports == null || ports.isEmpty() || ports.size() == 1) return 0.0;
        double total = ports.size();
        double entropy = 0.0;
        for (int ignored : ports) {
            double p = 1.0 / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return Math.min(5.0, entropy);
    }

    private double evaluatePayloadSuspicion(String snippet) {
        if (snippet == null || snippet.isBlank()) return 0.0;
        String upper = snippet.toUpperCase();
        double score = 0.0;
        if (upper.contains("UNION") && upper.contains("SELECT")) score += 0.7;
        if (upper.contains("' OR '1'='1") || upper.contains("\" OR \"1\"=\"1")) score += 0.8;
        if (upper.contains("../") || upper.contains("..\\")) score += 0.6;
        if (upper.contains("ETC/PASSWD") || upper.contains("CMD.EXE") || upper.contains("/BIN/SH")) score += 0.8;
        if (upper.contains("AUTH FAILED")) score += 0.5;
        if (upper.contains("ECHO_REQUEST_OVERSIZED")) score += 0.6;
        return Math.min(1.0, score);
    }
}
