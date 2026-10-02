package com.nids.threat3d.feature;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 41-dimensional structured feature vector derived from 5-tuple aggregated network flows.
 * Aligns with standard NIDS benchmark feature taxonomies (NSL-KDD / CIC-IDS).
 */
public class FeatureVector {

    // 1. Basic Flow Metrics (1-7)
    public final double duration;                // 1. Connection duration in seconds
    public final double protocolType;            // 2. Encoded protocol: 0=TCP, 1=UDP, 2=ICMP
    public final double serviceType;             // 3. Encoded service: 0=HTTP, 1=HTTPS, 2=DNS, 3=SSH, 4=SQL, 5=ICMP, 6=OTHER
    public final double srcBytes;                // 4. Bytes transmitted from source
    public final double dstBytes;                // 5. Bytes transmitted from destination
    public final double srcPackets;              // 6. Packet count from source
    public final double dstPackets;              // 7. Packet count from destination

    // 2. Traffic Rates & Dynamics (8-11)
    public final double packetRate;              // 8. Packets per second
    public final double byteRate;                // 9. Bytes per second
    public final double avgPacketSize;           // 10. Mean packet size in bytes
    public final double packetSizeStdDev;        // 11. Standard deviation of packet sizes

    // 3. Protocol Flag Distributions (12-19)
    public final double synFlagCount;            // 12. TCP SYN flag occurrences
    public final double ackFlagCount;            // 13. TCP ACK flag occurrences
    public final double finFlagCount;            // 14. TCP FIN flag occurrences
    public final double rstFlagCount;            // 15. TCP RST flag occurrences
    public final double pshFlagCount;            // 16. TCP PSH flag occurrences
    public final double urgFlagCount;            // 17. TCP URG flag occurrences
    public final double synAckRatio;             // 18. SYN to ACK ratio (flood indicator)
    public final double rstRate;                 // 19. Ratio of RST packets to total packets

    // 4. Connection State & Reliability (20-22)
    public final double failedConnectionRatio;   // 20. Fraction of failed/reset connections
    public final double connectionStatusCode;    // 21. 0=ESTABLISHED, 1=SYN_SENT, 2=FAILED, 3=RESET
    public final double payloadRatio;            // 22. Ratio of payload bytes to total wire bytes

    // 5. Host & Port Aggregation Behaviors (23-29)
    public final double dstHostCount;            // 23. Connections targeting destination in window
    public final double dstHostSrvCount;         // 24. Connections targeting same port/service on destination
    public final double dstHostSameSrvRate;      // 25. Percentage targeting same service
    public final double dstHostDiffSrvRate;      // 26. Percentage targeting different services
    public final double dstHostDiffPortCount;    // 27. Number of unique ports contacted (port scan indicator)
    public final double dstHostSerrorRate;       // 28. SYN error rate to destination
    public final double dstHostRerrorRate;       // 29. REJ/RST error rate to destination

    // 6. Source Host Behavioral Profile (30-34)
    public final double srcHostCount;            // 30. Total connections originating from source IP
    public final double srcHostDiffDstCount;     // 31. Number of distinct destination IPs contacted
    public final double inboundOutboundRatio;    // 32. Inbound vs outbound traffic balance
    public final double isPrivilegedPort;        // 33. 1 if targeting privileged port (<1024), else 0
    public final double isEphemeralPort;         // 34. 1 if source port is ephemeral (>=49152), else 0

    // 7. Time Distribution & Entropy Metrics (35-38)
    public final double interArrivalTimeMean;    // 35. Mean millisecond gap between packets
    public final double interArrivalTimeStdDev;  // 36. Jitter / standard deviation of packet inter-arrival
    public final double burstinessIndicator;     // 37. Ratio of peak packet frequency to average frequency
    public final double portEntropy;             // 38. Shannon entropy across destination ports

    // 8. Security Heuristics (39-41)
    public final double directionCode;           // 39. 0=INTERNAL, 1=INBOUND, 2=OUTBOUND
    public final double isHighRiskService;       // 40. 1 for SSH, SQL, RDP targets, else 0
    public final double payloadSuspicionScore;   // 41. Heuristic score (0.0 - 1.0) based on payload keywords

    public FeatureVector(double[] f) {
        if (f.length < 41) {
            throw new IllegalArgumentException("Feature vector requires exactly 41 dimensions, received: " + f.length);
        }
        this.duration = f[0];
        this.protocolType = f[1];
        this.serviceType = f[2];
        this.srcBytes = f[3];
        this.dstBytes = f[4];
        this.srcPackets = f[5];
        this.dstPackets = f[6];
        this.packetRate = f[7];
        this.byteRate = f[8];
        this.avgPacketSize = f[9];
        this.packetSizeStdDev = f[10];
        this.synFlagCount = f[11];
        this.ackFlagCount = f[12];
        this.finFlagCount = f[13];
        this.rstFlagCount = f[14];
        this.pshFlagCount = f[15];
        this.urgFlagCount = f[16];
        this.synAckRatio = f[17];
        this.rstRate = f[18];
        this.failedConnectionRatio = f[19];
        this.connectionStatusCode = f[20];
        this.payloadRatio = f[21];
        this.dstHostCount = f[22];
        this.dstHostSrvCount = f[23];
        this.dstHostSameSrvRate = f[24];
        this.dstHostDiffSrvRate = f[25];
        this.dstHostDiffPortCount = f[26];
        this.dstHostSerrorRate = f[27];
        this.dstHostRerrorRate = f[28];
        this.srcHostCount = f[29];
        this.srcHostDiffDstCount = f[30];
        this.inboundOutboundRatio = f[31];
        this.isPrivilegedPort = f[32];
        this.isEphemeralPort = f[33];
        this.interArrivalTimeMean = f[34];
        this.interArrivalTimeStdDev = f[35];
        this.burstinessIndicator = f[36];
        this.portEntropy = f[37];
        this.directionCode = f[38];
        this.isHighRiskService = f[39];
        this.payloadSuspicionScore = f[40];
    }

    public double[] toArray() {
        return new double[]{
                duration, protocolType, serviceType, srcBytes, dstBytes, srcPackets, dstPackets,
                packetRate, byteRate, avgPacketSize, packetSizeStdDev, synFlagCount, ackFlagCount,
                finFlagCount, rstFlagCount, pshFlagCount, urgFlagCount, synAckRatio, rstRate,
                failedConnectionRatio, connectionStatusCode, payloadRatio, dstHostCount,
                dstHostSrvCount, dstHostSameSrvRate, dstHostDiffSrvRate, dstHostDiffPortCount,
                dstHostSerrorRate, dstHostRerrorRate, srcHostCount, srcHostDiffDstCount,
                inboundOutboundRatio, isPrivilegedPort, isEphemeralPort, interArrivalTimeMean,
                interArrivalTimeStdDev, burstinessIndicator, portEntropy, directionCode,
                isHighRiskService, payloadSuspicionScore
        };
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("duration", duration);
        map.put("protocolType", protocolType);
        map.put("serviceType", serviceType);
        map.put("srcBytes", srcBytes);
        map.put("dstBytes", dstBytes);
        map.put("srcPackets", srcPackets);
        map.put("dstPackets", dstPackets);
        map.put("packetRate", packetRate);
        map.put("byteRate", byteRate);
        map.put("avgPacketSize", avgPacketSize);
        map.put("packetSizeStdDev", packetSizeStdDev);
        map.put("synFlagCount", synFlagCount);
        map.put("ackFlagCount", ackFlagCount);
        map.put("finFlagCount", finFlagCount);
        map.put("rstFlagCount", rstFlagCount);
        map.put("pshFlagCount", pshFlagCount);
        map.put("urgFlagCount", urgFlagCount);
        map.put("synAckRatio", synAckRatio);
        map.put("rstRate", rstRate);
        map.put("failedConnectionRatio", failedConnectionRatio);
        map.put("connectionStatusCode", connectionStatusCode);
        map.put("payloadRatio", payloadRatio);
        map.put("dstHostCount", dstHostCount);
        map.put("dstHostSrvCount", dstHostSrvCount);
        map.put("dstHostSameSrvRate", dstHostSameSrvRate);
        map.put("dstHostDiffSrvRate", dstHostDiffSrvRate);
        map.put("dstHostDiffPortCount", dstHostDiffPortCount);
        map.put("dstHostSerrorRate", dstHostSerrorRate);
        map.put("dstHostRerrorRate", dstHostRerrorRate);
        map.put("srcHostCount", srcHostCount);
        map.put("srcHostDiffDstCount", srcHostDiffDstCount);
        map.put("inboundOutboundRatio", inboundOutboundRatio);
        map.put("isPrivilegedPort", isPrivilegedPort);
        map.put("isEphemeralPort", isEphemeralPort);
        map.put("interArrivalTimeMean", interArrivalTimeMean);
        map.put("interArrivalTimeStdDev", interArrivalTimeStdDev);
        map.put("burstinessIndicator", burstinessIndicator);
        map.put("portEntropy", portEntropy);
        map.put("directionCode", directionCode);
        map.put("isHighRiskService", isHighRiskService);
        map.put("payloadSuspicionScore", payloadSuspicionScore);
        return map;
    }
}
