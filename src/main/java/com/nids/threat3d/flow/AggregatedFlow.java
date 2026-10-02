package com.nids.threat3d.flow;

import com.nids.threat3d.ingestion.TrafficRecord;
import com.nids.threat3d.model.NetworkFlow;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * Thread-safe aggregated state of a 5-tuple network conversation over a sliding window.
 */
public class AggregatedFlow {

    private final FlowKey key;
    private final Instant firstSeen;
    private volatile Instant lastSeen;

    private long packetCount = 0;
    private long byteCount = 0;
    private long srcBytes = 0;
    private long dstBytes = 0;
    private long srcPackets = 0;
    private long dstPackets = 0;

    private int synCount = 0;
    private int ackCount = 0;
    private int finCount = 0;
    private int rstCount = 0;
    private int pshCount = 0;
    private int urgCount = 0;

    private int failedConnectionCount = 0;
    private final List<Integer> packetSizes = new ArrayList<>();
    private final List<Long> interArrivalTimes = new ArrayList<>();
    private Instant previousPacketTime = null;

    private String service = "OTHER";
    private String lastConnectionStatus = "ESTABLISHED";
    private String latestPayloadSnippet = "";

    public AggregatedFlow(FlowKey key, TrafficRecord initialRecord) {
        this.key = key;
        this.firstSeen = initialRecord.getTimestamp();
        this.lastSeen = initialRecord.getTimestamp();
        update(initialRecord);
    }

    public synchronized void update(TrafficRecord record) {
        this.lastSeen = record.getTimestamp();
        this.packetCount++;
        this.byteCount += record.getPacketSize();

        if ("INBOUND".equalsIgnoreCase(record.getDirection()) || record.getSourceIp().equals(key.getSourceIp())) {
            this.srcBytes += record.getPacketSize();
            this.srcPackets++;
        } else {
            this.dstBytes += record.getPacketSize();
            this.dstPackets++;
        }

        if (record.hasFlag("SYN")) synCount++;
        if (record.hasFlag("ACK")) ackCount++;
        if (record.hasFlag("FIN")) finCount++;
        if (record.hasFlag("RST")) rstCount++;
        if (record.hasFlag("PSH")) pshCount++;
        if (record.hasFlag("URG")) urgCount++;

        if ("FAILED".equalsIgnoreCase(record.getConnectionStatus()) || record.hasFlag("RST")) {
            failedConnectionCount++;
        }

        this.service = record.getApplicationProtocol();
        this.lastConnectionStatus = record.getConnectionStatus();
        if (!record.getSimulatedPayloadSnippet().isBlank()) {
            this.latestPayloadSnippet = record.getSimulatedPayloadSnippet();
        }

        if (packetSizes.size() < 100) {
            packetSizes.add(record.getPacketSize());
        }

        if (previousPacketTime != null) {
            long diffMs = Math.max(0, record.getTimestamp().toEpochMilli() - previousPacketTime.toEpochMilli());
            if (interArrivalTimes.size() < 100) {
                interArrivalTimes.add(diffMs);
            }
        }
        previousPacketTime = record.getTimestamp();
    }

    public FlowKey getKey() {
        return key;
    }

    public Instant getFirstSeen() {
        return firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public synchronized long getPacketCount() {
        return packetCount;
    }

    public synchronized long getByteCount() {
        return byteCount;
    }

    public synchronized long getSrcBytes() {
        return srcBytes;
    }

    public synchronized long getDstBytes() {
        return dstBytes;
    }

    public synchronized long getSrcPackets() {
        return srcPackets;
    }

    public synchronized long getDstPackets() {
        return dstPackets;
    }

    public synchronized int getSynCount() {
        return synCount;
    }

    public synchronized int getAckCount() {
        return ackCount;
    }

    public synchronized int getFinCount() {
        return finCount;
    }

    public synchronized int getRstCount() {
        return rstCount;
    }

    public synchronized int getPshCount() {
        return pshCount;
    }

    public synchronized int getUrgCount() {
        return urgCount;
    }

    public synchronized int getFailedConnectionCount() {
        return failedConnectionCount;
    }

    public synchronized double getDurationSec() {
        long durationMs = Math.max(1, lastSeen.toEpochMilli() - firstSeen.toEpochMilli());
        return durationMs / 1000.0;
    }

    public synchronized double getPacketRate() {
        double duration = getDurationSec();
        return duration > 0 ? packetCount / duration : packetCount;
    }

    public synchronized double getByteRate() {
        double duration = getDurationSec();
        return duration > 0 ? byteCount / duration : byteCount;
    }

    public synchronized double getAvgPacketSize() {
        if (packetSizes.isEmpty()) return 0.0;
        return packetSizes.stream().mapToInt(Integer::intValue).average().orElse(0.0);
    }

    public synchronized double getPacketSizeStdDev() {
        if (packetSizes.size() <= 1) return 0.0;
        double mean = getAvgPacketSize();
        double sumSquareDiff = packetSizes.stream()
                .mapToDouble(s -> Math.pow(s - mean, 2))
                .sum();
        return Math.sqrt(sumSquareDiff / packetSizes.size());
    }

    public synchronized double getMeanInterArrivalTime() {
        if (interArrivalTimes.isEmpty()) return 0.0;
        return interArrivalTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
    }

    public synchronized double getInterArrivalTimeStdDev() {
        if (interArrivalTimes.size() <= 1) return 0.0;
        double mean = getMeanInterArrivalTime();
        double sumSquareDiff = interArrivalTimes.stream()
                .mapToDouble(t -> Math.pow(t - mean, 2))
                .sum();
        return Math.sqrt(sumSquareDiff / interArrivalTimes.size());
    }

    public String getService() {
        return service;
    }

    public String getLastConnectionStatus() {
        return lastConnectionStatus;
    }

    public String getLatestPayloadSnippet() {
        return latestPayloadSnippet;
    }

    /**
     * Converts aggregated in-memory metrics to persistent NetworkFlow entity.
     */
    public synchronized NetworkFlow toNetworkFlowEntity() {
        String flagsStr = String.format("SYN:%d,ACK:%d,FIN:%d,RST:%d", synCount, ackCount, finCount, rstCount);
        NetworkFlow flow = new NetworkFlow(
                key.getSourceIp(),
                key.getDestinationIp(),
                key.getSourcePort(),
                key.getDestinationPort(),
                key.getProtocol(),
                byteCount,
                packetCount,
                (float) getDurationSec(),
                flagsStr,
                service
        );
        flow.setFlowStart(LocalDateTime.ofInstant(firstSeen, ZoneId.systemDefault()));
        return flow;
    }
}
