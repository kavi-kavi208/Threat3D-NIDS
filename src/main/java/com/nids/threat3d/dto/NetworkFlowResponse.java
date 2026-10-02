package com.nids.threat3d.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nids.threat3d.model.NetworkFlow;

import java.time.LocalDateTime;

/**
 * Dedicated response DTO for network flows returned by {@code GET /api/v2/traffic/recent}.
 *
 * <p>Translates JPA {@link NetworkFlow} entity fields into the frontend contract format:
 * maps {@code srcIp}/{@code dstIp} to {@code sourceIp}/{@code destinationIp},
 * converts {@code durationSec} to milliseconds ({@code durationMs}), and parses
 * the composite TCP {@code flags} string into individual counters.</p>
 */
public final class NetworkFlowResponse {

    @JsonProperty("id")
    private final Long id;

    @JsonProperty("sourceIp")
    private final String sourceIp;
    @JsonProperty("srcIp")
    private final String srcIp;

    @JsonProperty("sourcePort")
    private final int sourcePort;
    @JsonProperty("srcPort")
    private final int srcPort;

    @JsonProperty("destinationIp")
    private final String destinationIp;
    @JsonProperty("dstIp")
    private final String dstIp;

    @JsonProperty("destinationPort")
    private final int destinationPort;
    @JsonProperty("dstPort")
    private final int dstPort;

    @JsonProperty("protocol")
    private final String protocol;

    @JsonProperty("packetCount")
    private final long packetCount;
    @JsonProperty("packetsSent")
    private final long packetsSent;

    @JsonProperty("byteCount")
    private final long byteCount;
    @JsonProperty("bytesSent")
    private final long bytesSent;

    @JsonProperty("durationMs")
    private final long durationMs;
    @JsonProperty("durationSec")
    private final float durationSec;

    @JsonProperty("synCount")
    private final int synCount;
    @JsonProperty("ackCount")
    private final int ackCount;
    @JsonProperty("finCount")
    private final int finCount;
    @JsonProperty("rstCount")
    private final int rstCount;

    @JsonProperty("flags")
    private final String flags;
    @JsonProperty("service")
    private final String service;

    @JsonProperty("flowStart")
    private final LocalDateTime flowStart;

    @JsonCreator
    public NetworkFlowResponse(
            @JsonProperty("id") Long id,
            @JsonProperty("sourceIp") String sourceIp,
            @JsonProperty("srcIp") String srcIp,
            @JsonProperty("sourcePort") Integer sourcePort,
            @JsonProperty("srcPort") Integer srcPort,
            @JsonProperty("destinationIp") String destinationIp,
            @JsonProperty("dstIp") String dstIp,
            @JsonProperty("destinationPort") Integer destinationPort,
            @JsonProperty("dstPort") Integer dstPort,
            @JsonProperty("protocol") String protocol,
            @JsonProperty("packetCount") Long packetCount,
            @JsonProperty("packetsSent") Long packetsSent,
            @JsonProperty("byteCount") Long byteCount,
            @JsonProperty("bytesSent") Long bytesSent,
            @JsonProperty("durationMs") Long durationMs,
            @JsonProperty("durationSec") Float durationSec,
            @JsonProperty("synCount") Integer synCount,
            @JsonProperty("ackCount") Integer ackCount,
            @JsonProperty("finCount") Integer finCount,
            @JsonProperty("rstCount") Integer rstCount,
            @JsonProperty("flags") String flags,
            @JsonProperty("service") String service,
            @JsonProperty("flowStart") LocalDateTime flowStart) {
        this.id = id;
        this.sourceIp = sourceIp != null ? sourceIp : (srcIp != null ? srcIp : "");
        this.srcIp = this.sourceIp;
        this.sourcePort = sourcePort != null ? sourcePort : (srcPort != null ? srcPort : 0);
        this.srcPort = this.sourcePort;
        this.destinationIp = destinationIp != null ? destinationIp : (dstIp != null ? dstIp : "");
        this.dstIp = this.destinationIp;
        this.destinationPort = destinationPort != null ? destinationPort : (dstPort != null ? dstPort : 0);
        this.dstPort = this.destinationPort;
        this.protocol = protocol != null ? protocol : "TCP";
        this.packetCount = packetCount != null ? packetCount : (packetsSent != null ? packetsSent : 0L);
        this.packetsSent = this.packetCount;
        this.byteCount = byteCount != null ? byteCount : (bytesSent != null ? bytesSent : 0L);
        this.bytesSent = this.byteCount;
        this.durationSec = durationSec != null ? durationSec : (durationMs != null ? durationMs / 1000.0f : 0.0f);
        this.durationMs = durationMs != null ? durationMs : Math.round(this.durationSec * 1000.0f);
        this.synCount = synCount != null ? synCount : parseFlag(flags, "SYN");
        this.ackCount = ackCount != null ? ackCount : parseFlag(flags, "ACK");
        this.finCount = finCount != null ? finCount : parseFlag(flags, "FIN");
        this.rstCount = rstCount != null ? rstCount : parseFlag(flags, "RST");
        this.flags = flags;
        this.service = service != null ? service : "OTHER";
        this.flowStart = flowStart;
    }

    public NetworkFlowResponse(
            Long id,
            String sourceIp,
            int sourcePort,
            String destinationIp,
            int destinationPort,
            String protocol,
            long packetCount,
            long byteCount,
            long durationMs,
            float durationSec,
            int synCount,
            int ackCount,
            int finCount,
            int rstCount,
            String flags,
            String service,
            LocalDateTime flowStart) {
        this(id, sourceIp, sourceIp, sourcePort, sourcePort,
                destinationIp, destinationIp, destinationPort, destinationPort,
                protocol, packetCount, packetCount, byteCount, byteCount,
                durationMs, durationSec, synCount, ackCount, finCount, rstCount,
                flags, service, flowStart);
    }

    /** Map a {@link NetworkFlow} JPA entity to this response DTO. */
    public static NetworkFlowResponse from(NetworkFlow flow) {
        if (flow == null) return null;
        int syn = parseFlag(flow.getFlags(), "SYN");
        int ack = parseFlag(flow.getFlags(), "ACK");
        int fin = parseFlag(flow.getFlags(), "FIN");
        int rst = parseFlag(flow.getFlags(), "RST");
        long durationMs = Math.round(flow.getDurationSec() * 1000.0f);

        return new NetworkFlowResponse(
                flow.getId(),
                flow.getSrcIp(),
                flow.getSrcPort(),
                flow.getDstIp(),
                flow.getDstPort(),
                flow.getProtocol(),
                flow.getPacketsSent(),
                flow.getBytesSent(),
                durationMs,
                flow.getDurationSec(),
                syn,
                ack,
                fin,
                rst,
                flow.getFlags(),
                flow.getService(),
                flow.getFlowStart()
        );
    }

    private static int parseFlag(String flags, String flagName) {
        if (flags == null || flags.isBlank()) return 0;
        for (String part : flags.split("[,;\\s]+")) {
            String[] kv = part.split("[:=]");
            if (kv.length == 2 && kv[0].trim().equalsIgnoreCase(flagName)) {
                try {
                    return Integer.parseInt(kv[1].trim());
                } catch (NumberFormatException ignored) {
                }
            } else if (kv.length == 1 && kv[0].trim().equalsIgnoreCase(flagName)) {
                return 1;
            }
        }
        return 0;
    }

    public Long getId() { return id; }
    public String getSourceIp() { return sourceIp; }
    public String getSrcIp() { return srcIp; }
    public int getSourcePort() { return sourcePort; }
    public int getSrcPort() { return srcPort; }
    public String getDestinationIp() { return destinationIp; }
    public String getDstIp() { return dstIp; }
    public int getDestinationPort() { return destinationPort; }
    public int getDstPort() { return dstPort; }
    public String getProtocol() { return protocol; }
    public long getPacketCount() { return packetCount; }
    public long getPacketsSent() { return packetsSent; }
    public long getByteCount() { return byteCount; }
    public long getBytesSent() { return bytesSent; }
    public long getDurationMs() { return durationMs; }
    public float getDurationSec() { return durationSec; }
    public int getSynCount() { return synCount; }
    public int getAckCount() { return ackCount; }
    public int getFinCount() { return finCount; }
    public int getRstCount() { return rstCount; }
    public String getFlags() { return flags; }
    public String getService() { return service; }
    public LocalDateTime getFlowStart() { return flowStart; }
}
