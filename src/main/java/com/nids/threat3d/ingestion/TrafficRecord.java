package com.nids.threat3d.ingestion;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Safe internal representation of a network traffic record.
 * Designed for defensive simulation and analysis without storing harmful payloads.
 */
public class TrafficRecord {

    private final Instant timestamp;
    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol; // TCP, UDP, ICMP
    private final int packetSize; // in bytes
    private final Set<String> tcpFlags; // SYN, ACK, FIN, RST, PSH, URG
    private final int payloadLength;
    private final String direction; // INBOUND, OUTBOUND, INTERNAL
    private final String applicationProtocol; // HTTP, HTTPS, DNS, SSH, ICMP, OTHER
    private final String connectionStatus; // ESTABLISHED, SYN_SENT, CLOSED, RESET, FAILED
    private final String simulatedPayloadSnippet; // Safe simulated tokens (e.g. "GET /index.html")

    public TrafficRecord(Instant timestamp, String sourceIp, String destinationIp,
                         int sourcePort, int destinationPort, String protocol,
                         int packetSize, Set<String> tcpFlags, int payloadLength,
                         String direction, String applicationProtocol,
                         String connectionStatus, String simulatedPayloadSnippet) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or blank");
        }
        if (destinationIp == null || destinationIp.isBlank()) {
            throw new IllegalArgumentException("Destination IP cannot be null or blank");
        }
        if (sourcePort < 0 || sourcePort > 65535) {
            throw new IllegalArgumentException("Invalid source port: " + sourcePort);
        }
        if (destinationPort < 0 || destinationPort > 65535) {
            throw new IllegalArgumentException("Invalid destination port: " + destinationPort);
        }
        if (protocol == null || protocol.isBlank()) {
            throw new IllegalArgumentException("Protocol cannot be null or blank");
        }

        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol.toUpperCase();
        this.packetSize = Math.max(20, packetSize);
        this.tcpFlags = tcpFlags != null ? Collections.unmodifiableSet(new HashSet<>(tcpFlags)) : Collections.emptySet();
        this.payloadLength = Math.max(0, payloadLength);
        this.direction = direction != null ? direction.toUpperCase() : "INTERNAL";
        this.applicationProtocol = applicationProtocol != null ? applicationProtocol.toUpperCase() : "OTHER";
        this.connectionStatus = connectionStatus != null ? connectionStatus.toUpperCase() : "ESTABLISHED";
        this.simulatedPayloadSnippet = simulatedPayloadSnippet != null ? simulatedPayloadSnippet : "";
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public Set<String> getTcpFlags() {
        return tcpFlags;
    }

    public boolean hasFlag(String flag) {
        return tcpFlags.contains(flag.toUpperCase());
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public String getDirection() {
        return direction;
    }

    public String getApplicationProtocol() {
        return applicationProtocol;
    }

    public String getConnectionStatus() {
        return connectionStatus;
    }

    public String getSimulatedPayloadSnippet() {
        return simulatedPayloadSnippet;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s:%d -> %s:%d (%s) size=%dB flags=%s",
                timestamp, sourceIp, sourcePort, destinationIp, destinationPort,
                protocol, packetSize, tcpFlags);
    }
}
