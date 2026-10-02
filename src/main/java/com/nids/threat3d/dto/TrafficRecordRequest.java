package com.nids.threat3d.dto;

import jakarta.validation.constraints.*;
import java.util.Collections;
import java.util.Set;

/**
 * Request DTO — submit a single synthetic or PCAP-replay traffic record
 * for processing through the NIDS detection pipeline.
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong><br>
 * This record is processed in-memory and never transmitted on a real network.</p>
 */
public final class TrafficRecordRequest {

    @NotBlank(message = "sourceIp is required")
    @Pattern(regexp = "^(\\d{1,3}\\.){3}\\d{1,3}$",
             message = "sourceIp must be a valid IPv4 address")
    private String sourceIp;

    @NotBlank(message = "destinationIp is required")
    @Pattern(regexp = "^(\\d{1,3}\\.){3}\\d{1,3}$",
             message = "destinationIp must be a valid IPv4 address")
    private String destinationIp;

    @Min(value = 0,     message = "sourcePort must be 0–65535")
    @Max(value = 65535, message = "sourcePort must be 0–65535")
    private int sourcePort;

    @Min(value = 0,     message = "destinationPort must be 0–65535")
    @Max(value = 65535, message = "destinationPort must be 0–65535")
    private int destinationPort;

    @NotBlank(message = "protocol is required (TCP, UDP, ICMP)")
    @Pattern(regexp = "(?i)^(TCP|UDP|ICMP)$",
             message = "protocol must be TCP, UDP, or ICMP")
    private String protocol;

    @Min(value = 20,   message = "packetSize minimum is 20 bytes")
    @Max(value = 65535, message = "packetSize maximum is 65535 bytes")
    private int packetSize = 64;

    /** TCP flags e.g. ["SYN","ACK"]. Empty for UDP/ICMP. */
    private Set<String> tcpFlags = Collections.emptySet();

    @Min(value = 0, message = "payloadLength cannot be negative")
    private int payloadLength;

    /** INBOUND, OUTBOUND, or INTERNAL. Defaults to INTERNAL. */
    private String direction = "INTERNAL";

    /** HTTP, HTTPS, DNS, SSH, SQL, ICMP, OTHER. Defaults to OTHER. */
    private String applicationProtocol = "OTHER";

    /** ESTABLISHED, SYN_SENT, CLOSED, RESET, FAILED. Defaults to ESTABLISHED. */
    private String connectionStatus = "ESTABLISHED";

    /**
     * Safe simulated payload snippet only — e.g. "GET /index.html HTTP/1.1".
     * Must NOT contain real exploit code or credentials.
     */
    @Size(max = 512, message = "simulatedPayloadSnippet must not exceed 512 characters")
    private String simulatedPayloadSnippet = "";

    // ── Constructors ─────────────────────────────────────────────────────────
    public TrafficRecordRequest() {}

    // ── Getters and setters ──────────────────────────────────────────────────
    public String getSourceIp()                  { return sourceIp; }
    public void setSourceIp(String v)            { this.sourceIp = v; }

    public String getDestinationIp()             { return destinationIp; }
    public void setDestinationIp(String v)       { this.destinationIp = v; }

    public int getSourcePort()                   { return sourcePort; }
    public void setSourcePort(int v)             { this.sourcePort = v; }

    public int getDestinationPort()              { return destinationPort; }
    public void setDestinationPort(int v)        { this.destinationPort = v; }

    public String getProtocol()                  { return protocol; }
    public void setProtocol(String v)            { this.protocol = v; }

    public int getPacketSize()                   { return packetSize; }
    public void setPacketSize(int v)             { this.packetSize = v; }

    public Set<String> getTcpFlags()             { return tcpFlags; }
    public void setTcpFlags(Set<String> v)       { this.tcpFlags = v != null ? v : Collections.emptySet(); }

    public int getPayloadLength()                { return payloadLength; }
    public void setPayloadLength(int v)          { this.payloadLength = v; }

    public String getDirection()                 { return direction; }
    public void setDirection(String v)           { this.direction = v; }

    public String getApplicationProtocol()       { return applicationProtocol; }
    public void setApplicationProtocol(String v) { this.applicationProtocol = v; }

    public String getConnectionStatus()          { return connectionStatus; }
    public void setConnectionStatus(String v)    { this.connectionStatus = v; }

    public String getSimulatedPayloadSnippet()   { return simulatedPayloadSnippet; }
    public void setSimulatedPayloadSnippet(String v) { this.simulatedPayloadSnippet = v != null ? v : ""; }
}
