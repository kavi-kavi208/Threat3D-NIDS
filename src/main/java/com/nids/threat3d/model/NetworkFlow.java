package com.nids.threat3d.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "network_flows")
public class NetworkFlow {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String srcIp;

    @Column(nullable = false, length = 64)
    private String dstIp;

    @Column(nullable = false)
    private int srcPort;

    @Column(nullable = false)
    private int dstPort;

    @Column(nullable = false, length = 16)
    private String protocol; // TCP, UDP, ICMP

    @Column(nullable = false)
    private long bytesSent;

    @Column(nullable = false)
    private long packetsSent;

    @Column(nullable = false)
    private float durationSec;

    @Column(nullable = false)
    private LocalDateTime flowStart = LocalDateTime.now();

    @Column(length = 32)
    private String flags;

    @Column(length = 32)
    private String service; // HTTP, HTTPS, SSH, DNS, SQL, ICMP

    public NetworkFlow() {
    }

    public NetworkFlow(String srcIp, String dstIp, int srcPort, int dstPort,
                       String protocol, long bytesSent, long packetsSent,
                       float durationSec, String flags, String service) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.bytesSent = bytesSent;
        this.packetsSent = packetsSent;
        this.durationSec = durationSec;
        this.flowStart = LocalDateTime.now();
        this.flags = flags;
        this.service = service;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public long getBytesSent() {
        return bytesSent;
    }

    public void setBytesSent(long bytesSent) {
        this.bytesSent = bytesSent;
    }

    public long getPacketsSent() {
        return packetsSent;
    }

    public void setPacketsSent(long packetsSent) {
        this.packetsSent = packetsSent;
    }

    public float getDurationSec() {
        return durationSec;
    }

    public void setDurationSec(float durationSec) {
        this.durationSec = durationSec;
    }

    public LocalDateTime getFlowStart() {
        return flowStart;
    }

    public void setFlowStart(LocalDateTime flowStart) {
        this.flowStart = flowStart;
    }

    public String getFlags() {
        return flags;
    }

    public void setFlags(String flags) {
        this.flags = flags;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }
}
