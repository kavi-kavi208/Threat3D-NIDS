package com.nids.threat3d.flow;

import java.util.Objects;

/**
 * Immutable 5-tuple identifier for network flows:
 * (Source IP, Destination IP, Source Port, Destination Port, Protocol).
 */
public final class FlowKey {

    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;

    public FlowKey(String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol) {
        this.sourceIp = sourceIp != null ? sourceIp.trim() : "";
        this.destinationIp = destinationIp != null ? destinationIp.trim() : "";
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol != null ? protocol.trim().toUpperCase() : "TCP";
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlowKey flowKey = (FlowKey) o;
        return sourcePort == flowKey.sourcePort &&
                destinationPort == flowKey.destinationPort &&
                sourceIp.equals(flowKey.sourceIp) &&
                destinationIp.equals(flowKey.destinationIp) &&
                protocol.equals(flowKey.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]", sourceIp, sourcePort, destinationIp, destinationPort, protocol);
    }
}
