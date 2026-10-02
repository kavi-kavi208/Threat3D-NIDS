package com.nids.threat3d.flow;

import com.nids.threat3d.ingestion.TrafficRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe 5-tuple flow aggregator maintaining active conversation windows.
 * Safeguards memory by evicting expired flows and enforces bounded tracking limits.
 */
@Component
public class FlowTracker {

    private static final Logger log = LoggerFactory.getLogger(FlowTracker.class);

    private final Map<FlowKey, AggregatedFlow> activeFlows = new ConcurrentHashMap<>();
    private final Map<String, Set<Integer>> sourceContactedPorts = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> sourceContactedDestIps = new ConcurrentHashMap<>();

    @Value("${threat3d.flow.expiration-ms:60000}")
    private long flowExpirationMs = 60000;

    @Value("${threat3d.flow.max-active-flows:5000}")
    private int maxActiveFlows = 5000;

    /**
     * Ingests a single traffic record and aggregates into its corresponding flow.
     */
    public AggregatedFlow processRecord(TrafficRecord record) {
        if (record == null) return null;

        FlowKey key = new FlowKey(
                record.getSourceIp(),
                record.getDestinationIp(),
                record.getSourcePort(),
                record.getDestinationPort(),
                record.getProtocol()
        );

        // Host-level port scan and destination tracking
        sourceContactedPorts.computeIfAbsent(record.getSourceIp(), k -> ConcurrentHashMap.newKeySet())
                .add(record.getDestinationPort());
        sourceContactedDestIps.computeIfAbsent(record.getSourceIp(), k -> ConcurrentHashMap.newKeySet())
                .add(record.getDestinationIp());

        // Check capacity safeguard
        if (activeFlows.size() >= maxActiveFlows) {
            evictExpiredFlows();
        }

        return activeFlows.compute(key, (k, existingFlow) -> {
            if (existingFlow == null) {
                return new AggregatedFlow(k, record);
            } else {
                existingFlow.update(record);
                return existingFlow;
            }
        });
    }

    /**
     * Evicts flows whose last activity exceeds the expiration threshold.
     */
    public synchronized int evictExpiredFlows() {
        Instant cutoff = Instant.now().minusMillis(flowExpirationMs);
        int initialSize = activeFlows.size();

        activeFlows.entrySet().removeIf(entry -> entry.getValue().getLastSeen().isBefore(cutoff));

        int evicted = initialSize - activeFlows.size();
        if (evicted > 0) {
            log.debug("Evicted {} idle flows from active tracker.", evicted);
        }
        return evicted;
    }

    public List<AggregatedFlow> getActiveFlows() {
        return new ArrayList<>(activeFlows.values());
    }

    public Optional<AggregatedFlow> getFlow(FlowKey key) {
        return Optional.ofNullable(activeFlows.get(key));
    }

    public Set<Integer> getContactedPortsForSource(String sourceIp) {
        return sourceContactedPorts.getOrDefault(sourceIp, Collections.emptySet());
    }

    public Set<String> getContactedDestIpsForSource(String sourceIp) {
        return sourceContactedDestIps.getOrDefault(sourceIp, Collections.emptySet());
    }

    public int getActiveFlowCount() {
        return activeFlows.size();
    }

    public void clear() {
        activeFlows.clear();
        sourceContactedPorts.clear();
        sourceContactedDestIps.clear();
    }
}
