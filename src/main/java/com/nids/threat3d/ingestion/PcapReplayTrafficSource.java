package com.nids.threat3d.ingestion;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Replays pre-recorded packet capture sequences.
 * Pure Java implementation that operates safely in memory without requiring native libpcap/Npcap drivers.
 */
public class PcapReplayTrafficSource implements TrafficSource {

    private final List<TrafficRecord> preloadedRecords = new ArrayList<>();
    private int cursor = 0;

    public PcapReplayTrafficSource() {
        initDefaultSampleTrace();
    }

    public PcapReplayTrafficSource(List<TrafficRecord> customRecords) {
        if (customRecords != null) {
            this.preloadedRecords.addAll(customRecords);
        }
    }

    private void initDefaultSampleTrace() {
        Instant base = Instant.now().minusSeconds(60);
        // Pre-loaded defensive capture trace of multi-stage reconnaissance
        preloadedRecords.add(new TrafficRecord(base.plusMillis(100), "198.51.100.42", "192.168.1.10", 41201, 80, "TCP", 64, Set.of("SYN"), 0, "INBOUND", "HTTP", "SYN_SENT", ""));
        preloadedRecords.add(new TrafficRecord(base.plusMillis(200), "198.51.100.42", "192.168.1.10", 41202, 443, "TCP", 64, Set.of("SYN"), 0, "INBOUND", "HTTPS", "SYN_SENT", ""));
        preloadedRecords.add(new TrafficRecord(base.plusMillis(300), "198.51.100.42", "192.168.1.10", 41203, 22, "TCP", 64, Set.of("SYN"), 0, "INBOUND", "SSH", "SYN_SENT", ""));
        preloadedRecords.add(new TrafficRecord(base.plusMillis(400), "198.51.100.42", "192.168.1.10", 41204, 3306, "TCP", 64, Set.of("SYN"), 0, "INBOUND", "SQL", "SYN_SENT", ""));
        preloadedRecords.add(new TrafficRecord(base.plusMillis(500), "198.51.100.42", "192.168.1.10", 41205, 8080, "TCP", 64, Set.of("SYN"), 0, "INBOUND", "HTTP", "SYN_SENT", ""));
    }

    @Override
    public String getSourceType() {
        return "PCAP_REPLAY";
    }

    @Override
    public synchronized List<TrafficRecord> pollBatch(int batchSize) {
        if (cursor >= preloadedRecords.size()) {
            return Collections.emptyList();
        }
        int to = Math.min(preloadedRecords.size(), cursor + batchSize);
        List<TrafficRecord> sublist = new ArrayList<>(preloadedRecords.subList(cursor, to));
        cursor = to;
        return sublist;
    }

    @Override
    public synchronized boolean hasMore() {
        return cursor < preloadedRecords.size();
    }

    @Override
    public synchronized void reset() {
        this.cursor = 0;
    }
}
