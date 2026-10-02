package com.nids.threat3d.ingestion;

import java.util.List;

/**
 * Pluggable abstraction for network traffic ingestion.
 * Supports synthetic generated data and replay modes.
 */
public interface TrafficSource {

    /**
     * Identifies source type (e.g. "SYNTHETIC", "PCAP_REPLAY").
     */
    String getSourceType();

    /**
     * Polls the next batch of traffic records.
     *
     * @param batchSize maximum records to fetch
     * @return list of parsed TrafficRecord instances
     */
    List<TrafficRecord> pollBatch(int batchSize);

    /**
     * Whether more records are available.
     */
    boolean hasMore();

    /**
     * Resets the source to the beginning.
     */
    void reset();
}
