package com.nids.threat3d.dto;

public class ChatRequest {
    private String query;
    private String threatId;

    public ChatRequest() {}

    public ChatRequest(String query, String threatId) {
        this.query = query;
        this.threatId = threatId;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getThreatId() {
        return threatId;
    }

    public void setThreatId(String threatId) {
        this.threatId = threatId;
    }
}
