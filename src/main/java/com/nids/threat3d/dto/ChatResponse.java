package com.nids.threat3d.dto;

/**
 * DTO returned by the chatbot explain endpoint.
 * Mirrors the frontend TypeScript ChatResponse definition.
 */
public class ChatResponse {
    private String answer;
    private String severity; // e.g., LOW, MEDIUM, HIGH, CRITICAL
    private Integer score;   // 0-100 optional
    private java.util.List<String> mitre; // list of MITRE technique IDs
    private java.util.List<String> recommendations; // list of recommendation strings

    public ChatResponse() {}

    public ChatResponse(String answer, String severity, Integer score,
                        java.util.List<String> mitre,
                        java.util.List<String> recommendations) {
        this.answer = answer;
        this.severity = severity;
        this.score = score;
        this.mitre = mitre;
        this.recommendations = recommendations;
    }

    public String getAnswer() { return answer; }
    public void setAnswer(String answer) { this.answer = answer; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Integer getScore() { return score; }
    public void setScore(Integer score) { this.score = score; }

    public java.util.List<String> getMitre() { return mitre; }
    public void setMitre(java.util.List<String> mitre) { this.mitre = mitre; }

    public java.util.List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(java.util.List<String> recommendations) { this.recommendations = recommendations; }
}
