package com.nids.threat3d.engine.signature;

import com.nids.threat3d.threat.DefenseAction;

/**
 * Result of signature/rule matching against a network flow.
 */
public class SignatureMatchResult {

    private final boolean matched;
    private final String ruleId;
    private final String ruleName;
    private final String category;
    private final String severity;
    private final double confidence;
    private final String explanation;
    private final DefenseAction recommendedAction;
    private final String mitreTechnique;

    public SignatureMatchResult(boolean matched, String ruleId, String ruleName,
                                String category, String severity, double confidence,
                                String explanation, DefenseAction recommendedAction,
                                String mitreTechnique) {
        this.matched = matched;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.category = category;
        this.severity = severity;
        this.confidence = confidence;
        this.explanation = explanation;
        this.recommendedAction = recommendedAction;
        this.mitreTechnique = mitreTechnique;
    }

    public static SignatureMatchResult noMatch() {
        return new SignatureMatchResult(false, null, null, null, "LOW", 0.0,
                "No signature rule matched", DefenseAction.MONITOR, "T0000");
    }

    public boolean isMatched() {
        return matched;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getCategory() {
        return category;
    }

    public String getSeverity() {
        return severity;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getExplanation() {
        return explanation;
    }

    public DefenseAction getRecommendedAction() {
        return recommendedAction;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }
}
