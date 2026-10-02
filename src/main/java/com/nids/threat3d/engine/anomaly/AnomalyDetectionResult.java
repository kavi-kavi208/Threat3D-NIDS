package com.nids.threat3d.engine.anomaly;

import java.util.Collections;
import java.util.List;

/**
 * Result of anomaly evaluation against the statistical baseline.
 */
public class AnomalyDetectionResult {

    private final double anomalyScore; // 0.0 to 1.0
    private final double confidence;   // 0.0 to 1.0
    private final List<String> contributingFeatures;
    private final String explanation;
    private final String detectorName;

    public AnomalyDetectionResult(double anomalyScore, double confidence,
                                  List<String> contributingFeatures,
                                  String explanation, String detectorName) {
        this.anomalyScore = Math.max(0.0, Math.min(1.0, anomalyScore));
        this.confidence = Math.max(0.0, Math.min(1.0, confidence));
        this.contributingFeatures = contributingFeatures != null ?
                Collections.unmodifiableList(contributingFeatures) : Collections.emptyList();
        this.explanation = explanation != null ? explanation : "Normal statistical baseline";
        this.detectorName = detectorName != null ? detectorName : "Java Statistical Anomaly Detection";
    }

    public static AnomalyDetectionResult normal() {
        return new AnomalyDetectionResult(0.05, 0.95, Collections.emptyList(),
                "Flow conforms to baseline operational parameters", "Java Statistical Anomaly Detection");
    }

    public double getAnomalyScore() {
        return anomalyScore;
    }

    public double getConfidence() {
        return confidence;
    }

    public List<String> getContributingFeatures() {
        return contributingFeatures;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getDetectorName() {
        return detectorName;
    }
}
