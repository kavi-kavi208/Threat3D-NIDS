package com.nids.threat3d.engine;

import com.nids.threat3d.engine.anomaly.AnomalyDetectionResult;
import com.nids.threat3d.engine.signature.SignatureMatchResult;
import com.nids.threat3d.flow.AggregatedFlow;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.DetectionEvent;
import com.nids.threat3d.threat.ThreatType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Hybrid Threat Scorer — Phase 2 core scoring component.
 *
 * <p>Combines the output of two independent detection sub-systems into a single,
 * explainable 0–100 threat score that is mapped to a categorical severity level:</p>
 *
 * <pre>
 *  Score range  │ Severity
 *  ─────────────┼──────────
 *   0  – 24     │ LOW
 *  25  – 49     │ MEDIUM
 *  50  – 74     │ HIGH
 *  75  – 100    │ CRITICAL
 * </pre>
 *
 * <h3>Scoring formula</h3>
 * <pre>
 *  sigContribution      = sigScore(severity) × sigWeight × sigConfidence
 *  anomalyContribution  = anomalyScore × anomalyWeight × anomalyConfidence
 *  behavioralBonus      = computed from flow-level indicators (payload, risk service, port)
 *  rawScore             = sigContribution + anomalyContribution + behavioralBonus   ∈ [0,1]
 *  finalScore           = round(rawScore × 100)                                    ∈ [0,100]
 * </pre>
 *
 * <h3>Weights</h3>
 * <ul>
 *   <li>Signature: 0.60 — deterministic rule matches carry higher trust</li>
 *   <li>Anomaly  : 0.35 — Java statistical deviation (NOT machine learning)</li>
 *   <li>Behavioral bonus cap: 0.05</li>
 * </ul>
 *
 * <p>All results are clearly labelled. Statistical anomaly detection is explicitly
 * identified as <em>Java Statistical Anomaly Detection</em>, never as a trained ML model.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@Component
public class HybridThreatScorer {

    private static final Logger log = LoggerFactory.getLogger(HybridThreatScorer.class);

    // ── Severity band boundaries ──────────────────────────────────────────────
    public static final int CRITICAL_THRESHOLD = 75;
    public static final int HIGH_THRESHOLD     = 50;
    public static final int MEDIUM_THRESHOLD   = 25;

    // ── Contribution weights (must sum to ≤ 1.0; remainder is behavioural bonus) ─
    private static final double SIG_WEIGHT     = 0.60;
    private static final double ANOMALY_WEIGHT = 0.35;
    private static final double BEHAVIORAL_CAP = 0.05;

    // ── Per-severity base scores fed into the signature contribution ──────────
    private static final double SIG_BASE_CRITICAL = 1.00;
    private static final double SIG_BASE_HIGH     = 0.75;
    private static final double SIG_BASE_MEDIUM   = 0.50;
    private static final double SIG_BASE_LOW      = 0.20;
    private static final double SIG_BASE_NONE     = 0.00;

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Compute a hybrid threat score and assemble a {@link DetectionEvent}.
     *
     * @param flow      the aggregated network flow being evaluated
     * @param sigResult output from {@link com.nids.threat3d.engine.signature.SignatureDetectionEngine}
     * @param anomResult output from {@link com.nids.threat3d.engine.anomaly.AnomalyDetectionEngine}
     * @return a fully populated {@link DetectionEvent} ready for persistence / streaming
     */
    public DetectionEvent score(AggregatedFlow flow,
                                SignatureMatchResult sigResult,
                                AnomalyDetectionResult anomResult) {

        // ── 1. Signature contribution ─────────────────────────────────────────
        double sigBase       = severityToBase(sigResult.getSeverity(), sigResult.isMatched());
        double sigContrib    = sigBase * SIG_WEIGHT * clamp(sigResult.getConfidence());

        // ── 2. Anomaly contribution ───────────────────────────────────────────
        // Source: Java Statistical Anomaly Detection (Welford Z-score baseline)
        double anomContrib   = clamp(anomResult.getAnomalyScore())
                             * ANOMALY_WEIGHT
                             * clamp(anomResult.getConfidence());

        // ── 3. Behavioral bonus (flow-level heuristics, capped at BEHAVIORAL_CAP) ─
        double behavioralBonus = computeBehavioralBonus(flow);

        // ── 4. Raw score → 0-100 integer ─────────────────────────────────────
        double rawScore  = sigContrib + anomContrib + behavioralBonus;
        int finalScore   = (int) Math.round(clamp(rawScore) * 100.0);

        // ── 5. Severity band ──────────────────────────────────────────────────
        String severity  = toSeverity(finalScore);
        if (sigResult.isMatched() && sigResult.getSeverity() != null) {
            String sigSev = sigResult.getSeverity().toUpperCase();
            if (severityRank(sigSev) > severityRank(severity)) {
                severity = sigSev;
                finalScore = Math.max(finalScore, severityToMinScore(sigSev));
            }
        }

        // ── 6. Determine dominant ThreatType ─────────────────────────────────
        ThreatType threatType = resolveThreatType(sigResult, anomResult, finalScore);

        // ── 7. Select the stronger defense recommendation ─────────────────────
        DefenseAction action = selectDefenseAction(sigResult.getRecommendedAction(), finalScore);

        // ── 8. MITRE technique — prefer signature match, fall back to threat type ─
        String mitre = (sigResult.isMatched() && sigResult.getMitreTechnique() != null)
                ? sigResult.getMitreTechnique()
                : threatType.getDefaultMitreId();

        // ── 9. Explainability narrative ───────────────────────────────────────
        String explanation = buildExplanation(
                flow, sigResult, anomResult,
                sigContrib, anomContrib, behavioralBonus, finalScore, severity);

        log.debug("[HybridScorer] {} → score={} severity={} type={} sig={} anom={}",
                flow.getKey(), finalScore, severity, threatType,
                sigResult.isMatched() ? sigResult.getRuleId() : "none",
                String.format("%.3f", anomResult.getAnomalyScore()));

        return new DetectionEvent(
                flow.getKey().getSourceIp(),
                flow.getKey().getDestinationIp(),
                flow.getKey().getSourcePort(),
                flow.getKey().getDestinationPort(),
                flow.getKey().getProtocol(),
                threatType,
                finalScore,
                severity,
                mitre,
                action,
                explanation
        );
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * Maps a severity string from {@link SignatureMatchResult} to a [0,1] base score.
     * When no rule matched, the base is 0.
     */
    private double severityToBase(String severity, boolean matched) {
        if (!matched || severity == null) return SIG_BASE_NONE;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SIG_BASE_CRITICAL;
            case "HIGH"     -> SIG_BASE_HIGH;
            case "MEDIUM"   -> SIG_BASE_MEDIUM;
            default         -> SIG_BASE_LOW;   // "LOW" and any unknown
        };
    }

    /**
     * Flow-level behavioral bonuses that are independent of both signature rules
     * and statistical baselines. Capped at {@value #BEHAVIORAL_CAP}.
     */
    private double computeBehavioralBonus(AggregatedFlow flow) {
        double bonus = 0.0;

        // High failed-connection ratio is a universal brute-force / scan signal
        long totalPkts = flow.getPacketCount();
        if (totalPkts > 0) {
            double failedRatio = (double) flow.getFailedConnectionCount() / totalPkts;
            if (failedRatio > 0.5) {
                bonus += 0.025;
            }
        }

        // Unusually large URG flag usage (covert-channel indicator)
        if (flow.getUrgCount() > 3) {
            bonus += 0.015;
        }

        // High RST count relative to packets (scan / reset flood)
        if (totalPkts > 0 && (double) flow.getRstCount() / totalPkts > 0.4) {
            bonus += 0.010;
        }

        return Math.min(bonus, BEHAVIORAL_CAP);
    }

    /**
     * Resolves the dominant {@link ThreatType} from combined scorer inputs.
     * Signature matches take precedence; falls back to anomaly or NORMAL.
     */
    private ThreatType resolveThreatType(SignatureMatchResult sig,
                                         AnomalyDetectionResult anom,
                                         int finalScore) {
        // Signature match → check specific SID first, then map rule category to ThreatType
        if (sig.isMatched()) {
            if ("SID-1001".equalsIgnoreCase(sig.getRuleId())) return ThreatType.SYN_FLOOD;
            if ("SID-1002".equalsIgnoreCase(sig.getRuleId())) return ThreatType.PORT_SCAN;
            if ("SID-1003".equalsIgnoreCase(sig.getRuleId())) return ThreatType.WEB_ANOMALY;
            if ("SID-1004".equalsIgnoreCase(sig.getRuleId())) return ThreatType.BRUTE_FORCE;
            if ("SID-1005".equalsIgnoreCase(sig.getRuleId())) return ThreatType.ICMP_FLOOD;

            if (sig.getCategory() != null) {
                ThreatType fromSig = categoryToThreatType(sig.getCategory());
                if (fromSig != ThreatType.NORMAL) {
                    return fromSig;
                }
            }
        }

        // Anomaly-only detection above MEDIUM threshold
        if (anom.getAnomalyScore() >= 0.40 && finalScore >= MEDIUM_THRESHOLD) {
            return ThreatType.ANOMALOUS_TRAFFIC;
        }

        // Default
        return ThreatType.NORMAL;
    }

    /**
     * Maps a Snort rule category string to the closest {@link ThreatType} enum.
     */
    private ThreatType categoryToThreatType(String category) {
        return switch (category.toUpperCase()) {
            case "DOS", "DDOS", "SYN_FLOOD", "SYN-FLOOD"   -> ThreatType.SYN_FLOOD;
            case "ICMP_FLOOD", "ICMP-FLOOD"                 -> ThreatType.ICMP_FLOOD;
            case "RECON", "PORT_SCAN", "PORT-SCAN",
                 "SCAN", "PROBE"                            -> ThreatType.PORT_SCAN;
            case "BRUTE_FORCE", "BRUTE-FORCE",
                 "AUTH", "SSH_BRUTE"                        -> ThreatType.BRUTE_FORCE;
            case "WEB", "SQLI", "SQL_INJECTION",
                 "WEB_EXPLOIT", "EXPLOIT", "APPLICATION"    -> ThreatType.WEB_ANOMALY;
            case "MULTI", "APT", "MULTI_STAGE"              ->
                    ThreatType.MULTI_STAGE_SUSPICIOUS_ACTIVITY;
            default                                          -> ThreatType.NORMAL;
        };
    }

    /**
     * Escalates the defense action from the signature engine if the hybrid
     * score warrants stronger intervention.
     */
    private DefenseAction selectDefenseAction(DefenseAction sigAction, int score) {
        // Score-driven floor — never downgrade what signature already recommended
        DefenseAction scoreAction = switch (toSeverity(score)) {
            case "CRITICAL" -> DefenseAction.RECOMMEND_BLOCK;
            case "HIGH"     -> DefenseAction.RECOMMEND_RATE_LIMIT;
            case "MEDIUM"   -> DefenseAction.ALERT;
            default         -> DefenseAction.MONITOR;
        };

        // Pick whichever action is "stronger" (higher ordinal in the enum)
        return (scoreAction.ordinal() > sigAction.ordinal()) ? scoreAction : sigAction;
    }

    /**
     * Maps an integer score in [0,100] to a severity label.
     */
    public static String toSeverity(int score) {
        if (score >= CRITICAL_THRESHOLD) return "CRITICAL";
        if (score >= HIGH_THRESHOLD)     return "HIGH";
        if (score >= MEDIUM_THRESHOLD)   return "MEDIUM";
        return "LOW";
    }

    private static int severityRank(String sev) {
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH"     -> 3;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 1;
            default         -> 0;
        };
    }

    private static int severityToMinScore(String sev) {
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> CRITICAL_THRESHOLD;
            case "HIGH"     -> HIGH_THRESHOLD;
            case "MEDIUM"   -> MEDIUM_THRESHOLD;
            default         -> 0;
        };
    }

    /** Clamps a double to [0.0, 1.0]. */
    private double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }

    /**
     * Builds a human-readable explainability string showing each contribution.
     */
    private String buildExplanation(AggregatedFlow flow,
                                    SignatureMatchResult sig,
                                    AnomalyDetectionResult anom,
                                    double sigContrib, double anomContrib,
                                    double behavioral, int finalScore,
                                    String severity) {

        List<String> parts = new ArrayList<>();

        // Signature contribution
        if (sig.isMatched()) {
            parts.add(String.format("SigRule[%s '%s' conf=%.0f%%]→+%.1f",
                    sig.getRuleId(), sig.getRuleName(),
                    sig.getConfidence() * 100, sigContrib * 100));
        } else {
            parts.add("SigRule[no-match]→+0");
        }

        // Anomaly contribution (always labelled as statistical, never ML)
        parts.add(String.format("JavaStatAnom[score=%.3f conf=%.0f%%]→+%.1f",
                anom.getAnomalyScore(), anom.getConfidence() * 100, anomContrib * 100));

        // Contributing anomalous features (up to 3)
        if (!anom.getContributingFeatures().isEmpty()) {
            List<String> features = anom.getContributingFeatures();
            String featureStr = features.size() <= 3
                    ? String.join(", ", features)
                    : String.join(", ", features.subList(0, 3))
                      + " +" + (features.size() - 3) + " more";
            parts.add("AnomalyFeatures[" + featureStr + "]");
        }

        // Behavioral bonus
        if (behavioral > 0) {
            parts.add(String.format("Behavioral→+%.1f", behavioral * 100));
        }

        // Flow identity
        parts.add(String.format("Flow[%s→%s:%d %s]",
                flow.getKey().getSourceIp(),
                flow.getKey().getDestinationIp(),
                flow.getKey().getDestinationPort(),
                flow.getKey().getProtocol()));

        return String.format("Score=%d/100 (%s) | %s | %s",
                finalScore, severity, String.join(" | ", parts),
                DefenseAction.SAFETY_DISCLAIMER);
    }
}
