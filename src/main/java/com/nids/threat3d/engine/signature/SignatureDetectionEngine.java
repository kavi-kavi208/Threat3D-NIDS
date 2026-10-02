package com.nids.threat3d.engine.signature;

import com.nids.threat3d.feature.FeatureVector;
import com.nids.threat3d.flow.AggregatedFlow;
import com.nids.threat3d.model.SnortRule;
import com.nids.threat3d.repository.SnortRuleRepository;
import com.nids.threat3d.threat.DefenseAction;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Deterministic Java signature matching engine.
 * Evaluates active SnortRule signatures against flow features without executing attacks.
 */
@Component
public class SignatureDetectionEngine {

    private final SnortRuleRepository snortRuleRepository;

    public SignatureDetectionEngine(SnortRuleRepository snortRuleRepository) {
        this.snortRuleRepository = snortRuleRepository;
    }

    public SignatureMatchResult evaluate(AggregatedFlow flow, FeatureVector features) {
        if (flow == null || features == null) {
            return SignatureMatchResult.noMatch();
        }

        List<SnortRule> activeRules = snortRuleRepository.findByEnabledTrue();

        // Check rules and select the match with the highest severity priority
        SignatureMatchResult bestMatch = SignatureMatchResult.noMatch();
        for (SnortRule rule : activeRules) {
            SignatureMatchResult match = checkRule(rule, flow, features);
            if (match.isMatched()) {
                if (severityRank(match.getSeverity()) > severityRank(bestMatch.getSeverity())) {
                    bestMatch = match;
                }
            }
        }

        return bestMatch;
    }

    private int severityRank(String sev) {
        if (sev == null) return 0;
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH"     -> 3;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 1;
            default         -> 0;
        };
    }

    private SignatureMatchResult checkRule(SnortRule rule, AggregatedFlow flow, FeatureVector f) {
        String ruleId = rule.getId();

        // SID-1001: TCP SYN Flood DoS
        if ("SID-1001".equalsIgnoreCase(ruleId)) {
            if ((f.synFlagCount >= 25 && f.synAckRatio > 3.0) || (f.dstHostSerrorRate > 0.8 && f.srcPackets >= 20)) {
                return new SignatureMatchResult(
                        true,
                        rule.getId(),
                        rule.getName(),
                        rule.getAttackCategory(),
                        "CRITICAL",
                        0.95,
                        String.format("Matched SID-1001: SYN flood detected with %d SYN packets (ratio: %.1f) and 0/low ACKs",
                                (int) f.synFlagCount, f.synAckRatio),
                        DefenseAction.ISOLATE_SIMULATION_NODE,
                        rule.getMitreTechnique() != null ? rule.getMitreTechnique() : "T1498"
                );
            }
        }

        // SID-1002: Rapid Port Scanning Probe
        if ("SID-1002".equalsIgnoreCase(ruleId)) {
            if (f.dstHostDiffPortCount >= 8 || (f.synFlagCount >= 10 && f.dstHostDiffPortCount >= 5)) {
                String severity = f.dstHostDiffPortCount >= 10 ? "HIGH" : "MEDIUM";
                return new SignatureMatchResult(
                        true,
                        rule.getId(),
                        rule.getName(),
                        rule.getAttackCategory(),
                        severity,
                        0.90,
                        String.format("Matched SID-1002: Port scan reconnaissance probing %d distinct destination ports",
                                (int) f.dstHostDiffPortCount),
                        DefenseAction.RECOMMEND_BLOCK,
                        rule.getMitreTechnique() != null ? rule.getMitreTechnique() : "T1046"
                );
            }
        }

        // SID-1003: SQL Injection Pattern
        if ("SID-1003".equalsIgnoreCase(ruleId)) {
            if (f.payloadSuspicionScore > 0.5 && !"ICMP".equalsIgnoreCase(flow.getKey().getProtocol())) {
                return new SignatureMatchResult(
                        true,
                        rule.getId(),
                        rule.getName(),
                        rule.getAttackCategory(),
                        "HIGH",
                        0.92,
                        String.format("Matched SID-1003: Suspicious SQL injection payload token detected (suspicion score: %.2f)",
                                f.payloadSuspicionScore),
                        DefenseAction.RECOMMEND_BLOCK,
                        rule.getMitreTechnique() != null ? rule.getMitreTechnique() : "T1190"
                );
            }
        }

        // SID-1004: SSH Brute Force
        if ("SID-1004".equalsIgnoreCase(ruleId)) {
            if (flow.getKey().getDestinationPort() == 22 && (f.failedConnectionRatio > 0.5 || f.rstRate > 0.5) && f.srcPackets >= 4) {
                return new SignatureMatchResult(
                        true,
                        rule.getId(),
                        rule.getName(),
                        rule.getAttackCategory(),
                        "HIGH",
                        0.88,
                        String.format("Matched SID-1004: Repeated authentication failure pattern on port 22 (failure ratio: %.2f)",
                                f.failedConnectionRatio),
                        DefenseAction.RECOMMEND_BLOCK,
                        rule.getMitreTechnique() != null ? rule.getMitreTechnique() : "T1110"
                );
            }
        }

        // SID-1005: ICMP Ping of Death
        if ("SID-1005".equalsIgnoreCase(ruleId)) {
            if ("ICMP".equalsIgnoreCase(flow.getKey().getProtocol()) && (f.avgPacketSize > 1000 || f.packetRate > 50)) {
                return new SignatureMatchResult(
                        true,
                        rule.getId(),
                        rule.getName(),
                        rule.getAttackCategory(),
                        "HIGH",
                        0.89,
                        String.format("Matched SID-1005: High-bandwidth oversized ICMP echo flood (avg size: %.0fB, rate: %.1f pkts/sec)",
                                f.avgPacketSize, f.packetRate),
                        DefenseAction.RECOMMEND_RATE_LIMIT,
                        rule.getMitreTechnique() != null ? rule.getMitreTechnique() : "T1498.001"
                );
            }
        }

        return SignatureMatchResult.noMatch();
    }
}
