package com.nids.threat3d.service;

import com.nids.threat3d.engine.HybridThreatScorer;
import com.nids.threat3d.service.ThreatCorrelationService.CorrelationResult;
import com.nids.threat3d.threat.DefenseAction;
import com.nids.threat3d.threat.DetectionEvent;
import com.nids.threat3d.threat.MitreMapping;
import com.nids.threat3d.threat.ThreatType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

/**
 * Defense Recommendation Service — Phase 2.
 *
 * <p>Translates {@link DetectionEvent} and {@link CorrelationResult} objects into
 * structured, human-readable {@link DefenseRecommendation} objects that describe
 * <em>simulated</em> countermeasures for analyst review.</p>
 *
 * <h3>Safety contract — strictly enforced</h3>
 * <ul>
 *   <li>This service <strong>NEVER</strong> modifies firewall rules.</li>
 *   <li>This service <strong>NEVER</strong> sends network packets.</li>
 *   <li>This service <strong>NEVER</strong> changes host or router configuration.</li>
 *   <li>Every recommendation carries the mandatory disclaimer:
 *       {@value DefenseAction#SAFETY_DISCLAIMER}.</li>
 *   <li>All action labels are prefixed with {@code "[SIMULATED]"} in the
 *       {@link DefenseRecommendation#getActionLabel()} field.</li>
 * </ul>
 *
 * <h3>Recommendation escalation table</h3>
 * <pre>
 *  Score / Severity      │ Base action
 *  ──────────────────────┼───────────────────────────────
 *   0–24   LOW           │ MONITOR
 *  25–49   MEDIUM        │ ALERT
 *  50–74   HIGH          │ RECOMMEND_RATE_LIMIT
 *  75–100  CRITICAL      │ RECOMMEND_BLOCK
 *  Correlated multi-stage│ ISOLATE_SIMULATION_NODE
 * </pre>
 *
 * <p>{@value DefenseAction#SAFETY_DISCLAIMER}</p>
 */
@Service
public class DefenseRecommendationService {

    private static final Logger log = LoggerFactory.getLogger(DefenseRecommendationService.class);

    // ── Analyst-readable step templates keyed by DefenseAction ────────────────
    private static final Map<DefenseAction, List<String>> ACTION_STEPS;

    static {
        Map<DefenseAction, List<String>> m = new EnumMap<>(DefenseAction.class);

        m.put(DefenseAction.MONITOR, List.of(
                "[SIMULATED] Continue passive traffic observation on the affected flow.",
                "[SIMULATED] Log full flow metadata to the NIDS audit trail.",
                "[SIMULATED] Set a 5-minute alert escalation timer if behaviour persists."
        ));

        m.put(DefenseAction.ALERT, List.of(
                "[SIMULATED] Raise a Level-1 analyst alert in the SIEM dashboard.",
                "[SIMULATED] Capture and tag the source IP for enhanced monitoring.",
                "[SIMULATED] Attach detection evidence (score, features, MITRE ID) to ticket.",
                "[SIMULATED] Notify on-call analyst via simulated notification channel."
        ));

        m.put(DefenseAction.RECOMMEND_RATE_LIMIT, List.of(
                "[SIMULATED] Apply rate-limiting policy to source IP at perimeter router.",
                "[SIMULATED] Set connection-rate cap to 20 new sessions / second from this source.",
                "[SIMULATED] Log all dropped packets to the simulated flow audit log.",
                "[SIMULATED] Schedule automatic policy review in 30 minutes.",
                "[SIMULATED] Raise a Level-2 analyst alert with rate-limit evidence."
        ));

        m.put(DefenseAction.RECOMMEND_BLOCK, List.of(
                "[SIMULATED] Add source IP to perimeter firewall deny list.",
                "[SIMULATED] Terminate all active sessions from this source.",
                "[SIMULATED] Notify network operations via simulated incident ticket.",
                "[SIMULATED] Cross-check source IP against threat-intelligence feed (simulated).",
                "[SIMULATED] Retain all evidence for 72-hour analyst review window."
        ));

        m.put(DefenseAction.ISOLATE_SIMULATION_NODE, List.of(
                "[SIMULATED] Remove compromised node from simulated network topology.",
                "[SIMULATED] Null-route all inbound/outbound traffic to/from node IP.",
                "[SIMULATED] Trigger simulated forensic snapshot of node state.",
                "[SIMULATED] Notify incident response team via simulated P1 alert.",
                "[SIMULATED] Quarantine node in dedicated isolated VLAN (simulation).",
                "[SIMULATED] Begin simulated IOC sweep on adjacent topology nodes."
        ));

        ACTION_STEPS = Collections.unmodifiableMap(m);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate a {@link DefenseRecommendation} from a single {@link DetectionEvent}.
     *
     * @param event the scored detection event from {@link com.nids.threat3d.engine.HybridThreatScorer}
     * @return a structured, simulation-only recommendation
     */
    public DefenseRecommendation recommend(DetectionEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("DetectionEvent must not be null");
        }

        DefenseAction action = escalateAction(event.getRecommendedAction(),
                (int) event.getThreatScore(), event.getThreatType(), false);

        MitreMapping mitre = MitreMapping.forThreatType(event.getThreatType(),
                "Single-event recommendation for " + event.getThreatType().name());

        String rationale = buildSingleEventRationale(event, action);
        List<String> steps = ACTION_STEPS.getOrDefault(action, List.of());
        List<String> iocs = buildIocs(event.getSourceIp(), event.getDestinationIp(),
                event.getDestinationPort(), event.getProtocol());

        log.debug("[DefenseRec] single-event src={} score={} → action={}",
                event.getSourceIp(), (int) event.getThreatScore(), action);

        return new DefenseRecommendation(
                RecommendationSource.SINGLE_EVENT,
                event.getSourceIp(),
                event.getDestinationIp(),
                event.getDestinationPort(),
                action,
                "[SIMULATED] " + action.getDescription(),
                event.getThreatType(),
                event.getSeverity(),
                (int) event.getThreatScore(),
                mitre,
                rationale,
                steps,
                iocs,
                Instant.now()
        );
    }

    /**
     * Generate a {@link DefenseRecommendation} from a {@link CorrelationResult},
     * representing a correlated multi-event finding from {@link ThreatCorrelationService}.
     *
     * @param correlation the correlated multi-event result
     * @return a structured, simulation-only recommendation (may be escalated to ISOLATE)
     */
    public DefenseRecommendation recommendFromCorrelation(CorrelationResult correlation) {
        if (correlation == null) {
            throw new IllegalArgumentException("CorrelationResult must not be null");
        }

        boolean isMultiStage = correlation.getCorrelatedThreatType()
                == ThreatType.MULTI_STAGE_SUSPICIOUS_ACTIVITY;

        DefenseAction action = escalateAction(
                correlation.getRecommendedAction(),
                (int) correlation.getCompositeScore(),
                correlation.getCorrelatedThreatType(),
                isMultiStage);

        String rationale = buildCorrelationRationale(correlation, action, isMultiStage);
        List<String> steps = ACTION_STEPS.getOrDefault(action, List.of());
        List<String> iocs  = buildCorrelationIocs(correlation);

        log.debug("[DefenseRec] correlation src={} score={} types={} → action={}",
                correlation.getSourceIp(),
                (int) correlation.getCompositeScore(),
                correlation.getObservedThreatTypes().size(),
                action);

        return new DefenseRecommendation(
                RecommendationSource.CORRELATED_MULTI_EVENT,
                correlation.getSourceIp(),
                null,   // destination not applicable for correlated group
                -1,
                action,
                "[SIMULATED] " + action.getDescription(),
                correlation.getCorrelatedThreatType(),
                correlation.getSeverity(),
                (int) correlation.getCompositeScore(),
                correlation.getMitreMapping(),
                rationale,
                steps,
                iocs,
                Instant.now()
        );
    }

    /**
     * Batch-process a list of detection events and return one recommendation per event.
     *
     * @param events list of scored detection events
     * @return list of recommendations in the same order (never null elements)
     */
    public List<DefenseRecommendation> recommendAll(List<DetectionEvent> events) {
        if (events == null || events.isEmpty()) return Collections.emptyList();
        List<DefenseRecommendation> results = new ArrayList<>(events.size());
        for (DetectionEvent e : events) {
            results.add(recommend(e));
        }
        return results;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Escalation logic
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Determines the final {@link DefenseAction} by taking the stronger of:
     * <ol>
     *   <li>The score-derived floor action from the severity band</li>
     *   <li>The recommended action already present on the event/correlation</li>
     *   <li>Hard escalation to {@link DefenseAction#ISOLATE_SIMULATION_NODE} for
     *       confirmed multi-stage activity with CRITICAL score</li>
     * </ol>
     */
    private DefenseAction escalateAction(DefenseAction baseAction, int score,
                                         ThreatType type, boolean isCorrelated) {

        // Score-driven floor
        DefenseAction scoreFloor = switch (HybridThreatScorer.toSeverity(score)) {
            case "CRITICAL" -> DefenseAction.RECOMMEND_BLOCK;
            case "HIGH"     -> DefenseAction.RECOMMEND_RATE_LIMIT;
            case "MEDIUM"   -> DefenseAction.ALERT;
            default          -> DefenseAction.MONITOR;
        };

        // Take whichever is stronger (higher ordinal)
        DefenseAction chosen = (scoreFloor.ordinal() > baseAction.ordinal())
                ? scoreFloor : baseAction;

        // Hard escalation: correlated multi-stage CRITICAL → isolate
        if (isCorrelated
                && type == ThreatType.MULTI_STAGE_SUSPICIOUS_ACTIVITY
                && score >= HybridThreatScorer.CRITICAL_THRESHOLD) {
            chosen = DefenseAction.ISOLATE_SIMULATION_NODE;
        }

        // SYN Flood + CRITICAL always triggers isolation (volumetric DoS)
        if (type == ThreatType.SYN_FLOOD && score >= HybridThreatScorer.CRITICAL_THRESHOLD) {
            chosen = DefenseAction.ISOLATE_SIMULATION_NODE;
        }

        return chosen;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rationale builders
    // ─────────────────────────────────────────────────────────────────────────

    private String buildSingleEventRationale(DetectionEvent event, DefenseAction chosen) {
        return String.format(
                "Single-event recommendation | src=%s | dst=%s:%d | protocol=%s | " +
                "threatType=%s | score=%d/100 | severity=%s | chosenAction=%s | " +
                "explanation=[%s] | MITRE=%s | %s",
                event.getSourceIp(),
                event.getDestinationIp(),
                event.getDestinationPort(),
                event.getProtocol(),
                event.getThreatType().name(),
                (int) event.getThreatScore(),
                event.getSeverity(),
                chosen.name(),
                truncate(event.getExplanation(), 200),
                event.getMitreTechnique(),
                DefenseAction.SAFETY_DISCLAIMER
        );
    }

    private String buildCorrelationRationale(CorrelationResult corr,
                                              DefenseAction chosen,
                                              boolean isMultiStage) {
        String typeList = corr.getObservedThreatTypes().stream()
                .map(Enum::name)
                .reduce((a, b) -> a + ", " + b)
                .orElse("none");

        return String.format(
                "Correlated multi-event recommendation | src=%s | events=%d | " +
                "observedTypes=[%s] | compositeScore=%.1f/100 | severity=%s | " +
                "isMultiStage=%s | chosenAction=%s | window=[%s → %s] | " +
                "MITRE=%s '%s' | %s",
                corr.getSourceIp(),
                corr.getEventCount(),
                typeList,
                corr.getCompositeScore(),
                corr.getSeverity(),
                isMultiStage ? "YES (kill-chain pattern detected)" : "NO",
                chosen.name(),
                corr.getWindowStart(),
                corr.getWindowEnd(),
                corr.getMitreMapping().getTechniqueId(),
                corr.getMitreMapping().getTechniqueName(),
                DefenseAction.SAFETY_DISCLAIMER
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IOC builders
    // ─────────────────────────────────────────────────────────────────────────

    /** Indicators of compromise for a single event (informational only). */
    private List<String> buildIocs(String srcIp, String dstIp,
                                   int dstPort, String protocol) {
        List<String> iocs = new ArrayList<>();
        if (srcIp != null)   iocs.add("src-ip:" + srcIp);
        if (dstIp != null)   iocs.add("dst-ip:" + dstIp);
        if (dstPort > 0)     iocs.add("dst-port:" + dstPort);
        if (protocol != null) iocs.add("protocol:" + protocol);
        return Collections.unmodifiableList(iocs);
    }

    /** Indicators of compromise for a correlated result (source IP + all observed types). */
    private List<String> buildCorrelationIocs(CorrelationResult corr) {
        List<String> iocs = new ArrayList<>();
        iocs.add("src-ip:" + corr.getSourceIp());
        iocs.add("event-count:" + corr.getEventCount());
        for (ThreatType t : corr.getObservedThreatTypes()) {
            iocs.add("threat-type:" + t.name());
        }
        iocs.add("mitre:" + corr.getMitreMapping().getTechniqueId());
        return Collections.unmodifiableList(iocs);
    }

    /** Truncates long strings for narrative embedding. */
    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "…";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner types
    // ─────────────────────────────────────────────────────────────────────────

    /** Indicates whether this recommendation was derived from a single event or correlation. */
    public enum RecommendationSource {
        SINGLE_EVENT,
        CORRELATED_MULTI_EVENT
    }

    /**
     * Immutable, simulation-only defense recommendation.
     *
     * <p>All action labels are prefixed with {@code "[SIMULATED]"} and every
     * instance carries the {@link DefenseAction#SAFETY_DISCLAIMER} in its
     * {@link #getRationale()} field.<br>
     * <strong>{@value DefenseAction#SAFETY_DISCLAIMER}</strong></p>
     */
    public static final class DefenseRecommendation {

        private final RecommendationSource source;
        private final String sourceIp;
        private final String destinationIp;   // null for correlation results
        private final int    destinationPort; // -1 for correlation results
        private final DefenseAction action;
        private final String actionLabel;     // "[SIMULATED] <description>"
        private final ThreatType threatType;
        private final String severity;
        private final int    score;
        private final MitreMapping mitreMapping;
        private final String rationale;
        private final List<String> remediationSteps;
        private final List<String> indicatorsOfCompromise;
        private final Instant generatedAt;

        public DefenseRecommendation(RecommendationSource source,
                                     String sourceIp, String destinationIp, int destinationPort,
                                     DefenseAction action, String actionLabel,
                                     ThreatType threatType, String severity, int score,
                                     MitreMapping mitreMapping, String rationale,
                                     List<String> remediationSteps,
                                     List<String> indicatorsOfCompromise,
                                     Instant generatedAt) {
            this.source                 = source;
            this.sourceIp               = sourceIp;
            this.destinationIp          = destinationIp;
            this.destinationPort        = destinationPort;
            this.action                 = action;
            this.actionLabel            = actionLabel;
            this.threatType             = threatType;
            this.severity               = severity;
            this.score                  = score;
            this.mitreMapping           = mitreMapping;
            this.rationale              = rationale;
            this.remediationSteps       = Collections.unmodifiableList(remediationSteps);
            this.indicatorsOfCompromise = Collections.unmodifiableList(indicatorsOfCompromise);
            this.generatedAt            = generatedAt;
        }

        public RecommendationSource getSource()                     { return source; }
        public String getSourceIp()                                 { return sourceIp; }
        public String getDestinationIp()                            { return destinationIp; }
        public int    getDestinationPort()                          { return destinationPort; }
        public DefenseAction getAction()                            { return action; }
        public String getActionLabel()                              { return actionLabel; }
        public ThreatType getThreatType()                           { return threatType; }
        public String getSeverity()                                 { return severity; }
        public int    getScore()                                    { return score; }
        public MitreMapping getMitreMapping()                       { return mitreMapping; }
        public String getRationale()                                { return rationale; }
        public List<String> getRemediationSteps()                   { return remediationSteps; }
        public List<String> getIndicatorsOfCompromise()             { return indicatorsOfCompromise; }
        public Instant getGeneratedAt()                             { return generatedAt; }

        /** Convenience: true when the action is more than passive monitoring. */
        public boolean isActionable() {
            return action != DefenseAction.MONITOR;
        }

        /** Convenience: true when isolation of a simulated node is recommended. */
        public boolean requiresNodeIsolation() {
            return action == DefenseAction.ISOLATE_SIMULATION_NODE;
        }
    }
}
