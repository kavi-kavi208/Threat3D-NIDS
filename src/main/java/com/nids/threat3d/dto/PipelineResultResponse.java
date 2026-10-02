package com.nids.threat3d.dto;

import com.nids.threat3d.pipeline.NidsDetectionPipeline.PipelineResult;
import com.nids.threat3d.service.DefenseRecommendationService.DefenseRecommendation;
import com.nids.threat3d.service.ThreatCorrelationService.CorrelationResult;

import java.time.Instant;
import java.util.List;

/**
 * Response DTO for a single record processed through the full NIDS pipeline.
 *
 * <p>Wraps the {@link DetectionEventResponse}, an optional
 * {@link CorrelationSummary} (when a multi-event pattern was detected), and the
 * {@link RecommendationSummary} with simulated defense guidance.</p>
 *
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
public final class PipelineResultResponse {

    private final boolean                 success;
    private final String                  errorMessage;
    private final DetectionEventResponse  detectionEvent;
    private final CorrelationSummary      correlation;    // null when no multi-event correlation
    private final RecommendationSummary   recommendation;
    private final Instant                 processedAt;
    private final String                  safetyDisclaimer = "SIMULATION ONLY — NO REAL NETWORK CHANGES";

    private PipelineResultResponse(boolean success, String errorMessage,
                                   DetectionEventResponse detectionEvent,
                                   CorrelationSummary correlation,
                                   RecommendationSummary recommendation) {
        this.success         = success;
        this.errorMessage    = errorMessage;
        this.detectionEvent  = detectionEvent;
        this.correlation     = correlation;
        this.recommendation  = recommendation;
        this.processedAt     = Instant.now();
    }

    /** Map a {@link PipelineResult} to this response DTO. */
    public static PipelineResultResponse from(PipelineResult result) {
        if (result == null) return error("Null pipeline result");
        if (result.hasError()) return error(result.getErrorMessage());

        DetectionEventResponse eventResponse =
                DetectionEventResponse.from(result.getDetectionEvent());

        CorrelationSummary corrSummary =
                result.getCorrelationResult() != null
                        ? CorrelationSummary.from(result.getCorrelationResult())
                        : null;

        RecommendationSummary recSummary =
                result.getRecommendation() != null
                        ? RecommendationSummary.from(result.getRecommendation())
                        : null;

        return new PipelineResultResponse(true, null, eventResponse, corrSummary, recSummary);
    }

    /** Error response with no detection data. */
    public static PipelineResultResponse error(String message) {
        return new PipelineResultResponse(false, message, null, null, null);
    }

    public boolean                isSuccess()         { return success; }
    public String                 getErrorMessage()   { return errorMessage; }
    public DetectionEventResponse getDetectionEvent() { return detectionEvent; }
    public CorrelationSummary     getCorrelation()    { return correlation; }
    public RecommendationSummary  getRecommendation() { return recommendation; }
    public Instant                getProcessedAt()    { return processedAt; }
    public String                 getSafetyDisclaimer(){ return safetyDisclaimer; }

    // ─────────────────────────────────────────────────────────────────────────
    // Nested DTO: multi-event correlation summary
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Condensed summary of a {@link CorrelationResult} for REST serialization.
     */
    public static final class CorrelationSummary {
        private final String       sourceIp;
        private final String       correlatedThreatType;
        private final String       severity;
        private final double       compositeScore;
        private final int          eventCount;
        private final List<String> observedThreatTypes;
        private final String       mitreId;
        private final String       mitreName;
        private final String       narrative;
        private final String       recommendedAction;

        private CorrelationSummary(CorrelationResult r) {
            this.sourceIp             = r.getSourceIp();
            this.correlatedThreatType = r.getCorrelatedThreatType().name();
            this.severity             = r.getSeverity();
            this.compositeScore       = r.getCompositeScore();
            this.eventCount           = r.getEventCount();
            this.observedThreatTypes  = r.getObservedThreatTypes()
                                         .stream().map(Enum::name).toList();
            this.mitreId              = r.getMitreMapping().getTechniqueId();
            this.mitreName            = r.getMitreMapping().getTechniqueName();
            this.narrative            = r.getNarrative();
            this.recommendedAction    = "[SIMULATED] " + r.getRecommendedAction().name();
        }

        public static CorrelationSummary from(CorrelationResult r) {
            return r == null ? null : new CorrelationSummary(r);
        }

        public String       getSourceIp()              { return sourceIp; }
        public String       getCorrelatedThreatType()  { return correlatedThreatType; }
        public String       getSeverity()              { return severity; }
        public double       getCompositeScore()        { return compositeScore; }
        public int          getEventCount()            { return eventCount; }
        public List<String> getObservedThreatTypes()   { return observedThreatTypes; }
        public String       getMitreId()               { return mitreId; }
        public String       getMitreName()             { return mitreName; }
        public String       getNarrative()             { return narrative; }
        public String       getRecommendedAction()     { return recommendedAction; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Nested DTO: defense recommendation summary
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Condensed summary of a {@link DefenseRecommendation} for REST serialization.
     *
     * <p>All actions are {@code [SIMULATED]}. Disclaimer is always present.</p>
     */
    public static final class RecommendationSummary {
        private final String       source;             // SINGLE_EVENT | CORRELATED_MULTI_EVENT
        private final String       action;             // e.g. RECOMMEND_BLOCK
        private final String       actionLabel;        // "[SIMULATED] ..."
        private final String       threatType;
        private final String       severity;
        private final int          score;
        private final String       mitreId;
        private final String       mitreName;
        private final String       rationale;
        private final List<String> remediationSteps;
        private final List<String> indicatorsOfCompromise;
        private final boolean      requiresNodeIsolation;
        private final String       safetyDisclaimer;

        private RecommendationSummary(DefenseRecommendation r) {
            this.source                 = r.getSource().name();
            this.action                 = r.getAction().name();
            this.actionLabel            = r.getActionLabel();
            this.threatType             = r.getThreatType().name();
            this.severity               = r.getSeverity();
            this.score                  = r.getScore();
            this.mitreId                = r.getMitreMapping().getTechniqueId();
            this.mitreName              = r.getMitreMapping().getTechniqueName();
            this.rationale              = r.getRationale();
            this.remediationSteps       = r.getRemediationSteps();
            this.indicatorsOfCompromise = r.getIndicatorsOfCompromise();
            this.requiresNodeIsolation  = r.requiresNodeIsolation();
            this.safetyDisclaimer       = com.nids.threat3d.threat.DefenseAction.SAFETY_DISCLAIMER;
        }

        public static RecommendationSummary from(DefenseRecommendation r) {
            return r == null ? null : new RecommendationSummary(r);
        }

        public String       getSource()                 { return source; }
        public String       getAction()                 { return action; }
        public String       getActionLabel()            { return actionLabel; }
        public String       getThreatType()             { return threatType; }
        public String       getSeverity()               { return severity; }
        public int          getScore()                  { return score; }
        public String       getMitreId()                { return mitreId; }
        public String       getMitreName()              { return mitreName; }
        public String       getRationale()              { return rationale; }
        public List<String> getRemediationSteps()       { return remediationSteps; }
        public List<String> getIndicatorsOfCompromise() { return indicatorsOfCompromise; }
        public boolean      isRequiresNodeIsolation()   { return requiresNodeIsolation; }
        public String       getSafetyDisclaimer()       { return safetyDisclaimer; }
    }
}
