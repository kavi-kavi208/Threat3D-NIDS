package com.nids.threat3d.engine.anomaly;

import com.nids.threat3d.feature.FeatureVector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Java Statistical Anomaly Detection Engine.
 *
 * <p>This is NOT a trained machine-learning model.
 * It uses pure-Java incremental Welford statistics (online mean + variance)
 * to build a per-feature baseline from observed traffic. Any feature whose
 * current value deviates by more than a configurable Z-score threshold
 * from its running mean is flagged as anomalous.</p>
 *
 * <p>Algorithm summary:
 * <ol>
 *   <li>Maintain online (Welford) mean and M2 (sum-of-squared-deviations) for
 *       each of the 41 FeatureVector dimensions.</li>
 *   <li>On each new vector, compute Z-score per feature: |x - mean| / stddev.</li>
 *   <li>Count how many features exceed the Z-score threshold (default 3.0).</li>
 *   <li>Derive an anomaly score in [0,1] proportional to the fraction of
 *       anomalous features, boosted by the maximum individual Z-score.</li>
 *   <li>Apply hard-coded payload suspicion and high-risk service bonuses to
 *       capture threat signals that purely statistical methods may miss during
 *       the warm-up period.</li>
 * </ol>
 * </p>
 *
 * <p>Warm-up: the first {@code WARMUP_SAMPLES} observations are used only to
 * seed the baseline; results during that period carry reduced confidence.</p>
 */
@Component
public class AnomalyDetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetectionEngine.class);

    /** Number of samples required before the baseline is considered reliable. */
    private static final int WARMUP_SAMPLES = 50;

    /** Z-score threshold above which a feature dimension is considered anomalous. */
    private static final double Z_THRESHOLD = 3.0;

    /** Number of feature dimensions (must match FeatureVector). */
    private static final int FEATURE_COUNT = 41;

    /** Detector identity label — always use this exact string (no ML claims). */
    private static final String DETECTOR_NAME = "Java Statistical Anomaly Detection";

    // ─── Feature labels for human-readable output ────────────────────────────

    private static final String[] FEATURE_NAMES = {
            "duration", "protocolType", "serviceType", "srcBytes", "dstBytes",
            "srcPackets", "dstPackets", "packetRate", "byteRate", "avgPacketSize",
            "packetSizeStdDev", "synFlagCount", "ackFlagCount", "finFlagCount",
            "rstFlagCount", "pshFlagCount", "urgFlagCount", "synAckRatio", "rstRate",
            "failedConnectionRatio", "connectionStatusCode", "payloadRatio",
            "dstHostCount", "dstHostSrvCount", "dstHostSameSrvRate", "dstHostDiffSrvRate",
            "dstHostDiffPortCount", "dstHostSerrorRate", "dstHostRerrorRate",
            "srcHostCount", "srcHostDiffDstCount", "inboundOutboundRatio",
            "isPrivilegedPort", "isEphemeralPort", "interArrivalTimeMean",
            "interArrivalTimeStdDev", "burstinessIndicator", "portEntropy",
            "directionCode", "isHighRiskService", "payloadSuspicionScore"
    };

    // ─── Welford online statistics (thread-safe per-feature accumulators) ─────

    /** Running count of samples ingested into the baseline. */
    private final AtomicLong sampleCount = new AtomicLong(0);

    /**
     * Per-feature Welford accumulators stored in a concurrent map.
     * Key = feature index [0..40]. Value = double[2] { mean, M2 }.
     */
    private final Map<Integer, double[]> welfordState = new ConcurrentHashMap<>();

    // ─── Constructor ──────────────────────────────────────────────────────────

    public AnomalyDetectionEngine() {
        // Initialise all 41 accumulators: [mean=0.0, M2=0.0]
        for (int i = 0; i < FEATURE_COUNT; i++) {
            welfordState.put(i, new double[]{0.0, 0.0});
        }
        log.info("[{}] Initialised with {} feature dimensions, Z-threshold={}, warm-up={}",
                DETECTOR_NAME, FEATURE_COUNT, Z_THRESHOLD, WARMUP_SAMPLES);
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Analyse a feature vector and return an anomaly score.
     * The vector is also fed into the Welford accumulators to continuously
     * refine the baseline.
     *
     * @param fv the feature vector produced by FeatureExtractor
     * @return AnomalyDetectionResult with score in [0,1] and contributing features
     */
    public AnomalyDetectionResult analyse(FeatureVector fv) {
        double[] values = fv.toArray();
        long n = sampleCount.incrementAndGet();

        // Step 1 — Update Welford baseline with this observation
        updateBaseline(values, n);

        // Step 2 — If still in warm-up, return low-confidence result
        if (n <= WARMUP_SAMPLES) {
            return buildWarmupResult(n);
        }

        // Step 3 — Compute per-feature Z-scores against established baseline
        List<String> anomalousFeatures = new ArrayList<>();
        double maxZ = 0.0;
        double sumExcessZ = 0.0;

        for (int i = 0; i < FEATURE_COUNT; i++) {
            double[] state = welfordState.get(i);
            double mean = state[0];
            double variance = (n > 1) ? state[1] / (n - 1) : 0.0;
            double stdDev = Math.sqrt(variance);

            if (stdDev < 1e-9) {
                // Feature has near-zero variance — flag only if value is non-zero
                if (Math.abs(values[i] - mean) > 1e-6) {
                    anomalousFeatures.add(FEATURE_NAMES[i] + "(static-deviation)");
                }
                continue;
            }

            double z = Math.abs(values[i] - mean) / stdDev;

            if (z > maxZ) {
                maxZ = z;
            }

            if (z >= Z_THRESHOLD) {
                anomalousFeatures.add(String.format("%s(z=%.2f)", FEATURE_NAMES[i], z));
                sumExcessZ += (z - Z_THRESHOLD);
            }
        }

        // Step 4 — Derive anomaly score
        double score = computeScore(anomalousFeatures.size(), maxZ, sumExcessZ, fv);

        // Step 5 — Compute confidence: scales up from 0.5 as sample count grows
        double confidence = computeConfidence(n);

        // Step 6 — Build explanation
        String explanation = buildExplanation(anomalousFeatures, score, maxZ, n);

        if (score > 0.3) {
            log.debug("[{}] Anomaly detected — score={:.3f}, features={}, maxZ={:.2f}, n={}",
                    DETECTOR_NAME, score, anomalousFeatures.size(), maxZ, n);
        }

        return new AnomalyDetectionResult(score, confidence, anomalousFeatures, explanation, DETECTOR_NAME);
    }

    /**
     * Reset the statistical baseline. Useful between simulation scenarios
     * to avoid cross-contamination of the learned distribution.
     */
    public void resetBaseline() {
        sampleCount.set(0);
        for (int i = 0; i < FEATURE_COUNT; i++) {
            welfordState.put(i, new double[]{0.0, 0.0});
        }
        log.info("[{}] Baseline reset.", DETECTOR_NAME);
    }

    /**
     * Returns the number of samples ingested into the baseline so far.
     */
    public long getSampleCount() {
        return sampleCount.get();
    }

    /**
     * Returns true if the engine has passed the warm-up period and baseline
     * statistics are considered reliable.
     */
    public boolean isBaselineReady() {
        return sampleCount.get() > WARMUP_SAMPLES;
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * Welford's online algorithm for computing running mean and M2.
     * Thread safety: updates are serialised on a per-feature lock via
     * synchronised access to the individual double[] arrays.
     *
     * <pre>
     *   mean_n = mean_{n-1} + (x - mean_{n-1}) / n
     *   M2_n   = M2_{n-1}   + (x - mean_{n-1}) * (x - mean_n)
     *   var_n  = M2_n / (n - 1)   [sample variance]
     * </pre>
     */
    private void updateBaseline(double[] values, long n) {
        for (int i = 0; i < FEATURE_COUNT; i++) {
            double[] state = welfordState.get(i);
            synchronized (state) {
                double delta = values[i] - state[0];
                state[0] += delta / n;                          // new mean
                double delta2 = values[i] - state[0];
                state[1] += delta * delta2;                     // new M2
            }
        }
    }

    /**
     * Derives a [0,1] anomaly score from:
     * <ul>
     *   <li>Fraction of features that exceeded Z_THRESHOLD</li>
     *   <li>Maximum observed Z-score (capped at 10.0 for scaling)</li>
     *   <li>Payload suspicion score (hard heuristic bonus)</li>
     *   <li>High-risk service + privilege port bonus</li>
     * </ul>
     */
    private double computeScore(int anomalousCount, double maxZ,
                                double sumExcessZ, FeatureVector fv) {

        // Base: fraction of anomalous features
        double featureFraction = (double) anomalousCount / FEATURE_COUNT;

        // Z-score component: max Z normalised to [0,1] with cap at 10.0
        double zComponent = Math.min(maxZ / 10.0, 1.0);

        // Weighted blend — feature fraction dominates
        double baseScore = (featureFraction * 0.55) + (zComponent * 0.35);

        // Hard heuristic bonuses (independent of statistical baseline)
        double heuristicBonus = 0.0;

        // Payload suspicion is already in [0,1]
        if (fv.payloadSuspicionScore > 0.3) {
            heuristicBonus += fv.payloadSuspicionScore * 0.15;
        }

        // High-risk service targeting (SSH, SQL, RDP)
        if (fv.isHighRiskService > 0.5) {
            heuristicBonus += 0.05;
        }

        // Privileged port targeting combined with external direction
        if (fv.isPrivilegedPort > 0.5 && fv.directionCode > 0.5) {
            heuristicBonus += 0.05;
        }

        double finalScore = Math.min(baseScore + heuristicBonus, 1.0);

        // Ensure truly benign flows (no statistical anomalies, no heuristic flags)
        // are not scored above the baseline noise floor
        if (anomalousCount == 0 && heuristicBonus < 0.05) {
            finalScore = Math.min(finalScore, 0.10);
        }

        return finalScore;
    }

    /**
     * Confidence grows from 0.5 at warm-up boundary to 0.97 asymptotically
     * as more samples are observed.
     *
     * <pre>confidence = 0.5 + 0.47 * (1 - e^{-k * (n - WARMUP)})</pre>
     */
    private double computeConfidence(long n) {
        double k = 0.02; // growth rate constant
        double extra = n - WARMUP_SAMPLES;
        return 0.50 + 0.47 * (1.0 - Math.exp(-k * extra));
    }

    /** Returns a warm-up phase result with reduced confidence. */
    private AnomalyDetectionResult buildWarmupResult(long n) {
        double warmupConfidence = 0.30 + (0.20 * n / WARMUP_SAMPLES);
        return new AnomalyDetectionResult(
                0.05, warmupConfidence, List.of(),
                String.format("Baseline warm-up in progress (%d/%d samples)", n, WARMUP_SAMPLES),
                DETECTOR_NAME
        );
    }

    /** Constructs a human-readable explanation string. */
    private String buildExplanation(List<String> anomalousFeatures,
                                    double score, double maxZ, long n) {
        if (anomalousFeatures.isEmpty()) {
            return String.format(
                    "Flow conforms to statistical baseline (n=%d, maxZ=%.2f)", n, maxZ);
        }
        String topFeatures = anomalousFeatures.size() <= 3
                ? String.join(", ", anomalousFeatures)
                : String.join(", ", anomalousFeatures.subList(0, 3)) +
                  String.format(" … +%d more", anomalousFeatures.size() - 3);

        return String.format(
                "Statistical deviation detected: score=%.3f, %d feature(s) exceed Z>%.1f — [%s]",
                score, anomalousFeatures.size(), Z_THRESHOLD, topFeatures);
    }
}
