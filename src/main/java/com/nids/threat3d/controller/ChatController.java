package com.nids.threat3d.controller;

import com.nids.threat3d.dto.ChatRequest;
import com.nids.threat3d.dto.ChatResponse;
import com.nids.threat3d.model.ThreatAlert;
import com.nids.threat3d.repository.ThreatAlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI &amp; Offline Cybersecurity Expert Chat Controller.
 * Provides context-aware threat explanation and safe defensive guidance.
 *
 * <p>Acts as BOTH a cybersecurity tutor and a Threat3D application guide.</p>
 * <p><strong>SIMULATION ONLY — NO REAL NETWORK CHANGES.</strong></p>
 */
@RestController
@RequestMapping
public class ChatController {

    private static final Logger log = LoggerFactory.getLogger(ChatController.class);
    private final ThreatAlertRepository alertRepository;

    /** Pattern to extract alert/threat IDs from natural language, e.g. "Alert #859", "threat #123", "explain #42"
     *  Requires explicit '#' prefix to avoid false matches on words like "Threat3D", "SID1001" etc.
     *  Also matches "alert id 859", "threat id 859" with the word 'id' as separator.
     */
    private static final Pattern ALERT_ID_PATTERN =
            Pattern.compile(
                    "(?:" +
                    "(?:alert|threat)\\s+#(\\d{1,10})" +   // "alert #859" or "threat #859"
                    "|(?:alert|threat)\\s+id\\s+(\\d{1,10})" + // "alert id 859"
                    "|#(\\d{1,10})(?:\\b|\\s|$)" +           // standalone "#859"
                    ")",
                    Pattern.CASE_INSENSITIVE
            );

    public ChatController(ThreatAlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @PostMapping({"/api/v2/chat/explain", "/api/offline-expert"})
    public ResponseEntity<ChatResponse> handleChatOrExplain(@RequestBody(required = false) ChatRequest request) {
        if (request == null) {
            request = new ChatRequest("", null);
        }

        String rawQuery = request.getQuery() != null ? request.getQuery().trim() : "";
        if (rawQuery.length() > 1000) {
            rawQuery = rawQuery.substring(0, 1000);
        }

        String threatIdStr = request.getThreatId() != null ? request.getThreatId().trim() : null;
        boolean isTamil = containsTamil(rawQuery);

        // Scenario 1: Explicit threatId provided via field
        if (threatIdStr != null && !threatIdStr.isEmpty()) {
            try {
                Long id = Long.parseLong(threatIdStr);
                Optional<ThreatAlert> alertOpt = alertRepository.findById(id);
                if (alertOpt.isPresent()) {
                    return ResponseEntity.ok(buildThreatExplanation(alertOpt.get(), isTamil, rawQuery));
                }
            } catch (NumberFormatException ignored) {
                // Fall through
            }
        }

        // Scenario 2: Alert ID embedded in the query text, e.g. "Explain Alert #859"
        Matcher matcher = ALERT_ID_PATTERN.matcher(rawQuery);
        if (matcher.find()) {
            // Find the first non-null group (groups 1, 2, or 3 depending on which alternative matched)
            String idStr = null;
            for (int g = 1; g <= matcher.groupCount(); g++) {
                if (matcher.group(g) != null) {
                    idStr = matcher.group(g);
                    break;
                }
            }
            if (idStr != null) {
            try {
                Long id = Long.parseLong(idStr);
                Optional<ThreatAlert> alertOpt = alertRepository.findById(id);
                if (alertOpt.isPresent()) {
                    return ResponseEntity.ok(buildThreatExplanation(alertOpt.get(), isTamil, rawQuery));
                } else {
                    // Alert ID was parsed but not found in DB
                    String notFound = isTamil
                            ? String.format("அச்சுறுத்தல் #%d தரவுத்தளத்தில் கிடைக்கவில்லை. உருவகப்படுத்துதல் இயக்கி அச்சுறுத்தல்களை உருவாக்கிய பிறகு மீண்டும் முயற்சிக்கவும்.", id)
                            : String.format("Alert #%d was not found in the database. Run a simulation first to generate threat alerts, then query again.", id);
                    return ResponseEntity.ok(new ChatResponse(notFound, "LOW", 10,
                            List.of(), List.of("Run a simulation in Simulation Hub to generate alerts")));
                }
            } catch (NumberFormatException ignored) {
                // Fall through
            }
            } // end if (idStr != null)
        } // end if (matcher.find())

        // Scenario 3: General cybersecurity / application guidance query
        return ResponseEntity.ok(buildExpertAnswer(rawQuery, isTamil));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // THREAT EXPLANATION  (uses real persisted backend data)
    // ─────────────────────────────────────────────────────────────────────────

    private ChatResponse buildThreatExplanation(ThreatAlert alert, boolean isTamil, String rawQuery) {
        String attackType = alert.getAttackType() != null ? alert.getAttackType() : "Unknown Anomaly";
        String severity   = alert.getSeverity() != null ? alert.getSeverity().toUpperCase() : "MEDIUM";
        int score = alert.getConfidenceScore() > 0
                ? Math.round(alert.getConfidenceScore() * 100.0f)
                : 50;

        List<String> mitre = new ArrayList<>();
        if (alert.getMitreTechnique() != null && !alert.getMitreTechnique().isBlank()) {
            mitre.add(alert.getMitreTechnique());
        }

        List<String> recommendations = new ArrayList<>();
        String answer;
        String q = rawQuery.toLowerCase();

        boolean askingWhy = q.contains("why") || q.contains("reason") || q.contains("cause")
                || q.contains("enna") || q.contains("ஏன்") || q.contains("எதனால்");

        if (isTamil) {
            if (askingWhy) {
                answer = String.format(
                        "அச்சுறுத்தல் #%d %s என்று வகைப்படுத்தப்பட்டுள்ளது, ஏனெனில்:\n" +
                        "• தாக்குதல் வகை: %s\n" +
                        "• மூல IP: %s → இலக்கு IP: %s\n" +
                        "• நம்பிக்கை மதிப்பு: %d/100 — %s வரம்பை தாண்டியது\n" +
                        "• கண்டறிதல் காரணி: %s",
                        alert.getId(), severity, attackType,
                        alert.getSrcIp(), alert.getDstIp(),
                        score, severity,
                        alert.getDetails() != null ? alert.getDetails()
                                : "ஸ்னார்ட் கையொப்பம் பொருந்தியது அல்லது வெல்ஃபோர்ட் புள்ளிவிவர ஒழுங்கின்மை வரம்பை தாண்டியது."
                );
            } else {
                answer = String.format(
                        "அச்சுறுத்தல் #%d (%s) ஆய்வு:\n" +
                        "• மூல IP: %s → இலக்கு IP: %s\n" +
                        "• தீவிரத்தன்மை: %s (நம்பிக்கை மதிப்பு: %d/100)\n" +
                        "• கண்டறிதல் காரணி: %s",
                        alert.getId(), attackType,
                        alert.getSrcIp(), alert.getDstIp(),
                        severity, score,
                        alert.getDetails() != null ? alert.getDetails()
                                : "ஸ்னார்ட் விதி கையொப்ப பொருத்தம் அல்லது வெல்ஃபோர்ட் புள்ளிவிவர ஒழுங்கின்மை."
                );
            }

            addAttackRecommendationsTamil(attackType, alert.getSrcIp(), mitre, recommendations);
        } else {
            if (askingWhy) {
                answer = String.format(
                        "Alert #%d is classified as %s because:\n" +
                        "• Attack Type: %s\n" +
                        "• Source IP: %s → Destination IP: %s\n" +
                        "• Confidence Score: %d/100 — exceeded the %s severity threshold\n" +
                        "• Detection Reason: %s",
                        alert.getId(), severity, attackType,
                        alert.getSrcIp(), alert.getDstIp(),
                        score, severity,
                        alert.getDetails() != null ? alert.getDetails()
                                : "Snort signature matched or Welford statistical anomaly Z-score threshold exceeded."
                );
            } else {
                answer = String.format(
                        "Threat Alert #%d (%s) analyzed:\n" +
                        "• Source: %s → Destination: %s\n" +
                        "• Severity: %s (Confidence Score: %d/100)\n" +
                        "• Detection Reason: %s",
                        alert.getId(), attackType,
                        alert.getSrcIp(), alert.getDstIp(),
                        severity, score,
                        alert.getDetails() != null ? alert.getDetails()
                                : "Snort signature match or Welford statistical anomaly threshold exceeded."
                );
            }

            addAttackRecommendationsEnglish(attackType, alert.getSrcIp(), mitre, recommendations);
        }

        return new ChatResponse(answer, severity, score, mitre, recommendations);
    }

    private void addAttackRecommendationsEnglish(String attackType, String srcIp,
                                                  List<String> mitre, List<String> recommendations) {
        String t = attackType != null ? attackType.toUpperCase() : "";
        if (t.contains("SYN") || t.contains("DOS") || t.contains("FLOOD")) {
            mitre.add("T1498 (Network Denial of Service)");
            recommendations.add("Enable SYN cookies and TCP connection rate limiting.");
            recommendations.add("Apply egress/ingress filtering and temporarily isolate source IP " + srcIp + ".");
            recommendations.add("Verify edge firewall connection tracking table limits.");
        } else if (t.contains("SQL") || t.contains("INJECTION")) {
            mitre.add("T1190 (Exploit Public-Facing Application)");
            recommendations.add("Enforce Parameterized Queries / PreparedStatements across all database queries.");
            recommendations.add("Deploy WAF rule inspection for malicious SQL keywords.");
            recommendations.add("Apply Principle of Least Privilege on database user accounts.");
        } else if (t.contains("SCAN") || t.contains("PROBE") || t.contains("SWEEP")) {
            mitre.add("T1046 (Network Service Discovery)");
            recommendations.add("Close unused network ports and restrict perimeter ingress access.");
            recommendations.add("Enable automated scan-drop policies and rate limiting on connection attempts.");
        } else if (t.contains("BRUTE") || t.contains("FORCE") || t.contains("AUTH")) {
            mitre.add("T1110 (Brute Force)");
            recommendations.add("Implement account lockout policies after failed login attempts.");
            recommendations.add("Enable multi-factor authentication (MFA).");
        } else if (t.contains("ICMP")) {
            mitre.add("T1498 (Network Denial of Service)");
            recommendations.add("Enable ICMP rate limiting at the network perimeter.");
            recommendations.add("Block excessive ICMP echo requests at the firewall level.");
        } else {
            recommendations.add("Continuously monitor 5-tuple flow records for anomalous volume spikes.");
            recommendations.add("Verify Welford anomaly engine baseline convergence (requires 50+ samples).");
        }
    }

    private void addAttackRecommendationsTamil(String attackType, String srcIp,
                                                List<String> mitre, List<String> recommendations) {
        String t = attackType != null ? attackType.toUpperCase() : "";
        if (t.contains("SYN") || t.contains("DOS") || t.contains("FLOOD")) {
            mitre.add("T1498 (Network Denial of Service)");
            recommendations.add("SYN குக்கீகள் மற்றும் TCP இணைப்பு வீத வரம்புகளை செயல்படுத்தவும்.");
            recommendations.add("சந்தேகத்திற்கிடமான மூல IP (" + srcIp + ") ஐ தற்காலிகமாக தனிமைப்படுத்தவும்.");
        } else if (t.contains("SQL") || t.contains("INJECTION")) {
            mitre.add("T1190 (Exploit Public-Facing Application)");
            recommendations.add("அனைத்து SQL வினவல்களுக்கும் அளவுரு வினவல்களை பயன்படுத்தவும்.");
            recommendations.add("WAF மூலம் தீங்கிழைக்கும் SQL முக்கிய சொற்களை ஆய்வு செய்யவும்.");
        } else if (t.contains("SCAN") || t.contains("PROBE") || t.contains("SWEEP")) {
            mitre.add("T1046 (Network Service Discovery)");
            recommendations.add("பயன்படுத்தப்படாத திறந்த போர்ட்களை மூடவும்.");
            recommendations.add("தொடர்ச்சியான ஸ்கேன் IP முகவரிகளை தானியங்கி தடுப்பு பட்டியலில் சேர்க்கவும்.");
        } else if (t.contains("BRUTE") || t.contains("FORCE")) {
            mitre.add("T1110 (Brute Force)");
            recommendations.add("தொடர் தோல்வியான உள்நுழைவு முயற்சிகளுக்கு கணக்கு பூட்டல் கொள்கையை அமைக்கவும்.");
            recommendations.add("பல-காரணி அங்கீகாரம் (MFA) செயல்படுத்தவும்.");
        } else {
            recommendations.add("5-டூப்பிள் ஓட்ட பதிவுகளை தொடர்ந்து கண்காணிக்கவும்.");
            recommendations.add("வெல்ஃபோர்ட் ஒழுங்கின்மை இயந்திர அடிப்படை நிலையை சரிபார்க்கவும்.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EXPERT Q&A  (cybersecurity tutor + app guide)
    // ─────────────────────────────────────────────────────────────────────────

    private ChatResponse buildExpertAnswer(String query, boolean isTamil) {
        String q = query.toLowerCase();

        if (isTamil) {
            return buildTamilAnswer(q, query);
        }
        return buildEnglishAnswer(q, query);
    }

    // ── TAMIL Q&A ──────────────────────────────────────────────────────────────

    private ChatResponse buildTamilAnswer(String q, String originalQuery) {

        // How to use this app / step-by-step guide
        if ((q.contains("use") && (q.contains("app") || q.contains("indha") || q.contains("இந்த") || q.contains("epdi") || q.contains("எப்படி")))
                || q.contains("use panrathu") || q.contains("use panuvadhu")
                || q.contains("use பண்றது") || q.contains("பயன்படுத்துவது")
                || q.contains("எப்படி பயன்படுத்த") || q.contains("appai epdi")
                || q.contains("app epdi")) {
            return new ChatResponse(
                    "Threat3D App-ஐ பயன்படுத்த எளிய வழிகாட்டல்:\n\n" +
                    "1. Login — Admin, Analyst, அல்லது Student கணக்கில் உள்நுழையவும்.\n" +
                    "2. Dashboard — நேரலை threat stats மற்றும் 3D network topology-ஐ பார்க்கலாம்.\n" +
                    "3. Simulation Hub — Port Scan, SYN Flood போன்ற attack simulations-ஐ இயக்கி பார்க்கலாம்.\n" +
                    "4. Threat Alerts — கண்டறியப்பட்ட அச்சுறுத்தல்களை HIGH, CRITICAL போன்ற severity அடிப்படையில் வடிகட்டலாம்.\n" +
                    "5. Traffic & Flows — 5-tuple network flows மற்றும் packet விவரங்களை ஆராயலாம்.\n" +
                    "6. Rules & Engines — Snort signatures மற்றும் Welford anomaly engine நிலையை சரிபார்க்கலாம்.\n" +
                    "7. 3D Topology — Network nodes நிலையை (HEALTHY, SUSPICIOUS, COMPROMISED) 3D-ல் காணலாம்.\n" +
                    "8. Learning Center — MITRE ATT&CK techniques மற்றும் தற்காப்பு முறைகளை கற்கலாம்.",
                    "LOW", 10,
                    List.of("T1046", "T1498"),
                    List.of("Dashboard-லிருந்து தொடங்கவும்", "Simulation Hub-ல் முதல் simulation இயக்கவும்")
            );
        }

        // What to do next
        if (q.contains("next") && (q.contains("enna") || q.contains("என்ன") || q.contains("pannanum") || q.contains("பண்ணணும்"))
                || q.contains("next enna") || q.contains("அடுத்து என்ன") || q.contains("next step")) {
            return new ChatResponse(
                    "Threat3D-ல் அடுத்து செய்ய வேண்டியவை:\n\n" +
                    "1. Simulation Hub → Port Scan அல்லது SYN Flood simulation-ஐ இயக்கவும்.\n" +
                    "2. Threat Alerts → உருவாகும் புதிய Alerts-ஐ பார்க்கவும்.\n" +
                    "3. Traffic & Flows → 5-tuple network flows-ஐ ஆய்வு செய்யவும்.\n" +
                    "4. Rules & Engines → தூண்டப்பட்ட Snort rules-ஐ சரிபார்க்கவும்.\n" +
                    "5. Learning Center → MITRE ATT&CK தற்காப்பு உத்திகளை கற்கவும்.",
                    "LOW", 15,
                    List.of("T1046", "T1498"),
                    List.of("Simulation Hub-ல் தாக்குதலை இயக்கவும்", "Threat Alerts-ஐ கண்காணிக்கவும்")
            );
        }

        // NIDS explanation
        if (q.contains("nids") || q.contains("பிணைய ஊடுருவல்") || q.contains("nids na enna")
                || (q.contains("enna") && q.contains("nids"))) {
            return new ChatResponse(
                    "NIDS என்பது Network Intrusion Detection System. இது network traffic-ஐ தொடர்ச்சியாக கண்காணித்து சந்தேகத்திற்குரிய செயல்பாடுகள் மற்றும் ஊடுருவல்களைக் கண்டறியும் பாதுகாப்பு அமைப்பாகும்.\n\n" +
                    "Threat3D-ல் 2 முக்கிய கண்டறிதல் முறைகள் உள்ளன:\n" +
                    "1. Signature-Based Detection: Snort rules (SID 1001-1005) மூலம் அறியப்பட்ட attack patterns-ஐ ஒப்பிடுகிறது.\n" +
                    "2. Anomaly-Based Detection: Welford algorithm மூலம் normal network baseline-ல் இருந்து ஏற்படும் மாற்றங்களைக் கண்டறிகிறது.\n\n" +
                    "இவ்விரண்டையும் இணைத்து Hybrid Threat Score மூலம் அச்சுறுத்தல்கள் துல்லியமாகக் கண்டறியப்படுகின்றன.",
                    "LOW", 20,
                    List.of("T1046", "T1498"),
                    List.of("Rules & Engines பக்கத்தில் Snort விதிகளை பார்க்கலாம்",
                            "Welford anomaly engine baseline நிலையை சரிபார்க்கலாம்")
            );
        }

        // How Threat3D detects threats
        if ((q.contains("threat3d") || q.contains("இந்த") || q.contains("system") || q.contains("app") || q.contains("eppadi") || q.contains("epdi"))
                && (q.contains("detect") || q.contains("kandu pidukkum") || q.contains("கண்டறிகிறது") || q.contains("epadi detect") || q.contains("eppadi threat"))) {
            return new ChatResponse(
                    "Threat3D-ல் traffic 6 நிலைகளில் analyse செய்யப்பட்டு threats கண்டறியப்படுகின்றன:\n\n" +
                    "1. Flow Tracking: 5-tuple network flows-ஐ (src IP, dst IP, src port, dst port, protocol) சேகரிக்கிறது.\n" +
                    "2. Feature Extraction: 41 அம்சங்களை (packet count, byte count, TCP flags) கணக்கிடுகிறது.\n" +
                    "3. Snort Signature Matching: Snort rules (SID 1001–1005) மூலம் அறியப்பட்ட தாக்குதல்களை ஒப்பிடுகிறது.\n" +
                    "4. Welford Anomaly Detection: Baseline-ல் இருந்து ஏற்படும் மாறுபாடுகளை Z-score மூலம் கணக்கிடுகிறது.\n" +
                    "5. Hybrid Threat Scoring: Signature மற்றும் Anomaly மதிப்புகளை இணைத்து 0–100 Hybrid Threat Score உருவாக்குகிறது.\n" +
                    "6. Alert Generation: Threat Score வரம்பை தாண்டினால் Threat Alert உருவாக்கப்பட்டு H2 database-ல் சேமிக்கப்படுகிறது.",
                    "LOW", 25,
                    List.of("T1046", "T1498"),
                    List.of("Simulation Hub-ல் தாக்குதலை இயக்கி கண்டறிதலை நேரலையாக பார்க்கலாம்",
                            "Rules & Engines பக்கத்தில் Snort விதிகளை ஆய்வு செய்யலாம்")
            );
        }

        // Simulation how-to
        if (q.contains("simulation") || q.contains("உருவகப்படுத்துதல்") || q.contains("simulate")
                || q.contains("epdi run") || q.contains("epadi run") || q.contains("run panrathu")) {
            return new ChatResponse(
                    "Simulation Hub-ல் simulation இயக்க இந்த படிகளை பின்பற்றவும்:\n\n" +
                    "1. இடதுபுற Sidebar-ல் உள்ள 'Simulation Hub' பக்கத்திற்கு செல்லவும்.\n" +
                    "2. Port Scan, SYN Flood, Brute Force அல்லது Web Anomaly போன்ற attack scenario-வை தேர்வு செய்யவும்.\n" +
                    "3. 'Launch Simulation' பொத்தானை கிளிக் செய்யவும்.\n" +
                    "4. Real-time progress மற்றும் detection நிகழ்வுகளை நேரலையாக பார்க்கலாம்.\n" +
                    "5. Simulation முடிந்ததும் Threat Alerts பக்கத்தில் புதிய Alerts-ஐ பார்க்க முடியும்.\n\n" +
                    "(குறிப்பு: இது 100% பாதுகாப்பான simulation — actual network-ல் எந்த பாதிப்பும் ஏற்படாது.)",
                    "MEDIUM", 60,
                    List.of("T1498", "T1046"),
                    List.of("Simulation Hub பக்கத்திற்கு செல்லவும்", "Port Scan simulation-ல் தொடங்கவும்")
            );
        }

        // Alert severity / Why HIGH
        if (q.contains("severity") || q.contains("high") || q.contains("critical")
                || (q.contains("yen") && (q.contains("alert") || q.contains("high")))
                || q.contains("ஏன் high")) {
            return new ChatResponse(
                    "Threat3D-ல் Alert HIGH severity என வகைப்படுத்தப்பட முக்கிய காரணங்கள்:\n\n" +
                    "1. Hybrid Threat Score: கணக்கிடப்பட்ட Threat Score 61 முதல் 80 வரை இருக்கும் போது அது HIGH severity ஆகிறது.\n" +
                    "2. Snort Signature Match: SQL Injection (SID-1003) அல்லது Brute Force (SID-1004) போன்ற ஆபத்தான Snort rules பொருந்தும் போது.\n" +
                    "3. Welford Anomaly Z-Score: Network traffic-ன் Z-score baseline-ல் இருந்து 3.0σ-க்கு மேல் விலகும் போது.\n\n" +
                    "குறிப்பிட்ட Alert ID-ஐ பற்றிய விவரங்களை அறிய 'Explain Alert #859' எனக் கேட்கலாம்!",
                    "HIGH", 75,
                    List.of("T1046", "T1190", "T1498"),
                    List.of("Threat Alerts பக்கத்தில் Alert விவரங்களை பார்க்கவும்", "Welford Anomaly Engine Z-score-ஐ சரிபார்க்கவும்")
            );
        }

        // Where to see threats
        if ((q.contains("threat") || q.contains("alert") || q.contains("எச்சரிக்கை") || q.contains("அச்சுறுத்தல்"))
                && (q.contains("where") || q.contains("enga") || q.contains("எங்கே") || q.contains("பார்") || q.contains("paarkka"))) {
            return new ChatResponse(
                    "Threat Alerts-ஐ பார்க்க வழிகாட்டல்:\n\n" +
                    "1. Sidebar-ல் உள்ள 'Threat Alerts' பக்கத்திற்கு செல்லவும்.\n" +
                    "2. Severity filter மூலம் CRITICAL, HIGH, MEDIUM, LOW என வகைப்படுத்தலாம்.\n" +
                    "3. Alert-ஐ கிளிக் செய்து MITRE ATT&CK mapping மற்றும் விவரங்களை காணலாம்.\n" +
                    "4. Dashboard-லும் சமீபத்திய அச்சுறுத்தல்கள் நேரலையாக காட்டப்படுகின்றன.\n" +
                    "5. NOVA Voice-ல் 'Show threats' என்று சொன்னால் நேரடியாக இந்த பக்கத்திற்கு செல்லலாம்.",
                    "HIGH", 75,
                    List.of("T1046", "T1190", "T1498"),
                    List.of("Threat Alerts பக்கத்திற்கு செல்லவும்", "CRITICAL severity மூலம் வடிகட்டவும்")
            );
        }

        // Welford algorithm
        if (q.contains("welford") || q.contains("வெல்ஃபோர்ட்") || q.contains("z-score") || q.contains("z score")
                || (q.contains("anomaly") && (q.contains("work") || q.contains("epdi") || q.contains("epadi")))) {
            return new ChatResponse(
                    "Welford's Algorithm என்பது real-time streaming data-வில் mean (μ) மற்றும் variance (σ²)-ஐ திறம்பட கணக்கிடும் வழிமுறையாகும்.\n\n" +
                    "Threat3D-ல் Welford செயல்படும் முறை:\n" +
                    "1. 41 network flow features-ன் இயல்பான நடத்தையை சேகரிக்கிறது.\n" +
                    "2. 50+ samples கிடைத்தவுடன் baseline தயார் (Ready) ஆகிறது.\n" +
                    "3. ஒவ்வொரு புதிய flow-க்கும் Z-score = (value − mean) / std_deviation கணக்கிடப்படுகிறது.\n" +
                    "4. Z-score 3.0σ-ஐ தாண்டினால் அது Anomaly என கண்டறியப்பட்டு Hybrid Threat Score-ல் சேர்க்கப்படுகிறது.",
                    "LOW", 25,
                    List.of("T1046"),
                    List.of("50+ benign மாதிரிகளுடன் baseline calibrate செய்யவும்",
                            "Rules & Engines பக்கத்தில் Z-score threshold-ஐ சரிபார்க்கவும்")
            );
        }

        // Dashboard
        if (q.contains("dashboard") || q.contains("முகப்பு") || q.contains("home") || q.contains("கட்டுப்பாட்டு மையம்")) {
            return new ChatResponse(
                    "SOC Dashboard:\n\n" +
                    "• நேரலை அச்சுறுத்தல் புள்ளிவிவரங்கள் (மொத்த Packets, Active Threats, Critical count)\n" +
                    "• 3D Network Topology miniview\n" +
                    "• WebSocket மூலம் நேரலை எச்சரிக்கை stream\n" +
                    "• Quick Simulation launcher\n" +
                    "• சமீபத்திய Threat Alerts பட்டியல்",
                    "LOW", 10,
                    List.of("T1046", "T1498"),
                    List.of("Dashboard இல் நேரலை தரவை கண்காணிக்கவும்")
            );
        }

        // Traffic/Flow
        if (q.contains("traffic") || q.contains("flow") || q.contains("போக்குவரத்து") || q.contains("ஓட்டம்")) {
            return new ChatResponse(
                    "Traffic & Flows பக்கம்:\n\n" +
                    "• 5-டூப்பிள் (src IP, dst IP, src port, dst port, protocol) பிணைய ஓட்டங்கள்\n" +
                    "• Packet count மற்றும் Byte count புள்ளிவிவரங்கள்\n" +
                    "• TCP Flags ஆய்வு\n" +
                    "• On-demand NIDS pipeline analysis ஐ தூண்ட முடியும்\n\n" +
                    "Simulation இயக்கிய பிறகு, இந்த பக்கத்தில் உருவாக்கப்பட்ட traffic ஐ பார்க்கலாம்.",
                    "LOW", 15,
                    List.of("T1046"),
                    List.of("Traffic & Flows பக்கத்திற்கு செல்லவும்")
            );
        }

        // Rules/Snort
        if (q.contains("rule") || q.contains("snort") || q.contains("விதி") || q.contains("signature")) {
            return new ChatResponse(
                    "Rules & Engines பக்கம்:\n\n" +
                    "ஸ்னார்ட் விதிகள் (Snort Rules):\n" +
                    "• SID 1001: ICMP Echo Flood\n" +
                    "• SID 1002: SYN Flood\n" +
                    "• SID 1003: Port Scan\n" +
                    "• SID 1004: SQL Injection\n" +
                    "• SID 1005: Brute Force\n\n" +
                    "வெல்ஃபோர்ட் இயந்திரம்:\n" +
                    "• Z-score threshold: 3.0σ\n" +
                    "• 50 மாதிரிகளுக்கு பிறகு Baseline தயாராகும்",
                    "LOW", 15,
                    List.of("T1046", "T1190"),
                    List.of("Rules & Engines பக்கத்திற்கு செல்லவும்")
            );
        }

        // Topology
        if (q.contains("topology") || q.contains("3d") || q.contains("இடவியல்") || q.contains("node") || q.contains("முனை")) {
            return new ChatResponse(
                    "3D Network Topology:\n\n" +
                    "• Three.js / WebGL மூலம் இடைமுகமான 3D காட்சி\n" +
                    "• முனை நிலைகள்: HEALTHY (பச்சை), SUSPICIOUS (மஞ்சள்), COMPROMISED (சிவப்பு), ISOLATED (சாம்பல்)\n" +
                    "• 3D spatial coordinates (posX, posY, posZ) மூலம் இடம் தீர்மானிக்கப்படுகிறது\n" +
                    "• தாக்குதல் animate செய்யும் போது particle effects காட்டப்படும்\n" +
                    "• OrbitControls மூலம் சுழற்றவும் / zoom செய்யவும்",
                    "LOW", 20,
                    List.of("T1046"),
                    List.of("3D Topology பக்கத்திற்கு செல்லவும்", "முனையை கிளிக் செய்து ஆய்வாளரை திறக்கவும்")
            );
        }

        // Learning
        if (q.contains("learning") || q.contains("கற்றல்") || q.contains("learn") || q.contains("mitre")) {
            return new ChatResponse(
                    "SOC Learning Center:\n\n" +
                    "• Threat Dossiers: கண்டறியப்பட்ட அச்சுறுத்தல் வகைகளின் விரிவான விளக்கம்\n" +
                    "• MITRE ATT&CK: T1046, T1190, T1498, T1110 போன்ற உத்திகளை கற்கலாம்\n" +
                    "• Defensive recommendations: தற்காப்பு நடவடிக்கைகள்\n" +
                    "• AI threat explanations: எந்த alert ஐயும் AI மூலம் விளக்கம் பெறலாம்",
                    "LOW", 10,
                    List.of("T1046", "T1190", "T1498"),
                    List.of("Learning Center க்கு செல்லவும்", "MITRE ATT&CK உத்திகளை ஆய்வு செய்யவும்")
            );
        }

        // DoS / SYN
        if (q.contains("dos") || q.contains("syn") || q.contains("வெள்ளம்") || q.contains("flood")) {
            return new ChatResponse(
                    "SYN Flood மற்றும் DoS தாக்குதல்கள்:\n\n" +
                    "SYN Flood என்பது ஒரு Denial-of-Service தாக்குதல். தாக்குபவர் முழுமையடையாத TCP இணைப்புகளை (half-open) ஏராளமாக அனுப்பி சர்வரின் connection queue ஐ நிரப்புகிறார்.\n\n" +
                    "தற்காப்பு நடவடிக்கைகள்:\n" +
                    "• SYN Cookies ஐ இயக்கவும் (sysctl net.ipv4.tcp_syncookies=1)\n" +
                    "• TCP connection rate limiting அமைக்கவும்\n" +
                    "• ஃபயர்வாலில் மூல IP அடிப்படையிலான வடிகட்டுதல்\n\n" +
                    "Threat3D இல்: SYN Flood simulation இயக்கி கண்டறிதலை நேரில் பாருங்கள்!",
                    "HIGH", 85,
                    List.of("T1498 (Network Denial of Service)"),
                    List.of("SYN Flood simulation இயக்கவும்", "SYN Cookies kernel parameter இயக்கவும்")
            );
        }

        // Hybrid Threat Score
        if (q.contains("hybrid") || q.contains("score") || q.contains("மதிப்பு") || q.contains("threat score")) {
            return new ChatResponse(
                    "Hybrid Threat Score — Threat3D கண்டறிதல் மதிப்பீட்டு முறை:\n\n" +
                    "Hybrid Threat Score என்பது இரண்டு கண்டறிதல் முறைகளை இணைக்கிறது:\n" +
                    "1. Snort signature match confidence (0–100)\n" +
                    "2. Welford anomaly Z-score normalized value (0–100)\n\n" +
                    "இரண்டும் weighted average மூலம் இணைக்கப்பட்டு:\n" +
                    "• 0–40: LOW severity\n" +
                    "• 41–60: MEDIUM severity\n" +
                    "• 61–80: HIGH severity\n" +
                    "• 81–100: CRITICAL severity\n\n" +
                    "இது false positives ஐ குறைத்து accurate detection செய்கிறது.",
                    "LOW", 30,
                    List.of("T1046"),
                    List.of("Rules & Engines பக்கத்தில் engine status பார்க்கவும்")
            );
        }

        // General Tamil fallback
        return new ChatResponse(
                "வணக்கம்! நான் NOVA — Threat3D NIDS-ன் AI உதவியாளர். நான் உங்களுக்கு:\n\n" +
                "📚 கற்றல் உதவி:\n" +
                "• 'NIDS na enna?' — NIDS பற்றி விளக்கம்\n" +
                "• 'Threat3D eppadi threat detect pannuthu?' — 6-stage pipeline விளக்கம்\n" +
                "• 'Welford epadi work pannuthu?' — Z-score algorithm விளக்கம்\n\n" +
                "🖥️ App வழிகாட்டல்:\n" +
                "• 'Indha app epdi use panrathu?' — படிப்படியான வழிகாட்டல்\n" +
                "• 'Simulation epdi run panrathu?' — Simulation Hub வழிகாட்டல்\n" +
                "• 'Threat enga paarkka?' — Alerts பார்க்கும் இடம்\n\n" +
                "🔍 Alert ஆய்வு:\n" +
                "• 'Explain Alert #859' — குறிப்பிட்ட alert விளக்கம்\n" +
                "• 'Alert yen HIGH severity la irukku?' — Alert severity காரணம்",
                "LOW", 10,
                List.of("T1046", "T1190", "T1498"),
                List.of("மேற்கண்ட கேள்விகளை கேட்கவும்", "Simulation Hub இல் தாக்குதல் இயக்கி பார்க்கவும்")
        );
    }

    // ── ENGLISH Q&A ────────────────────────────────────────────────────────────

    private ChatResponse buildEnglishAnswer(String q, String originalQuery) {

        // How to use the app / step-by-step guide
        if ((q.contains("how") && q.contains("use") && (q.contains("app") || q.contains("this") || q.contains("system")))
                || (q.contains("how do i") && q.contains("use"))
                || q.contains("step by step") || q.contains("get started") || q.contains("where to start")) {
            return new ChatResponse(
                    "How to use Threat3D NIDS — Step-by-Step Guide:\n\n" +
                    "Step 1: Login with admin / analyst / student credentials on the Login page.\n" +
                    "Step 2: Dashboard — View live threat stats and the 3D network topology preview.\n" +
                    "Step 3: Simulation Hub — Safely launch attack simulations (Port Scan, SYN Flood, Brute Force, etc.).\n" +
                    "Step 4: Threat Alerts — Review detected alerts, filter by severity (CRITICAL/HIGH/MEDIUM/LOW).\n" +
                    "Step 5: Traffic & Flows — Inspect the 5-tuple network flows generated by the simulation.\n" +
                    "Step 6: Rules & Engines — Review Snort signature rules and Welford anomaly engine status.\n" +
                    "Step 7: 3D Topology — Explore node states (HEALTHY/SUSPICIOUS/COMPROMISED/ISOLATED).\n" +
                    "Step 8: Learning Center — Study MITRE ATT&CK techniques and defensive recommendations.\n\n" +
                    "Tip: You can also use NOVA voice assistant to navigate by voice!",
                    "LOW", 10,
                    List.of("T1046", "T1498"),
                    List.of("Start from the Dashboard", "Run your first simulation in Simulation Hub")
            );
        }

        // What should I do next
        if ((q.contains("what") && q.contains("next")) || q.contains("what should i do")
                || q.contains("where do i go") || q.contains("next step")) {
            return new ChatResponse(
                    "What to do next in Threat3D:\n\n" +
                    "1. Go to Simulation Hub → Launch an attack scenario (Port Scan or SYN Flood to start).\n" +
                    "2. Go to Threat Alerts → Watch new alerts appear as detection fires.\n" +
                    "3. Go to Traffic & Flows → Inspect the generated 5-tuple traffic records.\n" +
                    "4. Go to Rules & Engines → See which Snort rule was triggered.\n" +
                    "5. Go to Learning Center → Study the attack dossier and MITRE ATT&CK mitigations.",
                    "LOW", 15,
                    List.of("T1046", "T1498"),
                    List.of("Run a simulation", "Monitor Threat Alerts page")
            );
        }

        // NIDS explanation
        if (q.contains("nids") || q.contains("intrusion detection") || q.contains("what is nids")
                || q.contains("network intrusion")) {
            return new ChatResponse(
                    "NIDS — Network Intrusion Detection System:\n\n" +
                    "A NIDS continuously monitors network traffic to identify suspicious activity, policy violations, and unauthorized access attempts in real time.\n\n" +
                    "Two core detection approaches:\n" +
                    "1. Signature-Based Detection: Matches traffic patterns against known attack signatures (like Snort rules SID 1001–1005 in Threat3D).\n" +
                    "2. Anomaly-Based Detection: Establishes a statistical baseline of normal behavior and flags deviations (Welford algorithm in Threat3D).\n\n" +
                    "Threat3D combines both into a Hybrid Threat Score for accurate, low-false-positive detection. Unlike IPS (Intrusion Prevention), NIDS only detects — it does not block.",
                    "LOW", 20,
                    List.of("T1046", "T1498"),
                    List.of("Review Snort rules in Rules & Engines page",
                            "Check anomaly engine baseline status")
            );
        }

        // How Threat3D detects threats — after Welford check so welford queries don't fall here
        if ((q.contains("threat3d") || q.contains("how does") || q.contains("this app"))
                && (q.contains("detect") || q.contains("work") || q.contains("identify"))
                && !q.contains("welford")) {
            return new ChatResponse(
                    "How Threat3D Detects Threats — The Detection Pipeline:\n\n" +
                    "Stage 1 — Flow Tracking: Captures 5-tuple network flows (src IP, dst IP, src port, dst port, protocol) in sliding windows.\n" +
                    "Stage 2 — Feature Extraction: Computes 41 dimensional features per flow (packet count, byte count, TCP SYN/ACK/RST flags, inter-arrival times, etc.).\n" +
                    "Stage 3 — Snort Signature Matching: Matches flow features against deterministic Snort rules (SID 1001–1005) for known attack patterns.\n" +
                    "Stage 4 — Welford Anomaly Detection: Computes real-time streaming Z-scores across all 41 dimensions to detect statistical deviations from baseline.\n" +
                    "Stage 5 — Hybrid Threat Scoring: Combines signature confidence + anomaly Z-score into a single 0–100 threat score.\n" +
                    "Stage 6 — Alert Generation: If the Hybrid Score exceeds severity threshold, a ThreatAlert is persisted to the H2 database with MITRE ATT&CK mapping.",
                    "LOW", 25,
                    List.of("T1046", "T1498"),
                    List.of("Launch a simulation to observe the pipeline live",
                            "Inspect Rules & Engines page for engine status")
            );
        }

        // Welford algorithm (English)
        if (q.contains("welford") || q.contains("anomaly") || q.contains("baseline")
                || q.contains("z-score") || q.contains("z score")) {
            return new ChatResponse(
                    "Welford's Online Algorithm in Threat3D:\n\n" +
                    "Welford's algorithm computes real-time streaming mean (μ) and variance (σ²) in a single pass without storing the full packet history.\n\n" +
                    "How it works in Threat3D:\n" +
                    "1. Each new flow updates the running mean and variance for all 41 feature dimensions simultaneously.\n" +
                    "2. After a warm-up period of 50 samples, the baseline is marked 'Ready'.\n" +
                    "3. For each incoming flow, a Z-score is computed:\n" +
                    "   Z = (observed_value − mean) / standard_deviation\n" +
                    "4. If |Z| > 3.0σ across any critical dimension, the flow is flagged as anomalous.\n" +
                    "5. The anomaly signal is combined with Snort signature results in the Hybrid Threat Scorer.\n\n" +
                    "Benefit: Detects zero-day and novel attacks that have no signature match.",
                    "LOW", 25,
                    List.of("T1046"),
                    List.of("Calibrate baseline with at least 50 benign traffic samples",
                            "Tune Z-score threshold (default 3.0σ) in Rules & Engines")
            );
        }

        // How to run a simulation
        if ((q.contains("how") || q.contains("run") || q.contains("launch") || q.contains("start"))
                && (q.contains("simulation") || q.contains("simulate") || q.contains("scenario"))) {

            return new ChatResponse(
                    "How to Run a Simulation in Threat3D:\n\n" +
                    "Step 1: Click 'Simulation Hub' in the left sidebar.\n" +
                    "Step 2: Select an attack scenario from the scenario picker:\n" +
                    "  • Port Scan — Simulates reconnaissance scanning for open ports\n" +
                    "  • SYN Flood — Simulates TCP SYN flood denial-of-service\n" +
                    "  • ICMP Flood — Simulates ping-based flood attack\n" +
                    "  • Brute Force — Simulates repeated authentication attempts\n" +
                    "  • Web Anomaly — Simulates abnormal HTTP request patterns\n" +
                    "  • Mixed Sequence — Runs multiple attack types in sequence\n" +
                    "Step 3: Click 'Launch Simulation'.\n" +
                    "Step 4: Watch real-time progress updates and detection events stream in.\n" +
                    "Step 5: After completion, view the summary report and visit Threat Alerts for the generated alerts.\n\n" +
                    "Note: 100% safe — no real network packets are transmitted!",
                    "MEDIUM", 60,
                    List.of("T1498", "T1046"),
                    List.of("Navigate to Simulation Hub", "Start with Port Scan scenario")
            );
        }

        // Where to see threats
        if ((q.contains("where") || q.contains("how") || q.contains("see") || q.contains("view") || q.contains("find"))
                && (q.contains("threat") || q.contains("alert"))) {
            return new ChatResponse(
                    "Where to See Threat Alerts in Threat3D:\n\n" +
                    "1. Click 'Threat Alerts' in the left sidebar navigation.\n" +
                    "2. Use the severity filter to focus on CRITICAL or HIGH alerts.\n" +
                    "3. Click any alert row to open the detailed inspector with MITRE ATT&CK mapping.\n" +
                    "4. The Dashboard also shows the most recent alerts in real time.\n" +
                    "5. NOVA voice: Say 'show threats' to navigate directly.\n\n" +
                    "Tip: Run a simulation first to populate the alerts list!",
                    "HIGH", 75,
                    List.of("T1046", "T1190", "T1498"),
                    List.of("Navigate to Threat Alerts page", "Filter by CRITICAL severity")
            );
        }

        // Dashboard
        if (q.contains("dashboard") || q.contains("home") || q.contains("main page") || q.contains("overview")) {
            return new ChatResponse(
                    "SOC Dashboard Overview:\n\n" +
                    "The main dashboard displays:\n" +
                    "• Real-time stat widgets: Total Packets, Active Flows, Threat Alerts, Anomaly Baseline status\n" +
                    "• 3D Network Topology mini-preview (click for fullscreen)\n" +
                    "• Live STOMP/WebSocket threat alert stream\n" +
                    "• Quick Scenario Launcher to start simulations instantly\n" +
                    "• Threat Severity Breakdown chart (CRITICAL / HIGH / MEDIUM / LOW)\n" +
                    "• Recent Alerts list with MITRE ATT&CK technique IDs",
                    "LOW", 10,
                    List.of("T1046", "T1498"),
                    List.of("Monitor live threat counters on the Dashboard",
                            "Use Quick Simulation Launcher to trigger attack tests")
            );
        }

        // Traffic
        if (q.contains("traffic") || q.contains("flow") || q.contains("packet")) {
            return new ChatResponse(
                    "Traffic & Flow Analysis:\n\n" +
                    "The Traffic page shows:\n" +
                    "• 5-tuple network flow records (source/destination IP, ports, protocol)\n" +
                    "• Packet count and byte totals per flow\n" +
                    "• TCP flag distribution (SYN, ACK, RST, FIN, URG)\n" +
                    "• On-demand NIDS pipeline analysis trigger\n" +
                    "• Flow timestamps and duration metrics\n\n" +
                    "After running a simulation, visit this page to inspect the generated synthetic traffic.",
                    "LOW", 15,
                    List.of("T1046"),
                    List.of("Inspect 5-tuple flow records", "Trigger on-demand pipeline analysis")
            );
        }

        // Rules / Snort
        if (q.contains("rule") || q.contains("snort") || q.contains("signature")) {
            return new ChatResponse(
                    "Detection Rules & Engines:\n\n" +
                    "Snort Rules (active):\n" +
                    "• SID 1001: ICMP Echo Flood detection\n" +
                    "• SID 1002: TCP SYN Flood detection\n" +
                    "• SID 1003: Port Scan/Sweep detection\n" +
                    "• SID 1004: SQL Injection pattern detection\n" +
                    "• SID 1005: Brute Force authentication detection\n\n" +
                    "Welford Anomaly Engine:\n" +
                    "• Z-score threshold: 3.0σ\n" +
                    "• Warm-up samples required: 50\n" +
                    "• Dimensions monitored: 41 flow features\n" +
                    "• Real-time streaming mean & variance computation",
                    "LOW", 15,
                    List.of("T1046", "T1190"),
                    List.of("Review active Snort rules in Rules & Engines page",
                            "Verify Welford baseline calibration status")
            );
        }

        // Topology
        if (q.contains("topology") || q.contains("3d") || q.contains("node") || q.contains("network map")) {
            return new ChatResponse(
                    "3D Network Topology Visualization:\n\n" +
                    "• Interactive WebGL 3D node graph powered by Three.js\n" +
                    "• Node states with color coding:\n" +
                    "  - HEALTHY: Green nodes — no threat activity detected\n" +
                    "  - SUSPICIOUS: Yellow nodes — anomalous traffic observed\n" +
                    "  - COMPROMISED: Red nodes — confirmed threat detected\n" +
                    "  - ISOLATED: Grey nodes — quarantined nodes\n" +
                    "• 3D spatial positioning using (posX, posY, posZ) coordinates\n" +
                    "• Attack animations: particle pulse effects during simulation\n" +
                    "• OrbitControls for pan, zoom, and rotate\n" +
                    "• Click any node to open the inspector drawer",
                    "LOW", 20,
                    List.of("T1046"),
                    List.of("Navigate to 3D Topology page",
                            "Click nodes to open the inspector drawer")
            );
        }

        // Learning
        if (q.contains("learning") || q.contains("learn") || q.contains("mitre") || q.contains("dossier") || q.contains("study")) {
            return new ChatResponse(
                    "SOC Learning Center:\n\n" +
                    "• Threat Dossiers: Detailed explanations of each attack type (Port Scan, SYN Flood, SQL Injection, Brute Force, etc.)\n" +
                    "• MITRE ATT&CK: Study techniques T1046, T1190, T1498, T1110 and their defensive countermeasures\n" +
                    "• AI threat explanations: Select any alert to generate a contextual AI analysis\n" +
                    "• Defensive recommendations: Actionable mitigations for each attack type",
                    "LOW", 10,
                    List.of("T1046", "T1190", "T1498"),
                    List.of("Navigate to Learning Center",
                            "Select a threat dossier to study MITRE ATT&CK mitigations")
            );
        }

        // Hybrid Threat Score
        if (q.contains("hybrid") || q.contains("hybrid score") || q.contains("threat score") || q.contains("confidence score")) {
            return new ChatResponse(
                    "Hybrid Threat Score — Threat3D's Scoring Model:\n\n" +
                    "The Hybrid Threat Score combines two detection signals into one unified 0–100 score:\n" +
                    "1. Snort Signature Confidence: How closely the traffic matches a known attack signature (0–100)\n" +
                    "2. Welford Anomaly Score: Normalized Z-score showing deviation from statistical baseline (0–100)\n\n" +
                    "Severity classification:\n" +
                    "• 0–40 → LOW\n" +
                    "• 41–60 → MEDIUM\n" +
                    "• 61–80 → HIGH\n" +
                    "• 81–100 → CRITICAL\n\n" +
                    "This hybrid approach reduces false positives vs. single-method detection.",
                    "LOW", 30,
                    List.of("T1046"),
                    List.of("View engine status in Rules & Engines",
                            "Run a simulation to see live scoring in action")
            );
        }

        // DoS / SYN Flood
        if (q.contains("syn") || q.contains("dos") || q.contains("flood") || q.contains("denial of service")) {
            return new ChatResponse(
                    "SYN Flood / Denial-of-Service Attack:\n\n" +
                    "A SYN Flood is a DoS attack where an attacker sends a massive volume of TCP SYN packets without completing the handshake. This exhausts the server's connection queue (backlog) and prevents legitimate connections.\n\n" +
                    "Defense countermeasures:\n" +
                    "• Enable SYN Cookies (sysctl net.ipv4.tcp_syncookies=1 on Linux)\n" +
                    "• Implement TCP connection rate limiting per source IP\n" +
                    "• Deploy stateful firewall with connection tracking limits\n" +
                    "• Use scrubbing services / DDoS mitigation for large-scale attacks\n\n" +
                    "In Threat3D: SID 1002 (Snort) + Welford byte-count anomaly detects this pattern.",
                    "HIGH", 85,
                    List.of("T1498 (Network Denial of Service)"),
                    List.of("Enable kernel SYN cookies",
                            "Implement edge firewall rate limiting",
                            "Try SYN Flood simulation in Simulation Hub")
            );
        }

        // SQL Injection
        if (q.contains("sql") || q.contains("injection")) {
            return new ChatResponse(
                    "SQL Injection Attack:\n\n" +
                    "SQL Injection occurs when untrusted user input is concatenated directly into SQL query strings, allowing attackers to manipulate database queries, extract data, or bypass authentication.\n\n" +
                    "Defense best practices:\n" +
                    "• Always use Parameterized Queries / PreparedStatements — never string concatenation\n" +
                    "• Apply ORM abstraction layers (Hibernate, JPA)\n" +
                    "• Enforce Principle of Least Privilege on database accounts\n" +
                    "• Deploy WAF with SQL injection detection rules\n" +
                    "• Validate and sanitize all user input server-side\n\n" +
                    "In Threat3D: SID 1004 (Snort) detects common SQL injection payloads.",
                    "CRITICAL", 92,
                    List.of("T1190 (Exploit Public-Facing Application)"),
                    List.of("Use PreparedStatements with typed bind parameters",
                            "Deploy WAF SQL inspection rules")
            );
        }

        // Port Scan
        if (q.contains("port scan") || q.contains("port sweep") || q.contains("reconnaissance") || q.contains("recon")) {
            return new ChatResponse(
                    "Port Scan / Network Reconnaissance:\n\n" +
                    "Port scanning is a technique used by attackers to discover open ports and services on a target system, mapping potential attack entry points before exploitation.\n\n" +
                    "Common scan types:\n" +
                    "• TCP SYN scan (stealth scan) — sends SYN, doesn't complete handshake\n" +
                    "• TCP connect scan — completes the handshake, easier to detect\n" +
                    "• UDP scan — probes for open UDP services\n\n" +
                    "Defense:\n" +
                    "• Close unused ports and implement strict firewall egress/ingress rules\n" +
                    "• Enable IDS port scan detection (Snort SID 1003 in Threat3D)\n" +
                    "• Use port knocking or dynamic blocking for automated scan mitigation",
                    "MEDIUM", 55,
                    List.of("T1046 (Network Service Discovery)"),
                    List.of("Close unused ports via firewall policy",
                            "Enable automated scan-drop rules",
                            "Try Port Scan simulation in Simulation Hub")
            );
        }

        // Brute Force
        if (q.contains("brute force") || q.contains("brute-force") || q.contains("password attack") || q.contains("credential")) {
            return new ChatResponse(
                    "Brute Force Authentication Attack:\n\n" +
                    "Brute force attacks attempt to guess credentials by systematically trying all possible passwords or using credential dictionaries (dictionary attack).\n\n" +
                    "Defense measures:\n" +
                    "• Implement account lockout after N failed attempts (e.g., 5 attempts → 15-min lockout)\n" +
                    "• Enable multi-factor authentication (MFA/2FA)\n" +
                    "• Use CAPTCHA for public-facing login pages\n" +
                    "• Deploy rate limiting on authentication endpoints\n" +
                    "• Monitor and alert on high-frequency login failures\n\n" +
                    "In Threat3D: SID 1005 (Snort) + Welford frequency anomaly detects brute force patterns.",
                    "HIGH", 80,
                    List.of("T1110 (Brute Force)"),
                    List.of("Implement account lockout policies",
                            "Enable MFA on all critical accounts")
            );
        }

        // Default English fallback
        return new ChatResponse(
                "Hello! I'm NOVA — your AI assistant for Threat3D NIDS. I can help you with:\n\n" +
                "📚 Cybersecurity Education:\n" +
                "• 'What is NIDS?' — Learn about network intrusion detection\n" +
                "• 'How does Welford work?' — Algorithm explanation\n" +
                "• 'What is SYN Flood?' — Attack type explanations\n" +
                "• 'How does Threat3D detect threats?' — Full pipeline walkthrough\n\n" +
                "🖥️ App Navigation Guide:\n" +
                "• 'How do I use this app?' — Step-by-step guide\n" +
                "• 'How do I run a simulation?' — Simulation Hub walkthrough\n" +
                "• 'Where can I see threats?' — Alert navigation guide\n" +
                "• 'What should I do next?' — Workflow recommendations\n\n" +
                "🔍 Alert Analysis:\n" +
                "• 'Explain Alert #859' — Real alert data from database\n" +
                "• 'Why is Alert #859 HIGH?' — Severity reasoning\n\n" +
                "Ask me anything!",
                "LOW", 10,
                List.of("T1046", "T1190", "T1498"),
                List.of("Try asking about a specific alert by ID",
                        "Ask how to run a simulation to get started")
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UTILITY
    // ─────────────────────────────────────────────────────────────────────────

    /** Returns true if the text contains any Tamil Unicode character (U+0B80–U+0BFF). */
    private boolean containsTamil(String text) {
        if (text == null) return false;
        for (char c : text.toCharArray()) {
            if (c >= '\u0B80' && c <= '\u0BFF') {
                return true;
            }
        }
        // Also check for common Thanglish phonetic keywords that should trigger Tamil response
        String lower = text.toLowerCase();
        return lower.contains("enna") || lower.contains("epdi") || lower.contains("epadi") || lower.contains("eppadi")
                || lower.contains("yeppadi") || lower.contains("pannu") || lower.contains("pannanum") || lower.contains("panrathu")
                || lower.contains("panradhu") || lower.contains("paarkka") || lower.contains("enga") || lower.contains("yen")
                || lower.contains("indha") || lower.contains("nids na") || lower.contains("irukku") || lower.contains("iruku");
    }
}
