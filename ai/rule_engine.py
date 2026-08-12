# ============================================================
# CyberGuard AI — ai/rule_engine.py
#
# Combines ALL phishing signals into one final risk score.
#
# Inputs:
#   - MuRIL phishing classifier
#   - NER/content signals
#   - Sender analysis
#   - Subject analysis
#   - URL analysis
#   - Brand spoof detection
#   - Threat intelligence
#   - Threat category/severity
#
# Output:
#   - final_score: 0-100
#   - verdict: Safe / Suspicious / Phishing
#   - severity: Low / Medium / High / Critical
#   - reasons
#   - score_breakdown
#
# IMPORTANT:
# The AI model is only ONE signal.
# The final decision is made using all available signals.
#
# Security-awareness messages are handled separately because
# legitimate awareness content can contain words such as:
#   password, OTP, phishing, bank account, fraud, KYC, etc.
#
# Those words alone must NOT make a message phishing.
# ============================================================

import os
import sys

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)


# ============================================================
# SCORE HELPERS
# ============================================================

def get_severity_label(score: int) -> str:
    """
    Convert final risk score into severity.

    0-29   = Low
    30-59  = Medium
    60-84  = High
    85-100 = Critical
    """

    if score >= 85:
        return "Critical"

    elif score >= 60:
        return "High"

    elif score >= 30:
        return "Medium"

    return "Low"


# ============================================================
# MAIN PHISHING RULE ENGINE
# ============================================================

def compute_final_score(
    ai_confidence: float,
    ai_verdict: str,
    ner_risk: int,
    sender_risk: int,
    subject_risk: int,
    url_risk: int,
    brand_risk: int,
    threat_intel_risk: int,
    threat_category: str,
    threat_severity: str,
) -> dict:
    """
    Combine all phishing signals into a final 0-100 score.

    Signals:

        AI model          : 40
        NER/content       : 20
        Sender            : 15
        Subject           : 10
        URL               : 15
        Brand spoof       : 15
        Threat Intel      : 20
        Severity bonus    : 5

        Maximum raw score : 140

    IMPORTANT DESIGN:

    A high-confidence AI phishing prediction is strong evidence,
    but it is NOT automatically treated as the final truth.

    Security-awareness messages are given special treatment
    because legitimate security education content can contain
    many phishing-related keywords.
    """

    # ========================================================
    # 0. NORMALIZE INPUTS
    # ========================================================

    try:
        ai_confidence = float(ai_confidence)
    except (TypeError, ValueError):
        ai_confidence = 0.0

    ai_confidence = max(
        0.0,
        min(ai_confidence, 1.0)
    )

    try:
        ner_risk = int(ner_risk)
    except (TypeError, ValueError):
        ner_risk = 0

    try:
        sender_risk = int(sender_risk)
    except (TypeError, ValueError):
        sender_risk = 0

    try:
        subject_risk = int(subject_risk)
    except (TypeError, ValueError):
        subject_risk = 0

    try:
        url_risk = int(url_risk)
    except (TypeError, ValueError):
        url_risk = 0

    try:
        brand_risk = int(brand_risk)
    except (TypeError, ValueError):
        brand_risk = 0

    try:
        threat_intel_risk = int(threat_intel_risk)
    except (TypeError, ValueError):
        threat_intel_risk = 0

    ner_risk = max(
        0,
        min(ner_risk, 100)
    )

    sender_risk = max(
        0,
        min(sender_risk, 40)
    )

    subject_risk = max(
        0,
        min(subject_risk, 30)
    )

    url_risk = max(
        0,
        min(url_risk, 40)
    )

    brand_risk = max(
        0,
        min(brand_risk, 25)
    )

    threat_intel_risk = max(
        0,
        min(threat_intel_risk, 40)
    )

    ai_verdict = str(
        ai_verdict
    ).strip().lower()

    threat_category = (
        str(threat_category).strip()
        if threat_category
        else "Unknown"
    )

    threat_severity = (
        str(threat_severity).strip()
        if threat_severity
        else "Low"
    )


    # ========================================================
    # DETECT SECURITY AWARENESS CATEGORY
    # ========================================================

    is_security_awareness = (
        threat_category.lower()
        in [
            "security awareness",
            "security-awareness",
            "awareness",
        ]
    )


    # ========================================================
    # 1. AI MODEL SCORE
    # ========================================================

    if ai_verdict == "phishing":

        # MuRIL probability contributes up to 40 points.
        ai_score = int(
            ai_confidence * 40
        )

    elif ai_verdict == "safe":

        # Safe prediction contributes zero phishing risk.
        ai_score = 0

    else:

        # Unknown verdict — use confidence conservatively.
        ai_score = int(
            ai_confidence * 20
        )

    ai_score = max(
        0,
        min(ai_score, 40)
    )


    # ========================================================
    # 2. NER / CONTENT SCORE
    # ========================================================

    ner_score = int(
        min(
            (ner_risk / 100.0) * 20,
            20
        )
    )


    # ========================================================
    # 3. SENDER SCORE
    # ========================================================

    sender_score = int(
        min(
            (sender_risk / 40.0) * 15,
            15
        )
    )


    # ========================================================
    # 4. SUBJECT SCORE
    # ========================================================

    subject_score = int(
        min(
            (subject_risk / 30.0) * 10,
            10
        )
    )


    # ========================================================
    # 5. URL SCORE
    # ========================================================

    url_score = int(
        min(
            (url_risk / 40.0) * 15,
            15
        )
    )


    # ========================================================
    # 6. BRAND SPOOF SCORE
    # ========================================================

    brand_score = int(
        min(
            (brand_risk / 25.0) * 15,
            15
        )
    )


    # ========================================================
    # 7. THREAT INTELLIGENCE SCORE
    # ========================================================

    intel_score = int(
        min(
            (threat_intel_risk / 40.0) * 20,
            20
        )
    )


    # ========================================================
    # 8. THREAT SEVERITY BONUS
    # ========================================================

    severity_bonus_map = {
        "Critical": 5,
        "High": 3,
        "Medium": 1,
        "Low": 0,
    }

    severity_bonus = severity_bonus_map.get(
        threat_severity,
        0
    )


    # ========================================================
    # 9. RAW SCORE
    # ========================================================

    raw_total = (
        ai_score
        + ner_score
        + sender_score
        + subject_score
        + url_score
        + brand_score
        + intel_score
        + severity_bonus
    )


    # Maximum possible score = 140

    max_possible = 140

    final_score = int(
        min(
            (raw_total / max_possible) * 100,
            100
        )
    )


    # ========================================================
    # 10. STRONG AI OVERRIDES
    # ========================================================

    if ai_verdict == "phishing":

        # Very high confidence AI phishing.
        if ai_confidence >= 0.98:

            final_score = max(
                final_score,
                85
            )

        elif ai_confidence >= 0.95:

            final_score = max(
                final_score,
                80
            )

        elif ai_confidence >= 0.90:

            final_score = max(
                final_score,
                75
            )

        elif ai_confidence >= 0.85:

            final_score = max(
                final_score,
                65
            )

        elif ai_confidence >= 0.75:

            final_score = max(
                final_score,
                55
            )


    # ========================================================
    # 11. THREAT INTELLIGENCE OVERRIDE
    # ========================================================

    # External threat intelligence is strong independent evidence.

    if threat_intel_risk >= 30:

        final_score = max(
            final_score,
            80
        )

    elif threat_intel_risk >= 25:

        final_score = max(
            final_score,
            70
        )


    # ========================================================
    # 12. BRAND SPOOF OVERRIDE
    # ========================================================

    if brand_risk >= 20:

        final_score = max(
            final_score,
            70
        )

    elif brand_risk >= 15:

        final_score = max(
            final_score,
            60
        )


    # ========================================================
    # 13. CRITICAL SENDER SIGNAL
    # ========================================================

    if sender_risk >= 40:

        final_score = max(
            final_score,
            60
        )

    elif sender_risk >= 30:

        final_score = max(
            final_score,
            50
        )


    # ========================================================
    # 14. MULTIPLE CORROBORATING SIGNALS
    # ========================================================

    corroborating_signals = 0

    if ner_score >= 8:
        corroborating_signals += 1

    if sender_score >= 6:
        corroborating_signals += 1

    if subject_score >= 5:
        corroborating_signals += 1

    if url_score >= 6:
        corroborating_signals += 1

    if brand_score >= 6:
        corroborating_signals += 1

    if intel_score >= 6:
        corroborating_signals += 1


    # If AI says phishing AND independent detectors agree,
    # raise the minimum score.

    if ai_verdict == "phishing":

        if corroborating_signals >= 4:

            final_score = max(
                final_score,
                85
            )

        elif corroborating_signals >= 2:

            final_score = max(
                final_score,
                75
            )


    # ========================================================
    # 15. SAFE MODEL PROTECTION
    # ========================================================

    if (
        ai_verdict == "safe"
        and ai_confidence >= 0.95
        and threat_intel_risk == 0
        and brand_risk < 20
        and sender_risk < 40
    ):

        final_score = min(
            final_score,
            30
        )


    # ========================================================
    # 16. SECURITY AWARENESS PROTECTION
    #
    # THIS IS THE IMPORTANT NEW SECTION.
    #
    # Example legitimate message:
    #
    # "Never share your OTP or password.
    #  Do not allow anyone to use your bank account.
    #  Report suspicious activity."
    #
    # MuRIL may see:
    #
    # OTP
    # password
    # bank account
    # fraud
    # phishing
    #
    # and classify it as phishing.
    #
    # However, those words can also occur in legitimate
    # security-awareness messages.
    #
    # Therefore the threat classifier is used as an additional
    # contextual signal.
    # ========================================================

    awareness_override_applied = False

    strong_independent_evidence = (
        threat_intel_risk >= 25
        or brand_risk >= 20
        or sender_risk >= 40
        or url_risk >= 30
        or ner_risk >= 70
    )


    if is_security_awareness:

        # ----------------------------------------------------
        # CASE 1:
        # Security awareness + NO strong malicious evidence
        #
        # Downgrade the AI false positive.
        # ----------------------------------------------------

        if not strong_independent_evidence:

            final_score = min(
                final_score,
                25
            )

            awareness_override_applied = True


        # ----------------------------------------------------
        # CASE 2:
        # Security awareness + strong independent evidence
        #
        # DO NOT automatically make it Safe.
        # ----------------------------------------------------

        else:

            awareness_override_applied = False


    # ========================================================
    # 17. FINAL BOUND
    # ========================================================

    final_score = max(
        0,
        min(
            int(final_score),
            100
        )
    )


    # ========================================================
    # 18. FINAL VERDICT
    # ========================================================

    if final_score >= 70:

        verdict = "Phishing"

        if final_score >= 85:

            severity = "Critical"

        else:

            severity = "High"


    elif final_score >= 40:

        verdict = "Suspicious"

        severity = "Medium"


    else:

        verdict = "Safe"

        severity = "Low"


    # ========================================================
    # 19. HUMAN-READABLE REASONS
    # ========================================================

    reasons = []


    # --------------------------------------------------------
    # SECURITY AWARENESS RESULT
    # --------------------------------------------------------

    if awareness_override_applied:

        reasons.append(
            "Security-awareness context detected"
        )

        reasons.append(
            "The message uses protective or educational "
            "language rather than requesting credentials or payment"
        )

        reasons.append(
            "No strong independent malicious indicators were found"
        )

        if ai_verdict == "phishing":

            reasons.append(
                "The AI phishing prediction was downgraded "
                "because the overall context indicates security awareness"
            )


    # --------------------------------------------------------
    # AI REASON
    # --------------------------------------------------------

    elif ai_verdict == "phishing":

        if ai_confidence >= 0.98:

            reasons.append(
                f"AI model detected phishing patterns "
                f"({ai_confidence * 100:.1f}% confidence)"
            )

        elif ai_confidence >= 0.90:

            reasons.append(
                f"AI model strongly detected phishing patterns "
                f"({ai_confidence * 100:.1f}% confidence)"
            )

        elif ai_confidence >= 0.75:

            reasons.append(
                f"AI model detected phishing patterns "
                f"({ai_confidence * 100:.1f}% confidence)"
            )


    # ========================================================
    # NER REASON
    # ========================================================

    if ner_score >= 10:

        reasons.append(
            "Multiple phishing signals detected in email content"
        )

    elif ner_score >= 5:

        reasons.append(
            "Suspicious entities or content patterns detected"
        )


    # ========================================================
    # SENDER REASON
    # ========================================================

    if sender_score >= 10:

        reasons.append(
            "Sender domain shows strong phishing indicators"
        )

    elif sender_score >= 5:

        reasons.append(
            "Sender information contains suspicious indicators"
        )


    # ========================================================
    # SUBJECT REASON
    # ========================================================

    if subject_score >= 7:

        reasons.append(
            "Subject line contains strong urgency or "
            "social-engineering indicators"
        )

    elif subject_score >= 5:

        reasons.append(
            "Subject line contains urgency manipulation"
        )


    # ========================================================
    # URL REASON
    # ========================================================

    if url_score >= 10:

        reasons.append(
            "Highly suspicious URL patterns detected"
        )

    elif url_score >= 5:

        reasons.append(
            "Suspicious URL detected"
        )


    # ========================================================
    # BRAND REASON
    # ========================================================

    if brand_score >= 10:

        reasons.append(
            "Brand impersonation detected"
            + (
                f" ({threat_category})"
                if threat_category
                else ""
            )
        )

    elif brand_score >= 5:

        reasons.append(
            "Possible brand impersonation detected"
        )


    # ========================================================
    # THREAT INTELLIGENCE REASON
    # ========================================================

    if intel_score >= 10:

        reasons.append(
            "Threat intelligence sources flagged "
            "suspicious infrastructure or content"
        )

    elif intel_score >= 5:

        reasons.append(
            "Threat intelligence produced a warning signal"
        )


    # ========================================================
    # THREAT CATEGORY REASON
    # ========================================================

    if (
        threat_category
        and threat_category not in [
            "None",
            "Unknown",
            "Generic Phishing",
            "Security Awareness",
        ]
        and threat_severity in [
            "Critical",
            "High",
        ]
    ):

        reasons.append(
            f"Threat category: {threat_category}"
        )


    # ========================================================
    # SECURITY AWARENESS + STRONG EVIDENCE
    # ========================================================

    if (
        is_security_awareness
        and not awareness_override_applied
        and strong_independent_evidence
    ):

        reasons.append(
            "Security-awareness wording was detected, "
            "but independent malicious indicators were also found"
        )


    # ========================================================
    # FALLBACK REASON
    # ========================================================

    if not reasons:

        if verdict == "Safe":

            reasons.append(
                "No significant phishing signals detected"
            )

        else:

            reasons.append(
                "Some suspicious indicators were detected"
            )


    # ========================================================
    # 20. RETURN RESULT
    # ========================================================

    return {

        "final_score": final_score,

        "verdict": verdict,

        "severity": severity,

        "threat_category": threat_category,

        "reasons": reasons,

        "score_breakdown": {

            "ai_model": ai_score,

            "ner_signals": ner_score,

            "sender": sender_score,

            "subject": subject_score,

            "urls": url_score,

            "brand_spoof": brand_score,

            "threat_intel": intel_score,

            "severity_bonus": severity_bonus,

            "total_raw": raw_total,

            "max_possible": max_possible,

            "corroborating_signals": corroborating_signals,

            "security_awareness": is_security_awareness,

            "awareness_override_applied":
                awareness_override_applied,
        },
    }


# ============================================================
# TEST CASES
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("CyberGuard AI — Rule Engine Test")
    print("=" * 70)


    scenarios = [

        # ====================================================
        # 1. VERY HIGH CONFIDENCE PHISHING
        # ====================================================

        {
            "label":
                "Very high confidence phishing",

            "ai_confidence":
                0.9983,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                0,

            "sender_risk":
                0,

            "subject_risk":
                0,

            "url_risk":
                0,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "Investment Fraud",

            "threat_severity":
                "High",
        },


        # ====================================================
        # 2. SBI SPOOF WITH MULTIPLE SIGNALS
        # ====================================================

        {
            "label":
                "High confidence SBI phishing",

            "ai_confidence":
                0.99,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                89,

            "sender_risk":
                35,

            "subject_risk":
                25,

            "url_risk":
                40,

            "brand_risk":
                25,

            "threat_intel_risk":
                30,

            "threat_category":
                "Banking Fraud",

            "threat_severity":
                "Critical",
        },


        # ====================================================
        # 3. HINDI PHISHING
        # ====================================================

        {
            "label":
                "Hindi multilingual phishing",

            "ai_confidence":
                0.95,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                70,

            "sender_risk":
                20,

            "subject_risk":
                20,

            "url_risk":
                0,

            "brand_risk":
                20,

            "threat_intel_risk":
                0,

            "threat_category":
                "KYC Fraud",

            "threat_severity":
                "Critical",
        },


        # ====================================================
        # 4. MODERATE PHISHING
        # ====================================================

        {
            "label":
                "Moderate phishing",

            "ai_confidence":
                0.60,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                30,

            "sender_risk":
                15,

            "subject_risk":
                10,

            "url_risk":
                15,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "Generic Phishing",

            "threat_severity":
                "Medium",
        },


        # ====================================================
        # 5. LEGITIMATE EMAIL
        # ====================================================

        {
            "label":
                "Legitimate email",

            "ai_confidence":
                0.98,

            "ai_verdict":
                "Safe",

            "ner_risk":
                0,

            "sender_risk":
                0,

            "subject_risk":
                0,

            "url_risk":
                0,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "None",

            "threat_severity":
                "Low",
        },


        # ====================================================
        # 6. SAFE AI BUT SUSPICIOUS URL
        # ====================================================

        {
            "label":
                "Safe AI but suspicious URL",

            "ai_confidence":
                0.96,

            "ai_verdict":
                "Safe",

            "ner_risk":
                20,

            "sender_risk":
                15,

            "subject_risk":
                10,

            "url_risk":
                40,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "Generic Phishing",

            "threat_severity":
                "Medium",
        },


        # ====================================================
        # 7. KANNADA SECURITY AWARENESS
        #
        # This is similar to your RBI message.
        #
        # MuRIL may say Phishing with high confidence because
        # the text contains:
        #
        # OTP
        # password
        # bank account
        # fraud
        #
        # But the threat classifier says:
        #
        # Security Awareness
        #
        # Therefore the final result should become Safe.
        # ====================================================

        {
            "label":
                "Kannada security awareness",

            "ai_confidence":
                1.00,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                0,

            "sender_risk":
                0,

            "subject_risk":
                0,

            "url_risk":
                0,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "Security Awareness",

            "threat_severity":
                "Low",
        },


        # ====================================================
        # 8. SECURITY AWARENESS WITH SUSPICIOUS URL
        #
        # This MUST remain suspicious/phishing because there
        # is independent malicious evidence.
        # ====================================================

        {
            "label":
                "Security awareness with suspicious URL",

            "ai_confidence":
                0.95,

            "ai_verdict":
                "Phishing",

            "ner_risk":
                20,

            "sender_risk":
                10,

            "subject_risk":
                5,

            "url_risk":
                40,

            "brand_risk":
                0,

            "threat_intel_risk":
                0,

            "threat_category":
                "Security Awareness",

            "threat_severity":
                "Low",
        },
    ]


    # ========================================================
    # RUN ALL TESTS
    # ========================================================

    for scenario in scenarios:

        label = scenario.pop(
            "label"
        )

        result = compute_final_score(
            **scenario
        )

        print("\n" + "-" * 70)

        print(
            f"Scenario : {label}"
        )

        print(
            f"Verdict  : "
            f"{result['verdict']}"
        )

        print(
            f"Severity : "
            f"{result['severity']}"
        )

        print(
            f"Score    : "
            f"{result['final_score']}/100"
        )

        print(
            f"Category : "
            f"{result['threat_category']}"
        )

        print(
            "\nReasons:"
        )

        for reason in result["reasons"]:

            print(
                f"  - {reason}"
            )

        print(
            "\nScore breakdown:"
        )

        for key, value in result[
            "score_breakdown"
        ].items():

            print(
                f"  {key}: {value}"
            )


    print(
        "\n" + "=" * 70
    )

    print(
        "Rule Engine Test Complete"
    )

    print(
        "=" * 70
    )