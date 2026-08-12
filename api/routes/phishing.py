# ============================================================
# CyberGuard AI — api/routes/phishing.py
#
# Full phishing analysis pipeline
#
# POST /api/analyze/phishing
# POST /api/analyze/image
# GET  /api/phishing/alerts
# GET  /api/phishing/stats
# ============================================================

import os
import sys
import re

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)


# ============================================================
# AI MODULE IMPORTS
# ============================================================

from ai.phishing_classifier import classify_email
from ai.ner_extractor import extract_entities
from ai.sender_analyzer import analyze_sender
from ai.subject_analyzer import analyze_subject
from ai.url_analyzer import analyze_urls, resolve_shortened_url
from ai.brand_spoof_detector import detect_brand_spoof
from ai.threat_classifier import classify_threat
from ai.threat_intel import run_threat_intel
from ai.rule_engine import compute_final_score
from ai.ocr_extractor import extract_text_from_image


# ============================================================
# DATABASE IMPORTS
# ============================================================

from storage.db import (
    save_phishing_alert,
    get_phishing_alerts,
    get_phishing_stats,
)


# ============================================================
# ROUTER
# ============================================================

router = APIRouter()


# ============================================================
# REQUEST MODEL
# ============================================================

class EmailInput(BaseModel):
    email_text: str
    sender_email: str = ""
    subject: str = ""
    language: str = "en"


# ============================================================
# SENDER NORMALIZATION
# ============================================================

def normalize_sender(sender_email: str) -> tuple[str, str]:
    """
    Normalize sender input.

    The frontend may send either:

        noreply@github.com

    or:

        GitHub <noreply@github.com>

    This function extracts the actual email address and domain.

    Returns:
        (normalized_email, sender_domain)

    Example:

        GitHub <noreply@github.com>

    becomes:

        noreply@github.com
        github.com
    """

    if not sender_email:
        return "", ""

    sender_email = str(sender_email).strip()

    # Extract a real email address from:
    #
    # GitHub <noreply@github.com>
    # noreply@github.com
    # "GitHub Security" <noreply@github.com>
    #
    match = re.search(
        r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
        sender_email
    )

    if not match:
        return sender_email.lower(), ""

    normalized_email = match.group(0).lower()

    parts = normalized_email.split("@", 1)

    if len(parts) != 2:
        return normalized_email, ""

    sender_domain = parts[1].lower().strip()

    return normalized_email, sender_domain


# ============================================================
# URL SHORTENER CHECK
# ============================================================

URL_SHORTENER_DOMAINS = {
    "tinyurl.com",
    "bit.ly",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "rb.gy",
    "cutt.ly",
    "tiny.cc",
    "short.io",
    "shorturl.at",
    "smarturl.it",
}


def is_shortened_url(url: str) -> bool:
    """
    Check whether a URL belongs to a known URL shortener.
    """

    if not url:
        return False

    url_lower = url.lower()

    for shortener in URL_SHORTENER_DOMAINS:
        if shortener in url_lower:
            return True

    return False



# ============================================================
# SECURITY-AWARENESS / BENIGN-CONTEXT DETECTION
# ============================================================

def is_security_awareness_message(email_text: str, subject: str = "") -> bool:
    """
    Detect educational/protective security-awareness messages.

    This is intentionally conservative:
    - It requires multiple awareness/protective signals.
    - It does not classify a message as awareness when strong
      independent malicious indicators are present; that decision
      is made later in run_full_pipeline().
    """

    full_text = f"{email_text} {subject}".lower()

    awareness_groups = [
        # English
        [
            "security awareness",
            "stay alert",
            "be alert",
            "protect yourself",
            "protect your account",
            "do not share",
            "don't share",
            "never share",
            "do not allow",
            "don't allow",
            "do not click",
            "do not respond",
            "report suspicious",
            "money mule",
            "fraud awareness",
        ],

        # Hindi
        [
            "सतर्क रहें",
            "सावधान रहें",
            "जागरूक रहें",
            "सुरक्षित रहें",
            "साझा न करें",
            "शेयर न करें",
            "किसी के साथ साझा न करें",
            "ओटीपी साझा न करें",
            "पासवर्ड साझा न करें",
            "बैंक विवरण साझा न करें",
            "मनाली म्यूूल",
            "मनी म्यूल",
        ],

        # Kannada
        [
            "ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ",
            "ಜಾಗರೂಕರಾಗಿರಿ",
            "ಜಾಗೃತಿ",
            "ಸುರಕ್ಷಿತವಾಗಿರಿ",
            "ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
            "ಯಾರೊಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
            "ಒಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
            "ಪಾಸ್‌ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
            "ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
            "ಮನಿ ಮ್ಯೂಲ್",
        ],

        # Tamil
        [
            "விழிப்புடன் இருங்கள்",
            "எச்சரிக்கையாக இருங்கள்",
            "பாதுகாப்பாக இருங்கள்",
            "பகிர வேண்டாம்",
            "யாருடனும் பகிர வேண்டாம்",
            "otp பகிர வேண்டாம்",
            "கடவுச்சொல்லை பகிர வேண்டாம்",
            "வங்கி விவரங்களை பகிர வேண்டாம்",
            "பாதுகாப்பு விழிப்புணர்வு",
        ],

        # Telugu
        [
            "జాగ్రత్తగా ఉండండి",
            "అప్రమత్తంగా ఉండండి",
            "సురక్షితంగా ఉండండి",
            "పంచుకోవద్దు",
            "ఎవరితోనూ పంచుకోవద్దు",
            "otp పంచుకోవద్దు",
            "పాస్‌వర్డ్ పంచుకోవద్దు",
            "బ్యాంక్ వివరాలను పంచుకోవద్దు",
            "భద్రతా అవగాహన",
        ],
    ]

    matched_groups = 0
    matched_signals = []

    for group in awareness_groups:
        matches = [item for item in group if item in full_text]
        if matches:
            matched_groups += 1
            matched_signals.extend(matches[:3])

    # A single generic phrase such as "stay alert" is not enough.
    # Two or more protective/awareness signals are required.
    if matched_groups >= 2 or len(matched_signals) >= 3:
        return True

    return False


def has_independent_malicious_signals(
    ner_risk: float,
    sender_risk: float,
    subject_risk: float,
    url_risk: float,
    brand_risk: float,
    threat_intel_risk: float,
    brand_spoofed: bool = False,
) -> bool:
    """
    Decide whether a security-awareness message also contains
    independent evidence that should prevent an awareness override.
    """

    if brand_spoofed:
        return True

    if brand_risk > 0:
        return True

    if threat_intel_risk > 0:
        return True

    # URL risk is treated as a strong independent signal.
    if url_risk >= 10:
        return True

    # Strong sender/subject risk should also prevent a blanket
    # security-awareness override.
    if sender_risk >= 10:
        return True

    if subject_risk >= 6:
        return True

    # NER risk becomes independent evidence when it is substantial.
    if ner_risk >= 15:
        return True

    return False


# ============================================================
# FULL ANALYSIS PIPELINE
# ============================================================

def run_full_pipeline(
    email_text: str,
    sender_email: str = "",
    subject: str = "",
    language: str = "en",
    source: str = "text",
) -> dict:

    """
    Full CyberGuard AI phishing analysis pipeline.

    Pipeline:

        1. MuRIL phishing classifier
        2. NER extraction
        3. Sender analysis
        4. Subject analysis
        5. URL analysis
        6. Shortened URL resolution
        7. Brand spoof detection
        8. Threat classification
        9. Threat intelligence
       10. Unified rule engine
       11. MongoDB storage
       12. API response
    """

    # ========================================================
    # BASIC INPUT CLEANING
    # ========================================================

    if not email_text:
        raise HTTPException(
            status_code=400,
            detail="Email text cannot be empty"
        )

    email_text = str(email_text).strip()

    # Keep the existing 3000-character protection.
    email_text = email_text[:3000]

    subject = str(subject or "").strip()
    language = str(language or "en").strip().lower()

    # ========================================================
    # NORMALIZE SENDER
    # ========================================================

    original_sender = sender_email

    sender_email, sender_domain = normalize_sender(
        sender_email
    )

    print("\n" + "=" * 70)
    print("CYBERGUARD AI — PHISHING ANALYSIS")
    print("=" * 70)

    print(f"Sender input    : {original_sender}")
    print(f"Normalized email: {sender_email}")
    print(f"Sender domain   : {sender_domain}")
    print(f"Subject         : {subject}")
    print(f"Language        : {language}")
    print(f"Source          : {source}")

    # ========================================================
    # STEP 1 — AI PHISHING CLASSIFICATION
    # ========================================================

    print("\n[1/9] Running MuRIL phishing classifier...")

    ai_result = classify_email(email_text)

    print(
        f"  Verdict    : {ai_result.get('verdict')}"
    )

    print(
        f"  Confidence : {ai_result.get('confidence')}"
    )

    print(
        f"  Phishing   : {ai_result.get('prob_phishing')}"
    )

    print(
        f"  Safe       : {ai_result.get('prob_safe')}"
    )

    # ========================================================
    # STEP 2 — NER EXTRACTION
    # ========================================================

    print("\n[2/9] Extracting entities...")

    ner_result = extract_entities(email_text)

    print(
        f"  Organizations : "
        f"{ner_result.get('orgs', [])[:10]}"
    )

    print(
        f"  URLs          : "
        f"{ner_result.get('urls', [])[:10]}"
    )

    print(
        f"  IPs           : "
        f"{ner_result.get('ips', [])[:10]}"
    )

    # ========================================================
    # STEP 3 — SENDER ANALYSIS
    # ========================================================

    print("\n[3/9] Analyzing sender...")

    sender_result = analyze_sender(
        sender_email=sender_email,
        sender_domain=sender_domain,
        email_text=email_text,
    )

    print(
        f"  Risk boost : "
        f"{sender_result.get('risk_boost', 0)}"
    )

    print(
        f"  Risk level : "
        f"{sender_result.get('sender_risk_level', 'Unknown')}"
    )

    # ========================================================
    # STEP 4 — SUBJECT ANALYSIS
    # ========================================================

    print("\n[4/9] Analyzing subject...")

    subject_result = analyze_subject(
        subject=subject,
        email_text=email_text,
    )

    print(
        f"  Risk boost : "
        f"{subject_result.get('risk_boost', 0)}"
    )

    print(
        f"  Risk level : "
        f"{subject_result.get('subject_risk', 'Unknown')}"
    )

    # ========================================================
    # STEP 5 — URL ANALYSIS
    # ========================================================

    print("\n[5/9] Analyzing URLs...")

    url_result = analyze_urls(email_text)

    urls_found = url_result.get(
        "urls_found",
        []
    )

    print(
        f"  URLs found : {len(urls_found)}"
    )

    print(
        f"  URL risk   : "
        f"{url_result.get('risk_boost', 0)}"
    )

    # ========================================================
    # STEP 5B — RESOLVE SHORTENED URLS
    # ========================================================

    print("\n[5B/9] Resolving shortened URLs...")

    resolved_urls = []

    for url in urls_found[:10]:

        if is_shortened_url(url):

            print(
                f"  Shortened URL detected: {url}"
            )

            try:
                resolved = resolve_shortened_url(url)

                if resolved:
                    print(
                        f"  Resolved to: {resolved}"
                    )

                    resolved_urls.append(resolved)

                else:
                    resolved_urls.append(url)

            except Exception as exc:

                print(
                    f"  Resolution failed: {exc}"
                )

                resolved_urls.append(url)

        else:

            resolved_urls.append(url)

    # Remove duplicates while preserving order
    resolved_urls = list(
        dict.fromkeys(resolved_urls)
    )

    # ========================================================
    # STEP 6 — BRAND SPOOF DETECTION
    # ========================================================

    print("\n[6/9] Detecting brand impersonation...")

    brand_result = detect_brand_spoof(
        email_text=email_text,
        sender_email=sender_email,
        sender_domain=sender_domain,
        orgs_found=ner_result.get(
            "orgs",
            []
        ),
    )

    print(
        f"  Brand spoofed : "
        f"{brand_result.get('brand_spoofed', False)}"
    )

    print(
        f"  Spoofed brand : "
        f"{brand_result.get('spoofed_brand')}"
    )

    print(
        f"  Brand risk    : "
        f"{brand_result.get('risk_boost', 0)}"
    )

    # ========================================================
    # STEP 7 — THREAT CLASSIFICATION
    # ========================================================

    print("\n[7/9] Classifying threat...")

    threat_result = classify_threat(
        email_text=email_text,
        subject=subject or subject_result.get(
            "subject",
            ""
        ),
        spoofed_brand=brand_result.get(
            "spoofed_brand"
        ),
        sender_domain=sender_domain,
    )

    print(
        f"  Category : "
        f"{threat_result.get('primary_category', 'Unknown')}"
    )

    print(
        f"  Severity : "
        f"{threat_result.get('severity', 'Medium')}"
    )

    print(
        f"  Confidence : "
        f"{threat_result.get('confidence', 0)}"
    )

    # ========================================================
    # STEP 8 — THREAT INTELLIGENCE
    # ========================================================

    print("\n[8/9] Running threat intelligence...")

    try:

        intel_result = run_threat_intel(
            urls=resolved_urls,
            email_text=email_text,
        )

    except Exception as exc:

        print(
            f"  Threat intelligence error: {exc}"
        )

        # Do NOT allow an external API failure
        # to crash the entire phishing analysis.

        intel_result = {
            "any_flagged": False,
            "flagged_sources": [],
            "results": [],
            "total_risk_boost": 0,
        }

    print(
        f"  Intel flagged : "
        f"{intel_result.get('any_flagged', False)}"
    )

    print(
        f"  Intel risk    : "
        f"{intel_result.get('total_risk_boost', 0)}"
    )

    # ========================================================
    # STEP 9 — UNIFIED RULE ENGINE
    # ========================================================

    print("\n[9/9] Combining all signals...")

    # --------------------------------------------------------
    # NER RISK
    # --------------------------------------------------------

    if "risk_score" in ner_result:

        ner_risk = ner_result.get(
            "risk_score",
            0
        )

    else:

        ner_risk = min(
            len(
                ner_result.get(
                    "urgency_words",
                    []
                )
            ) * 8
            +
            (
                20
                if ner_result.get(
                    "has_suspicious_url"
                )
                else 0
            ),
            80,
        )

    # --------------------------------------------------------
    # GET ALL OTHER RISK SIGNALS
    # --------------------------------------------------------

    sender_risk = sender_result.get(
        "risk_boost",
        0
    )

    subject_risk = subject_result.get(
        "risk_boost",
        0
    )

    url_risk = url_result.get(
        "risk_boost",
        0
    )

    brand_risk = brand_result.get(
        "risk_boost",
        0
    )

    threat_intel_risk = intel_result.get(
        "total_risk_boost",
        0
    )

    # --------------------------------------------------------
    # NORMALIZE THREAT CATEGORY USING THE OVERALL CONTEXT
    # --------------------------------------------------------
    #
    # The threat classifier is a content classifier. A legitimate
    # email can contain words such as "sign in", "account", or
    # "password" without being a phishing attack. Therefore the
    # category must not be shown as a phishing category when the
    # complete pipeline has no independent malicious evidence.
    #
    # This also handles multilingual security-awareness messages
    # whose wording can look suspicious to the AI model.

    awareness_context = is_security_awareness_message(
        email_text=email_text,
        subject=subject or subject_result.get(
            "subject",
            ""
        ),
    )

    independent_malicious = has_independent_malicious_signals(
        ner_risk=ner_risk,
        sender_risk=sender_risk,
        subject_risk=subject_risk,
        url_risk=url_risk,
        brand_risk=brand_risk,
        threat_intel_risk=threat_intel_risk,
        brand_spoofed=bool(
            brand_result.get(
                "brand_spoofed",
                False
            )
        ),
    )

    ai_prob_phishing = float(
        ai_result.get(
            "prob_phishing",
            0
        ) or 0
    )

    ai_is_safe = (
        str(
            ai_result.get(
                "verdict",
                "Safe"
            )
        ).lower()
        == "safe"
        and ai_prob_phishing < 0.50
    )

    # Security-awareness messages are allowed to override a very
    # strong AI phishing prediction ONLY when no independent
    # malicious evidence exists.
    if awareness_context and not independent_malicious:
        threat_category = "Security Awareness"
        threat_severity = "Low"

        threat_result["primary_category"] = "Security Awareness"
        threat_result["secondary_category"] = None
        threat_result["description"] = (
            "Security-awareness or educational message using "
            "protective language rather than requesting credentials, "
            "payment, or account access"
        )
        threat_result["severity"] = "Low"
        threat_result["confidence"] = 0.95

    # A genuinely safe message with no corroborating malicious
    # evidence should have NO threat category.
    elif ai_is_safe and not independent_malicious:
        threat_category = None
        threat_severity = "Low"

        threat_result["primary_category"] = None
        threat_result["secondary_category"] = None
        threat_result["description"] = (
            "No specific phishing threat identified"
        )
        threat_result["severity"] = "Low"
        threat_result["confidence"] = 0.0
        threat_result["indicators"] = []

    else:
        threat_category = threat_result.get(
            "primary_category",
            "Generic Phishing"
        )

        threat_severity = threat_result.get(
            "severity",
            "Medium"
        )

    print(
        f"  Context awareness : {awareness_context}"
    )

    print(
        f"  Independent risk  : {independent_malicious}"
    )

    print(
        f"  Effective category : {threat_category}"
    )

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    final = compute_final_score(
        ai_confidence=ai_result.get(
            "prob_phishing",
            0
        ),

        ai_verdict=ai_result.get(
            "verdict",
            "Safe"
        ),

        ner_risk=ner_risk,

        sender_risk=sender_risk,

        subject_risk=subject_risk,

        url_risk=url_risk,

        brand_risk=brand_risk,

        threat_intel_risk=threat_intel_risk,

        threat_category=threat_category,

        threat_severity=threat_severity,
    )

    print("\n" + "-" * 70)
    print("FINAL RESULT")
    print("-" * 70)

    print(
        f"  Verdict   : {final.get('verdict')}"
    )

    print(
        f"  Score     : "
        f"{final.get('final_score')}/100"
    )

    print(
        f"  Severity  : "
        f"{final.get('severity')}"
    )

    print(
        f"  Category  : "
        f"{final.get('threat_category')}"
    )

    print(
        f"  Reasons   : "
        f"{final.get('reasons', [])}"
    )

    print("-" * 70)

    # ========================================================
    # BUILD ALERT DATA
    # ========================================================

    alert_data = {

        # ----------------------------------------------------
        # Basic email information
        # ----------------------------------------------------

        "email_text": email_text,

        "subject": (
            subject
            or subject_result.get(
                "subject",
                ""
            )
        ),

        "sender_email": sender_email,

        "sender_domain": sender_domain,

        "language": language,

        "source": source,

        # ----------------------------------------------------
        # Final result
        # ----------------------------------------------------

        "verdict": final.get(
            "verdict",
            "Unknown"
        ),

        "risk_score": final.get(
            "final_score",
            0
        ),

        "severity": final.get(
            "severity",
            "Unknown"
        ),

        "threat_category": final.get(
            "threat_category",
            "Unknown"
        ),

        "reasons": final.get(
            "reasons",
            []
        ),

        "score_breakdown": final.get(
            "score_breakdown",
            {}
        ),

        # ----------------------------------------------------
        # AI signals
        # ----------------------------------------------------

        "ai_verdict": ai_result.get(
            "verdict",
            "Unknown"
        ),

        "ai_confidence": ai_result.get(
            "confidence",
            0
        ),

        "prob_phishing": ai_result.get(
            "prob_phishing",
            0
        ),

        "prob_safe": ai_result.get(
            "prob_safe",
            0
        ),

        # ----------------------------------------------------
        # NER signals
        # ----------------------------------------------------

        "urgency_words": ner_result.get(
            "urgency_words",
            []
        ),

        "urls": ner_result.get(
            "urls",
            []
        ),

        "suspicious_urls": ner_result.get(
            "suspicious_urls",
            []
        ),

        "orgs": ner_result.get(
            "orgs",
            []
        ),

        "ips": ner_result.get(
            "ips",
            []
        ),

        # ----------------------------------------------------
        # Sender signals
        # ----------------------------------------------------

        "sender_flags": sender_result.get(
            "flags",
            []
        ),

        "sender_risk": sender_result.get(
            "sender_risk_level",
            "Unknown"
        ),

        "is_free_provider": sender_result.get(
            "is_free_provider",
            False
        ),

        # ----------------------------------------------------
        # Subject signals
        # ----------------------------------------------------

        "subject_flags": subject_result.get(
            "flags",
            []
        ),

        "subject_risk": subject_result.get(
            "subject_risk",
            "Unknown"
        ),

        # ----------------------------------------------------
        # URL signals
        # ----------------------------------------------------

        "url_flags": url_result.get(
            "flags",
            []
        ),

        "url_count": url_result.get(
            "url_count",
            0
        ),

        "url_details": url_result.get(
            "url_details",
            []
        ),

        "resolved_urls": resolved_urls,

        # ----------------------------------------------------
        # Brand spoof signals
        # ----------------------------------------------------

        "brand_spoofed": brand_result.get(
            "brand_spoofed",
            False
        ),

        "spoofed_brand": brand_result.get(
            "spoofed_brand"
        ),

        "brand_details": brand_result.get(
            "details",
            []
        ),

        "multilingual_keywords": brand_result.get(
            "multilingual_keywords",
            []
        ),

        # ----------------------------------------------------
        # Threat category
        # ----------------------------------------------------

        "threat_description": threat_result.get(
            "description",
            ""
        ),

        "threat_indicators": threat_result.get(
            "indicators",
            []
        ),

        "threat_confidence": threat_result.get(
            "confidence",
            0
        ),

        "secondary_category": threat_result.get(
            "secondary_category"
        ),

        # ----------------------------------------------------
        # Threat intelligence
        # ----------------------------------------------------

        "intel_flagged": intel_result.get(
            "any_flagged",
            False
        ),

        "intel_sources": intel_result.get(
            "flagged_sources",
            []
        ),

        "intel_results": intel_result.get(
            "results",
            []
        ),

        # ----------------------------------------------------
        # Extra information
        # ----------------------------------------------------

        "has_suspicious_url": bool(
            url_result.get(
                "suspicious_urls",
                []
            )
        ),
    }

    # ========================================================
    # SAVE TO MONGODB
    # ========================================================

    try:

        alert_id = save_phishing_alert(
            alert_data
        )

    except Exception as exc:

        print(
            f"\nWARNING: Could not save "
            f"phishing alert to database: {exc}"
        )

        # Do not crash the analysis just because
        # MongoDB is unavailable.

        alert_id = None

    # ========================================================
    # FINAL API RESPONSE
    # ========================================================

    return {

        "alert_id": alert_id,

        "verdict": final.get(
            "verdict",
            "Unknown"
        ),

        "risk_score": final.get(
            "final_score",
            0
        ),

        "severity": final.get(
            "severity",
            "Unknown"
        ),

        "threat_category": final.get(
            "threat_category",
            "Unknown"
        ),

        "threat_description": threat_result.get(
            "description",
            ""
        ),

        "confidence": ai_result.get(
            "confidence",
            0
        ),

        "prob_phishing": ai_result.get(
            "prob_phishing",
            0
        ),

        "prob_safe": ai_result.get(
            "prob_safe",
            0
        ),

        "reasons": final.get(
            "reasons",
            []
        ),

        "score_breakdown": final.get(
            "score_breakdown",
            {}
        ),

        # NER
        "urgency_words": ner_result.get(
            "urgency_words",
            []
        ),

        "suspicious_urls": url_result.get(
            "suspicious_urls",
            []
        ),

        "orgs": ner_result.get(
            "orgs",
            []
        ),

        "ips": ner_result.get(
            "ips",
            []
        ),

        # Brand
        "brand_spoofed": brand_result.get(
            "brand_spoofed",
            False
        ),

        "spoofed_brand": brand_result.get(
            "spoofed_brand"
        ),

        "brand_details": brand_result.get(
            "details",
            []
        )[:3],

        "multilingual_keywords": brand_result.get(
            "multilingual_keywords",
            []
        ),

        # Sender
        "sender_email": sender_email,

        "sender_domain": sender_domain,

        "sender_flags": sender_result.get(
            "flags",
            []
        ),

        # Subject
        "subject_flags": subject_result.get(
            "flags",
            []
        ),

        # URLs
        "url_flags": url_result.get(
            "flags",
            []
        ),

        "url_count": url_result.get(
            "url_count",
            0
        ),

        "url_details": url_result.get(
            "url_details",
            []
        ),

        "resolved_urls": resolved_urls,

        # Threat intelligence
        "intel_flagged": intel_result.get(
            "any_flagged",
            False
        ),

        "intel_sources": intel_result.get(
            "flagged_sources",
            []
        ),

        "intel_results": intel_result.get(
            "results",
            []
        ),

        "has_suspicious_url": bool(
            url_result.get(
                "suspicious_urls",
                []
            )
        ),

        "source": source,

        "language": language,
    }


# ============================================================
# TEXT EMAIL ANALYSIS ENDPOINT
# ============================================================

@router.post("/analyze/phishing")
def analyze_phishing(
    payload: EmailInput
):

    if not payload.email_text.strip():

        raise HTTPException(
            status_code=400,
            detail="email_text cannot be empty"
        )

    return run_full_pipeline(
        email_text=payload.email_text,
        sender_email=payload.sender_email,
        subject=payload.subject,
        language=payload.language,
        source="text",
    )


# ============================================================
# IMAGE / SCREENSHOT ANALYSIS ENDPOINT
# ============================================================

@router.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...),
    language: str = Form("en"),
):

    # --------------------------------------------------------
    # Allowed image types
    # --------------------------------------------------------

    allowed = {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/tiff",
    }

    if file.content_type not in allowed:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type: "
                f"{file.content_type}"
            ),
        )

    # --------------------------------------------------------
    # Read image
    # --------------------------------------------------------

    image_bytes = await file.read()

    # Maximum 10 MB
    if len(image_bytes) > 10 * 1024 * 1024:

        raise HTTPException(
            status_code=400,
            detail="Image too large. Max 10MB."
        )

    # --------------------------------------------------------
    # OCR
    # --------------------------------------------------------

    try:

        ocr_result = extract_text_from_image(
            image_bytes,
            lang=language
        )

    except Exception as exc:

        print(
            f"OCR error: {exc}"
        )

        raise HTTPException(
            status_code=500,
            detail="OCR processing failed."
        )

    print("\n=== RAW OCR TEXT ===")
    print(
        repr(
            ocr_result.get(
                "text",
                ""
            )
        )
    )
    print("====================")

    # --------------------------------------------------------
    # Validate OCR
    # --------------------------------------------------------

    ocr_text = ocr_result.get(
        "text",
        ""
    )

    if (
        not ocr_result.get(
            "success",
            False
        )
        or len(ocr_text.strip()) < 10
    ):

        raise HTTPException(
            status_code=422,
            detail=(
                "Could not extract text from image. "
                "Ensure the image contains readable text."
            ),
        )

    # --------------------------------------------------------
    # Run normal phishing pipeline
    # --------------------------------------------------------

    result = run_full_pipeline(
        email_text=ocr_text,
        sender_email="",
        subject="",
        language=language,
        source="image",
    )

    # --------------------------------------------------------
    # Add OCR information to response
    # --------------------------------------------------------

    result["ocr_text"] = ocr_text

    result["ocr_confidence"] = ocr_result.get(
        "confidence",
        0
    )

    return result


# ============================================================
# PHISHING ALERTS
# ============================================================

@router.get("/phishing/alerts")
def phishing_alerts(
    limit: int = 50
):

    # Prevent unreasonable database queries
    limit = max(
        1,
        min(
            limit,
            500
        )
    )

    try:

        return get_phishing_alerts(
            limit=limit
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Could not retrieve phishing alerts: "
                f"{str(exc)}"
            ),
        )


# ============================================================
# PHISHING STATISTICS
# ============================================================

@router.get("/phishing/stats")
def phishing_stats():

    try:

        return get_phishing_stats()

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Could not retrieve phishing statistics: "
                f"{str(exc)}"
            ),
        )