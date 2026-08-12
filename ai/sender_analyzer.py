# ============================================================
# CyberGuard AI — ai/sender_analyzer.py
# Analyses the sender email address and domain for:
# - Free email provider used for official communication
# - Domain age (new domains = suspicious)
# - Suspicious patterns in sender address
# - Domain mismatch between display name and actual sender
# ============================================================

import os
import sys
import re
import socket
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Free email providers — legitimate banks/orgs never use these
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "aol.com", "protonmail.com",
    "icloud.com", "me.com", "mac.com", "live.com",
    "msn.com", "inbox.com", "mail.com", "zoho.com",
    "gmx.com", "gmx.net", "yandex.com", "yandex.ru",
    "tutanota.com", "fastmail.com", "hushmail.com",
    "yahoo.co.in", "yahoo.in", "rediff.com",
    "sify.com", "vsnl.net", "dataone.in",
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tech",
    ".info", ".biz", ".name", ".pw", ".cc", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".work", ".click", ".link",
    ".download", ".stream", ".review", ".win", ".loan",
    ".party", ".trade", ".date", ".racing", ".accountant",
}

# Suspicious words in domain names
SUSPICIOUS_DOMAIN_WORDS = [
    "verify", "secure", "login", "account", "update",
    "confirm", "validation", "alert", "suspended",
    "blocked", "unlock", "restore", "security",
    "official", "support", "helpdesk", "service",
    "authenticate", "authorization", "urgent",
    "banking", "netbanking", "onlinebanking",
    "reward", "prize", "winner", "claim",
    "kyc", "aadhar", "aadhaar", "pan",
]


def extract_sender_info(email_text: str, sender_email: str = "") -> dict:
    """
    Extract sender information from email text and headers.
    Tries to find FROM address if not provided.
    """
    # Try to extract sender from email text
    if not sender_email:
        patterns = [
            r'[Ff]rom:\s*[^<]*<([^>]+)>',
            r'[Ff]rom:\s*([\w.\-]+@[\w.\-]+\.\w+)',
            r'[Rr]eply-[Tt]o:\s*[^<]*<([^>]+)>',
            r'[Ss]ender:\s*([\w.\-]+@[\w.\-]+\.\w+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, email_text)
            if match:
                sender_email = match.group(1).strip()
                break

        # Fallback: match a bare email address anywhere near the start of the
        # text, even without angle brackets or a "From:" label. OCR frequently
        # drops '<' '>' from screenshots of email headers, especially in
        # multi-column table layouts, which silently breaks all four patterns
        # above and leaves sender_email empty.
        if not sender_email:
            plain_match = re.search(r'[\w.\-]+@[\w.\-]+\.\w+', email_text[:500])
            if plain_match:
                sender_email = plain_match.group(0).strip()

    if not sender_email:
        return {
            "sender_email":  "",
            "sender_domain": "",
            "display_name":  "",
            "found":         False,
        }

    # Parse email parts
    parts        = sender_email.lower().split("@")
    sender_local = parts[0] if len(parts) > 0 else ""
    sender_domain = parts[1] if len(parts) > 1 else ""

    # Try to extract display name from email text
    display_match = re.search(
        r'[Ff]rom:\s*([^<\n]+?)\s*(?:<|$)', email_text
    )
    display_name = display_match.group(1).strip() if display_match else ""

    return {
        "sender_email":   sender_email,
        "sender_domain":  sender_domain,
        "sender_local":   sender_local,
        "display_name":   display_name,
        "found":          True,
    }


def analyze_sender(
    sender_email: str = "",
    sender_domain: str = "",
    email_text: str = ""
) -> dict:
    """
    Full sender analysis returning risk signals.

    Returns:
        {
          "sender_email":        str,
          "sender_domain":       str,
          "is_free_provider":    bool,
          "has_suspicious_tld":  bool,
          "has_suspicious_words":bool,
          "domain_exists":       bool,
          "risk_boost":          int,
          "flags":               list,
          "sender_risk_level":   str
        }
    """
    flags      = []
    risk_boost = 0

    # Extract sender if not provided
    if not sender_email and not sender_domain:
        info = extract_sender_info(email_text, sender_email)
        sender_email  = info.get("sender_email", "")
        sender_domain = info.get("sender_domain", "")

    if not sender_domain and sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[1].lower()

    if not sender_domain:
        return {
            "sender_email":         sender_email,
            "sender_domain":        sender_domain,
            "is_free_provider":     False,
            "has_suspicious_tld":   False,
            "has_suspicious_words": False,
            "domain_exists":        True,
            "risk_boost":           0,
            "flags":                ["No sender domain found"],
            "sender_risk_level":    "Unknown",
        }

    sender_domain = sender_domain.lower().strip()

    # ── Check 1: Free email provider ─────────────────────────
    is_free = sender_domain in FREE_EMAIL_PROVIDERS
    if is_free:
        risk_boost += 15
        flags.append(
            f"Sender uses free email provider '{sender_domain}' — "
            f"legitimate banks and organisations never send official emails from free providers"
        )

    # ── Check 1b: Local-part impersonates an institutional domain ────
    # e.g. "hinshaw.berkeley.edu@gmail.com" — the address is engineered to
    # *look* like it comes from a university/government domain at a glance,
    # while the real domain is a free provider. OCR often turns the dot before
    # the TLD into a space ("berkeley edu"), so check both forms.
    if is_free:
        local_part = sender_email.split("@")[0] if "@" in sender_email else ""
        local_normalised = local_part.replace(" ", ".")
        if re.search(r'\.(edu|gov|ac\.\w+|edu\.\w+)\b', local_normalised, re.IGNORECASE):
            risk_boost += 30
            flags.append(
                f"Sender address local-part '{local_part}' is engineered to resemble "
                f"an institutional (.edu/.gov) address, but the real domain is the free "
                f"provider '{sender_domain}' — a known professor/agency impersonation pattern"
            )

    # ── Check 2: Suspicious TLD ───────────────────────────────
    has_suspicious_tld = False
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            has_suspicious_tld = True
            risk_boost += 20
            flags.append(f"Suspicious TLD '{tld}' — commonly used in phishing domains")
            break

    # ── Check 3: Suspicious words in domain ──────────────────
    has_suspicious_words = False
    found_words = []
    for word in SUSPICIOUS_DOMAIN_WORDS:
        if word in sender_domain:
            has_suspicious_words = True
            found_words.append(word)
    if len(found_words) >= 2:
        has_suspicious_words = True
        risk_boost += 15
    elif len(found_words) == 1:
        risk_boost += 3   # negligible — single generic word isn't enough alone
        flags.append(
            f"Suspicious words in sender domain: {', '.join(found_words)}"
        )

    # ── Check 4: Numeric characters in domain ────────────────
    domain_root = sender_domain.split(".")[0]
    if any(c.isdigit() for c in domain_root):
        risk_boost += 5
        flags.append(
            f"Sender domain contains numbers — often a sign of auto-generated phishing domain"
        )

    # ── Check 5: Too many hyphens ─────────────────────────────
    hyphen_count = sender_domain.count("-")
    if hyphen_count >= 2:
        risk_boost += 10
        flags.append(
            f"Sender domain has {hyphen_count} hyphens — "
            f"legitimate company domains rarely have multiple hyphens"
        )

    # ── Check 6: Domain existence check ──────────────────────
    domain_exists = True
    try:
        socket.gethostbyname(sender_domain)
    except socket.gaierror:
        domain_exists = False
        risk_boost += 10
        flags.append(f"Sender domain '{sender_domain}' does not exist or cannot be resolved")

    # ── Check 7: Very long domain ─────────────────────────────
    if len(sender_domain) > 40:
        risk_boost += 10
        flags.append(
            f"Sender domain is unusually long ({len(sender_domain)} chars) — "
            f"legitimate domains are typically short"
        )

    # ── Check 8: Display name mismatch ───────────────────────
    info = extract_sender_info(email_text, sender_email)
    display_name = info.get("display_name", "")
    if display_name and sender_domain:
        display_lower = display_name.lower()
        if any(brand in display_lower for brand in [
            "sbi", "hdfc", "icici", "axis", "kotak",
            "paytm", "google", "microsoft", "apple",
            "amazon", "flipkart", "irctc", "uidai"
        ]):
            # Display name mentions a brand but domain doesn't match
            brand_in_domain = any(
                brand in sender_domain for brand in [
                    "sbi", "hdfc", "icici", "axis", "kotak",
                    "paytm", "google", "microsoft", "apple",
                    "amazon", "flipkart", "irctc", "uidai"
                ]
            )
            if not brand_in_domain:
                risk_boost += 20
                flags.append(
                    f"Display name '{display_name}' suggests official sender "
                    f"but actual domain '{sender_domain}' does not match"
                )

    # ── Determine risk level ──────────────────────────────────
    if risk_boost >= 40:
        risk_level = "Critical"
    elif risk_boost >= 25:
        risk_level = "High"
    elif risk_boost >= 10:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "sender_email":         sender_email,
        "sender_domain":        sender_domain,
        "is_free_provider":     is_free,
        "has_suspicious_tld":   has_suspicious_tld,
        "has_suspicious_words": has_suspicious_words,
        "domain_exists":        domain_exists,
        "risk_boost":           min(risk_boost, 40),
        "flags":                flags,
        "sender_risk_level":    risk_level,
    }


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI — Sender Analyzer Test")
    print("=" * 60)

    tests = [
        {"email": "security@sbi-verify-account.com",   "label": "SBI spoof domain"},
        {"email": "noreply@gmail.com",                  "label": "Free provider"},
        {"email": "alert@hdfc-secure-login.xyz",        "label": "Suspicious TLD"},
        {"email": "support@onlinesbi.com",              "label": "Legitimate SBI"},
        {"email": "no-reply@icicibank.com",             "label": "Legitimate ICICI"},
        {"email": "winner@prize-claim-india-2026.top",  "label": "Lottery scam"},
        {"email": "hinshaw.berkeley.edu@gmail.com", "label": "Institutional local-part, free domain (professor impersonation)"},
    ]

    print("\n" + "=" * 60)
    print("OCR fallback test")
    print("=" * 60)
    test_ocr_text = "from: Prof. Stephen P. Hinshaw hinshaw.berkeley.edu@gmail.com to: student@berkeley.edu date: Feb 9, 2026"
    info = extract_sender_info(test_ocr_text)
    print("Extracted:", info)

    for t in tests:
        print(f"\nTest: {t['label']}")
        result = analyze_sender(sender_email=t["email"])
        print(f"  Domain       : {result['sender_domain']}")
        print(f"  Risk boost   : +{result['risk_boost']}")
        print(f"  Risk level   : {result['sender_risk_level']}")
        for flag in result["flags"]:
            print(f"  Flag         : {flag}")