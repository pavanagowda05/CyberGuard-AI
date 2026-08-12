# ============================================================
# CyberGuard AI — ai/brand_spoof_detector.py
# Detects brand spoofing in emails by comparing:
# - Sender domain vs known brand domains
# - Organisation names in email vs sender domain
# - Multilingual brand name mentions
# - Typosquatting detection
# ============================================================

import os
import sys
import json
import re
from difflib import SequenceMatcher

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import BASE_DIR

# ── Load brand databases ──────────────────────────────────────
BRANDS_PATH       = os.path.join(BASE_DIR, "data", "brands.json")
MULTILINGUAL_PATH = os.path.join(BASE_DIR, "data", "brands_multilingual.json")

_brands_db       = None
_multilingual_db = None

def _is_domain_in_brand_family(sender_domain: str, brand_name: str) -> bool:
    """
    Two brands are the same family only if one full name's tokens are an
    exact ordered prefix of the other's (e.g. "Google" -> "Google Pay",
    "Google Cloud"). This correctly rejects "Bank of Baroda" vs "Bank of
    America" (they diverge at the 3rd token) while still allowing
    legitimate sub-brand relationships.
    """
    brand_tokens = brand_name.lower().split()
    for brand in _brands_db["brands"]:
        candidate_tokens = brand["name"].lower().split()
        shorter, longer = sorted([brand_tokens, candidate_tokens], key=len)
        if shorter == longer[:len(shorter)]:
            for d in brand["domains"]:
                if sender_domain == d or sender_domain.endswith("." + d) or d.endswith("." + sender_domain):
                    return True
    return False

def _load_databases():
    global _brands_db, _multilingual_db
    if _brands_db is not None:
        return
    with open(BRANDS_PATH, encoding="utf-8") as f:
        _brands_db = json.load(f)
    with open(MULTILINGUAL_PATH, encoding="utf-8") as f:
        _multilingual_db = json.load(f)

IMPERSONATION_CONTEXT_WORDS = [
    "account", "verify", "verification", "login", "log in", "password",
    "security", "suspended", "confirm", "confirmation", "unauthorized",
    "unusual activity", "team", "support team", "security team",
    "billing", "payment", "invoice", "reset", "restore", "unlock", "kyc",
]

def _brand_mentioned_in_suspicious_context(brand_name_lower, text_lower, window=8):
    """
    Only treat a brand mention as a possible impersonation if it appears near
    account-action / urgency language — e.g. 'verify your Google account' —
    rather than a plain feature/partner mention like 'works with Google,
    OpenAI, and Anthropic'.
    """
    words = text_lower.split()
    brand_words = brand_name_lower.split()
    blen = len(brand_words)
    for i in range(len(words) - blen + 1):
        if words[i:i + blen] == brand_words:
            start = max(0, i - window)
            end = min(len(words), i + blen + window)
            context = " ".join(words[start:end])
            if any(kw in context for kw in IMPERSONATION_CONTEXT_WORDS):
                return True
    return False

# ── Typosquatting similarity check ───────────────────────────
def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def _extract_domain_root(domain: str) -> str:
    """Extract root domain name e.g. 'fake-sbi-verify.com' -> 'fake-sbi-verify'"""
    domain = domain.lower().strip()
    # Remove common TLDs
    for tld in [".co.in", ".org.in", ".net.in", ".gov.in",
                ".com", ".net", ".org", ".in", ".co", ".io"]:
        if domain.endswith(tld):
            domain = domain[:-len(tld)]
            break
    return domain

def _is_typosquat(sender_domain: str, brand_domain: str) -> tuple:
    sender_root = _extract_domain_root(sender_domain)
    brand_root  = _extract_domain_root(brand_domain)

    # Exact match — not a spoof
    if sender_root == brand_root:
        return False, 1.0, "exact_match"

    # NEW: Legitimate subdomain check — e.g. accounts.google.com, mail.google.com
    if sender_domain.endswith("." + brand_domain) or sender_domain == brand_domain:
        return False, 1.0, "legitimate_subdomain"
    
    # Reverse case — sender IS the parent domain, brand domain is a subdomain of sender
    # e.g. sender = google.com, brand (Google Pay) = pay.google.com
    if brand_domain.endswith("." + sender_domain) or brand_domain == sender_domain:
        return False, 1.0, "sender_is_parent_domain"

    # High similarity — likely typosquat
    sim = _similarity(sender_root, brand_root)
    if sim >= 0.85:
        return True, sim, "high_similarity"

    # Brand name embedded in domain e.g. "sbi-verify.com"
    if brand_root in sender_root and len(brand_root) >= 3:
        return True, 0.9, "brand_embedded"

    # Common typosquat patterns
    patterns = [
        # Character substitution: o->0, i->1, l->1
        brand_root.replace("o", "0").replace("i", "1").replace("l", "1"),
        brand_root.replace("0", "o").replace("1", "i"),
        # Character doubling: paypal -> paypall
        brand_root + brand_root[-1],
        # Missing letter
        brand_root[:-1],
        # Extra hyphen
        brand_root.replace("", "-").strip("-"),
        # Common additions
        brand_root + "-secure",
        brand_root + "-login",
        brand_root + "-verify",
        brand_root + "-online",
        brand_root + "-bank",
        brand_root + "-india",
        brand_root + "-support",
        brand_root + "-official",
        brand_root + "-update",
        brand_root + "-alert",
        "secure-" + brand_root,
        "login-" + brand_root,
        "verify-" + brand_root,
        "official-" + brand_root,
        "support-" + brand_root,
    ]
    for pattern in patterns:
        if sender_root == pattern:
            return True, 0.85, "pattern_match"

    return False, sim, "no_match"


def detect_brand_spoof(
    email_text: str,
    sender_email: str = "",
    sender_domain: str = "",
    orgs_found: list = None
) -> dict:
    """
    Detect brand spoofing in an email.

    Args:
        email_text:    full email body text
        sender_email:  sender email address e.g. security@sbi-verify.com
        sender_domain: sender domain e.g. sbi-verify.com
        orgs_found:    list of organisation names extracted by spaCy NER

    Returns:
        {
          "brand_spoofed":     bool,
          "spoofed_brand":     str or None,
          "spoof_method":      str,
          "similarity_score":  float,
          "risk_boost":        int (extra risk points),
          "details":           list of findings
        }
    """
    _load_databases()
    if orgs_found is None:
        orgs_found = []

    # Early exit — if sender_domain belongs to the SAME company family as
    # any brand mentioned in the text, skip spoof detection entirely
    if sender_domain:
        text_lower_check = email_text.lower()
        for brand in _brands_db["brands"]:
            brand_pattern = r'\b' + re.escape(brand["name"].lower()) + r'\b'
            if re.search(brand_pattern, text_lower_check):
            # if brand["name"].lower() in text_lower_check:
                if _is_domain_in_brand_family(sender_domain, brand["name"]):
                    return {
                        "brand_spoofed":    False,
                        "spoofed_brand":    None,
                        "spoof_method":     "same_company_family",
                        "similarity_score": 0.0,
                        "risk_boost":       0,
                        "multilingual_keywords": [],
                        "details":          [f"Sender domain '{sender_domain}' verified as legitimate for '{brand['name']}' company family"],
                    }

    findings      = []
    brand_spoofed = False
    ...
    spoofed_brand = None
    spoof_method  = "none"
    max_sim       = 0.0
    risk_boost    = 0

    text_lower = email_text.lower()

    # ── Check 1: Sender domain vs all brand domains ───────────
    if sender_domain:
        for brand in _brands_db["brands"]:
            # First check if sender IS legitimate for ANY of this brand's domains
            is_legit_for_brand = any(
                sender_domain == d or sender_domain.endswith("." + d)
                for d in brand["domains"]
            )
            if is_legit_for_brand:
                continue  # skip this brand entirely — sender is legitimate

            for official_domain in brand["domains"]:
                is_spoof, sim, method = _is_typosquat(sender_domain, official_domain)
                if is_spoof and sim > max_sim:
                    brand_spoofed = True
                    spoofed_brand = brand["name"]
                    spoof_method  = method
                    max_sim       = sim
                    risk_boost    = 25
                    findings.append(
                        f"Sender domain '{sender_domain}' spoofs '{brand['name']}' "
                        f"({official_domain}) — similarity {sim:.0%}"
                    )

    # ── Check 2: Brand mentioned in email but sender doesn't match ──
    for brand in _brands_db["brands"]:
        brand_name_lower = brand["name"].lower()
        # Use word-boundary matching instead of raw substring — prevents false
        # hits like "LIC" matching inside "click" or "SBI" inside a longer word
        pattern = r'\b' + re.escape(brand_name_lower) + r'\b'
        if re.search(pattern, text_lower) and _brand_mentioned_in_suspicious_context(brand_name_lower, text_lower):
            # Check if sender domain actually belongs to this brand
            sender_is_legit = False
            if sender_domain:
                for official_domain in brand["domains"]:
                    if official_domain in sender_domain or sender_domain in official_domain:
                        sender_is_legit = True
                        break
            if not sender_is_legit and sender_domain:
                if not brand_spoofed:
                    brand_spoofed = True
                    spoofed_brand = brand["name"]
                    spoof_method  = "brand_name_mismatch"
                    risk_boost    = max(risk_boost, 20)
                    findings.append(
                        f"Email mentions '{brand['name']}' but sender domain "
                        f"'{sender_domain}' is not their official domain"
                    )

    # ── Check 3: Multilingual brand name detection ─────────────
    for ml_brand in _multilingual_db["multilingual_brands"]:
        for lang, aliases in ml_brand.get("aliases", {}).items():
            for alias in aliases:
                if len(alias) < 3:  # skip overly short aliases — high false positive risk
                    continue
                if alias in email_text:
                    ...
                    # Found multilingual brand mention
                    sender_is_legit = False
                    if sender_domain:
                        for official_domain in ml_brand["official_domains"]:
                            if official_domain in sender_domain or sender_domain in official_domain:
                                sender_is_legit = True
                                break
                    if not sender_is_legit and sender_domain:
                        if not brand_spoofed:
                            brand_spoofed = True
                            spoofed_brand = ml_brand["name"]
                            spoof_method  = f"multilingual_{lang}"
                            risk_boost    = max(risk_boost, 20)
                        findings.append(
                            f"Email mentions '{ml_brand['name']}' in {lang.upper()} "
                            f"('{alias}') — sender domain does not match official domain"
                        )
                        break

    # ── Check 4: NER-extracted orgs vs sender domain ───────────
    for org in orgs_found:
        org_lower = org.lower().strip()
        for brand in _brands_db["brands"]:
            if _similarity(org_lower, brand["name"].lower()) > 0.8:
                if not _brand_mentioned_in_suspicious_context(brand["name"].lower(), text_lower):
                    continue  # e.g. "...models from OpenAI, Anthropic, Google..." — a partner mention, not impersonation
                sender_is_legit = False
                if sender_domain:
                    for official_domain in brand["domains"]:
                        if official_domain in sender_domain:
                            sender_is_legit = True
                            break
                if not sender_is_legit and sender_domain:
                    if not brand_spoofed:
                        brand_spoofed = True
                        spoofed_brand = brand["name"]
                        spoof_method  = "org_domain_mismatch"
                        risk_boost    = max(risk_boost, 15)
                    findings.append(
                        f"Email claims to be from '{org}' ({brand['name']}) "
                        f"but sent from '{sender_domain}'"
                    )

    # ── Check 5: Multilingual phishing keywords ────────────────
    phish_keywords = _multilingual_db.get("phishing_keywords", {})
    found_keywords = []
    for lang, keywords in phish_keywords.items():
        for kw in keywords:
            kw_pattern = r'\b' + re.escape(kw.lower()) + r'\b'
            if re.search(kw_pattern, email_text.lower()):
                found_keywords.append(f"{kw} ({lang})")

    if found_keywords:
        risk_boost += min(len(found_keywords) * 3, 15)
        findings.append(
            f"Multilingual phishing keywords found: {', '.join(found_keywords[:5])}"
        )

    return {
        "brand_spoofed":    brand_spoofed,
        "spoofed_brand":    spoofed_brand,
        "spoof_method":     spoof_method,
        "similarity_score": round(max_sim, 3),
        "risk_boost":       risk_boost,
        "multilingual_keywords": found_keywords[:10],
        "details":          findings,
    }


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI 2.0 — Brand Spoof Detector Test")
    print("=" * 60)

    tests = [
        {
            "name": "English SBI spoof",
            "text": "Dear User, your SBI account has been suspended. Verify now.",
            "sender_domain": "sbi-verify-account.com",
            "orgs": ["SBI", "State Bank of India"]
        },
        {
            "name": "Hindi phishing",
            "text": "प्रिय उपयोगकर्ता, आपका एसबीआई खाता निलंबित कर दिया गया है। तुरंत क्लिक करें।",
            "sender_domain": "sbionline-verify.net",
            "orgs": []
        },
        {
            "name": "HDFC typosquat",
            "text": "Your HDFC Bank account requires verification.",
            "sender_domain": "hdfcbank-secure.com",
            "orgs": ["HDFC Bank"]
        },
        {
            "name": "Legitimate email",
            "text": "Hi, please find the Q3 report attached. Thanks.",
            "sender_domain": "company.com",
            "orgs": []
        },
        {
            "name": "False positive regression - click should NOT match LIC",
            "text": "If you don't want to receive these job notifications, click unsubscribe.",
            "sender_domain": "honeywell.com",
            "orgs": []
        },
        {
            "name": "False positive regression - partner brand mention should NOT flag",
            "text": "Pro gives you access to the latest models from OpenAI, Anthropic, Google, and more in a single subscription.",
            "sender_domain": "perplexity.ai",
            "orgs": []
        },
        {
            "name": "False positive regression - NER org partner mention should NOT flag",
            "text": "Pro gives you access to the latest models from OpenAI, Anthropic, Google, and more in a single subscription.",
            "sender_domain": "perplexity.ai",
            "orgs": ["Google", "OpenAI", "Anthropic"]
        },
    ]

    for test in tests:
        print(f"\nTest: {test['name']}")
        result = detect_brand_spoof(
            email_text=test["text"],
            sender_domain=test["sender_domain"],
            orgs_found=test.get("orgs", [])
        )
        print(f"  Brand spoofed : {result['brand_spoofed']}")
        print(f"  Spoofed brand : {result['spoofed_brand']}")
        print(f"  Method        : {result['spoof_method']}")
        print(f"  Risk boost    : +{result['risk_boost']}")
        for detail in result["details"]:
            print(f"  Detail        : {detail}")