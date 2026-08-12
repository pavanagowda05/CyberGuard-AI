# ============================================================
# CyberGuard AI — ai/ner_extractor.py
# Uses spaCy and regex to extract suspicious entities
# from email text: URLs, sender domains, org names, IPs.
# ============================================================

import re
import spacy
from urllib.parse import urlparse

# Load spaCy model once
_nlp = None

def _load_nlp():
    global _nlp
    if _nlp is None:
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


def extract_entities(text: str) -> dict:
    """
    Extract named entities and suspicious signals from email text.

    Returns:
        {
          "urls":             list of URLs found,
          "suspicious_urls":  list of URLs flagged as suspicious,
          "orgs":             list of organisation names,
          "ips":              list of IP addresses,
          "urgency_words":    list of urgency/pressure words found,
          "has_suspicious_url": bool,
          "urgency_count":    int
        }
    """
    nlp = _load_nlp()

    # ── Extract URLs using regex ──────────────────────────────
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+]|[!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    urls = url_pattern.findall(text)

    # ── Extract IP addresses ──────────────────────────────────
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = ip_pattern.findall(text)

    # ── Flag suspicious URLs ──────────────────────────────────
    suspicious_domains = [
        "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly",
        "tiny.cc", "is.gd", "cli.gs", "pic.gd", "DwarfURL",
        "yourls.org", "prettylinkpro.com", "shorte.st",
    ]
    suspicious_keywords_in_url = [
        "login", "verify", "account", "secure", "update",
        "confirm", "banking", "password", "suspend", "urgent",
    ]

    suspicious_urls = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = (domain + path).lower()

        is_suspicious = (
            any(sd in domain for sd in suspicious_domains) or
            any(kw in full for kw in suspicious_keywords_in_url) or
            len(domain.split(".")) > 3  # too many subdomains
        )
        if is_suspicious:
            suspicious_urls.append(url)

    # ── Extract organisation names with spaCy NER ─────────────
    # Limit text length to avoid slow processing on very long emails
    doc  = nlp(text[:2000])
    orgs = list(set([
        ent.text for ent in doc.ents
        if ent.label_ in ("ORG", "PRODUCT", "GPE")
    ]))

    # ── Urgency word detection ────────────────────────────────
    urgency_words_list = [
        "urgent", "immediately", "suspended", "verify",
        "click here", "act now", "limited time", "24 hours",
        "48 hours", "expire", "expired", "permanent", "block",
        "blocked", "terminate", "terminated", "confirm",
        "validate", "unauthorized", "suspicious activity",
        "account locked", "unusual activity", "update required",
    ]
    text_lower = text.lower()
    found_urgency = [w for w in urgency_words_list if w in text_lower]

    return {
        "urls":               urls,
        "suspicious_urls":    suspicious_urls,
        "orgs":               orgs[:10],  # limit to 10
        "ips":                ips,
        "urgency_words":      found_urgency,
        "has_suspicious_url": len(suspicious_urls) > 0,
        "urgency_count":      len(found_urgency),
    }


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    test = (
        "Dear User, your SBI account has been suspended due to suspicious activity. "
        "Click here immediately to verify: http://fake-sbi-login.verify-account.com/update "
        "Act now — you have 24 hours before permanent closure. "
        "— SBI Security Team"
    )

    print("=" * 60)
    print("CyberGuard AI — NER Extractor Test")
    print("=" * 60)
    result = extract_entities(test)
    for k, v in result.items():
        print(f"  {k}: {v}")