# ============================================================
# CyberGuard AI — ai/url_analyzer.py
# Deep URL analysis — redirects, shorteners, suspicious patterns
# ============================================================

import re
import sys
import os
import requests
from urllib.parse import urlparse, unquote

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "tiny.cc", "is.gd", "cli.gs", "buff.ly", "adf.ly",
    "bc.vc", "u.to", "x.co", "cutt.ly", "rb.gy",
    "short.io", "shorturl.at", "smarturl.it", "su.pr",
    "dlvr.it", "mcaf.ee", "po.st", "qr.ae",
}

SUSPICIOUS_URL_WORDS = [
    "login", "signin", "verify", "validation", "secure",
    "account", "update", "confirm", "banking", "netbanking",
    "password", "credential", "authenticate", "authorization",
    "reset", "recover", "unlock", "unblock", "restore",
    "suspended", "blocked", "alert", "warning", "urgent",
    "kyc", "aadhar", "aadhaar", "pancard", "otp",
    "reward", "prize", "winner", "claim", "cashback",
    "payment", "invoice", "billing", "checkout",
    "free", "offer", "discount", "limited",
]

LEGITIMATE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "amazon.in", "sbi.co.in", "onlinesbi.com", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com",
    "paytm.com", "phonepe.com", "irctc.co.in",
    "uidai.gov.in", "incometax.gov.in", "gst.gov.in",
    "github.com", "stackoverflow.com", "wikipedia.org",
}


def extract_urls(text: str) -> list:
    """Extract all URLs from text."""
    pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+'
    )
    urls = pattern.findall(text)
    return list(set(urls))



def analyze_single_url(url: str) -> dict:
    """Analyze a single URL for phishing signals."""
    risk_boost = 0
    flags      = []

    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed   = urlparse(url)
        domain   = parsed.netloc.lower().replace("www.", "")
        path     = parsed.path.lower()
        query    = parsed.query.lower()
        full_url = (domain + path + query).lower()

        # Check URL shortener
        is_shortened = domain in URL_SHORTENERS
        if is_shortened:
            risk_boost += 15
            flags.append(f"URL shortener detected ({domain}) — hides real destination")

        # Check if legitimate domain
        is_legitimate = any(
            domain == ld or domain.endswith("." + ld)
            for ld in LEGITIMATE_DOMAINS
        )
        if is_legitimate:
            return {
                "url":           url,
                "domain":        domain,
                "is_shortened":  False,
                "is_legitimate": True,
                "risk_boost":    0,
                "flags":         ["Legitimate domain verified"],
            }

        # Suspicious words in URL
        found_words = [w for w in SUSPICIOUS_URL_WORDS if w in full_url]
        if len(found_words) >= 2:
            risk_boost += min(len(found_words) * 5, 20)
            flags.append(f"Suspicious words in URL: {', '.join(found_words[:5])}")
        elif len(found_words) == 1:
            risk_boost += 3

        # IP address as domain
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain):
            risk_boost += 25
            flags.append(f"URL uses IP address instead of domain name — strong phishing indicator")

        # Excessive subdomains
        subdomain_count = len(domain.split(".")) - 2
        if subdomain_count >= 3:
            risk_boost += 15
            flags.append(f"URL has {subdomain_count} subdomains — often used to fake legitimacy")

        # Long URL
        if len(url) > 100:
            risk_boost += 5
            flags.append(f"Unusually long URL ({len(url)} chars) — may be obfuscating destination")

        # URL encoding / obfuscation
        if "%" in url and unquote(url) != url:
            risk_boost += 10
            flags.append("URL contains encoded characters — may be obfuscating phishing content")

        # @ symbol in URL
        if "@" in parsed.netloc:
            risk_boost += 20
            flags.append("@ symbol in URL — browser ignores everything before @ sign")

        # Double slashes in path
        if "//" in path:
            risk_boost += 10
            flags.append("Double slashes in URL path — obfuscation technique")

        # Suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga",
                          ".cf", ".gq", ".click", ".loan", ".win"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_boost += 20
                flags.append(f"Suspicious TLD '{tld}' in URL")
                break

        return {
            "url":           url,
            "domain":        domain,
            "is_shortened":  is_shortened,
            "is_legitimate": False,
            "risk_boost":    min(risk_boost, 40),
            "flags":         flags,
        }

    except Exception as e:
        return {
            "url":           url,
            "domain":        "",
            "is_shortened":  False,
            "is_legitimate": False,
            "risk_boost":    5,
            "flags":         [f"Could not parse URL: {str(e)}"],
        }

def resolve_shortened_url(url: str, timeout: int = 5) -> str:
    """Follow redirects to find the real destination of a shortened URL."""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        return resp.url
    except Exception:
        try:
            resp = requests.get(url, allow_redirects=True, timeout=timeout, stream=True)
            resp.close()
            return resp.url
        except Exception:
            return url  # fallback — couldn't resolve, use original


# def analyze_urls(text: str) -> dict:
#     """Analyze all URLs found in email text."""
#     urls           = extract_urls(text)
#     url_results    = [analyze_single_url(u) for u in urls[:10]]
#     ...

def analyze_urls(text: str) -> dict:
    """Analyze all URLs found in email text."""
    urls           = extract_urls(text)
    url_results    = [analyze_single_url(u) for u in urls[:10]]
    total_boost    = min(sum(r["risk_boost"] for r in url_results), 40)
    suspicious     = [r for r in url_results if r["risk_boost"] > 0]
    all_flags      = []
    for r in url_results:
        all_flags.extend(r["flags"])

    return {
        "urls_found":      urls,
        "url_count":       len(urls),
        "suspicious_urls": [r["url"] for r in suspicious],
        "url_details":     url_results,
        "risk_boost":      total_boost,
        "flags":           all_flags[:10],
    }


if __name__ == "__main__":
    test_text = """
    Dear User, click here to verify:
    http://sbi-verify-login.xyz/account/update?ref=12345
    Or visit: http://bit.ly/3xYzAbc
    Safe link: https://www.google.com
    IP link: http://192.168.1.1/login
    """
    print("=" * 55)
    print("URL Analyzer Test")
    print("=" * 55)
    result = analyze_urls(test_text)
    print(f"URLs found: {result['url_count']}")
    print(f"Risk boost: +{result['risk_boost']}")
    for url_r in result["url_details"]:
        print(f"\n  URL: {url_r['url'][:60]}")
        print(f"  Risk: +{url_r['risk_boost']}")
        for f in url_r["flags"]:
            print(f"  Flag: {f}")
