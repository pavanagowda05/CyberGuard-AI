# ============================================================
# CyberGuard AI — ai/threat_intel.py
# Checks URLs and IPs against threat intelligence APIs:
# - VirusTotal
# - Google Safe Browsing
# - AbuseIPDB
# ============================================================

import os
import sys
import re
import json
import base64
import requests
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    VIRUSTOTAL_API_KEY, GOOGLE_SB_API_KEY,
    ABUSEIPDB_API_KEY, URLHAUS_API_KEY, ALIENVAULT_OTX_KEY,
    THREAT_INTEL_TIMEOUT, THREAT_INTEL_ENABLED
)

# ── VirusTotal ────────────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    try:
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp    = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=THREAT_INTEL_TIMEOUT
        )
        if resp.status_code == 200:
            data  = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1
            risk       = int((malicious + suspicious) / total * 100)
            return {
                "source":     "VirusTotal",
                "checked":    True,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "risk_score": risk,
                "flagged":    malicious > 0 or suspicious > 2,
                "details":    f"{malicious} malicious, {suspicious} suspicious out of {total} engines",
            }
        elif resp.status_code == 404:
            # URL not in VT database — submit for scanning
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=THREAT_INTEL_TIMEOUT
            )
            return {
                "source":  "VirusTotal",
                "checked": True,
                "flagged": False,
                "details": "URL submitted to VirusTotal for scanning — not in database yet",
                "risk_score": 0,
            }
        else:
            return {"source": "VirusTotal", "checked": False,
                    "flagged": False, "risk_score": 0,
                    "details": f"API error {resp.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "checked": False,
                "flagged": False, "risk_score": 0,
                "details": f"Error: {str(e)[:100]}"}


# ── Google Safe Browsing ──────────────────────────────────────
def check_google_safe_browsing(urls: list) -> dict:
    try:
        payload = {
            "client": {"clientId": "cyberguard-ai", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": u} for u in urls[:5]],
            }
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_API_KEY}",
            json=payload, timeout=THREAT_INTEL_TIMEOUT
        )
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            flagged_urls = [m.get("threat", {}).get("url", "") for m in matches]
            return {
                "source":       "Google Safe Browsing",
                "checked":      True,
                "flagged":      len(matches) > 0,
                "flagged_urls": flagged_urls,
                "risk_score":   30 if matches else 0,
                "details":      f"{len(matches)} URL(s) flagged by Google Safe Browsing",
            }
        else:
            return {"source": "Google Safe Browsing", "checked": False,
                    "flagged": False, "risk_score": 0,
                    "details": f"API error {resp.status_code}"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "checked": False,
                "flagged": False, "risk_score": 0,
                "details": f"Error: {str(e)[:100]}"}


# ── AbuseIPDB ─────────────────────────────────────────────────
def check_abuseipdb(ip: str) -> dict:
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        resp    = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=THREAT_INTEL_TIMEOUT
        )
        if resp.status_code == 200:
            data       = resp.json().get("data", {})
            score      = data.get("abuseConfidenceScore", 0)
            reports    = data.get("totalReports", 0)
            country    = data.get("countryCode", "Unknown")
            isp        = data.get("isp", "Unknown")
            return {
                "source":       "AbuseIPDB",
                "checked":      True,
                "flagged":      score > 25,
                "abuse_score":  score,
                "total_reports":reports,
                "country":      country,
                "isp":          isp,
                "risk_score":   min(score // 2, 30),
                "details":      f"IP abuse score: {score}/100, {reports} reports, ISP: {isp}",
            }
        else:
            return {"source": "AbuseIPDB", "checked": False,
                    "flagged": False, "risk_score": 0,
                    "details": f"API error {resp.status_code}"}
    except Exception as e:
        return {"source": "AbuseIPDB", "checked": False,
                "flagged": False, "risk_score": 0,
                "details": f"Error: {str(e)[:100]}"}
    
OTX_TIMEOUT = 25  # measured OTX round-trip ~15.5s in practice; shared 8s timeout was too short

def check_alienvault_otx(url: str) -> dict:
    """AlienVault OTX — checks URL against threat intelligence pulses."""
    try:
        domain = url.split("/")[2] if "//" in url else url.split("/")[0]
        headers = {"X-OTX-API-KEY": ALIENVAULT_OTX_KEY}
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=OTX_TIMEOUT
        )
        if resp.status_code == 200:
            data       = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "source":      "AlienVault OTX",
                "checked":     True,
                "flagged":     pulse_count > 0,
                "pulse_count": pulse_count,
                "risk_score":  min(pulse_count * 5, 25),
                "details":     f"{pulse_count} threat intelligence pulse(s) reference this domain"
                               if pulse_count > 0 else "No threat pulses found for this domain",
            }
        return {"source": "AlienVault OTX", "checked": False, "flagged": False,
                "risk_score": 0, "details": f"API error {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"source": "AlienVault OTX", "checked": False, "flagged": False,
                "risk_score": 0, "details": "OTX did not respond in time — treated as unknown, not clean"}
    except requests.exceptions.RequestException as e:
        return {"source": "AlienVault OTX", "checked": False, "flagged": False,
                "risk_score": 0, "details": f"OTX request failed: {str(e)[:100]}"}
def check_urlhaus(url: str) -> dict:
    """URLhaus — free malware URL database, requires Auth-Key."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": URLHAUS_API_KEY},
            timeout=THREAT_INTEL_TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                return {
                    "source":     "URLhaus",
                    "checked":    True,
                    "flagged":    True,
                    "risk_score": 35,
                    "details":    f"URL found in URLhaus malware database — threat: {data.get('threat', 'unknown')}",
                }
            else:
                return {
                    "source":     "URLhaus",
                    "checked":    True,
                    "flagged":    False,
                    "risk_score": 0,
                    "details":    "URL not found in URLhaus malware database",
                }
        return {"source": "URLhaus", "checked": False, "flagged": False,
                "risk_score": 0, "details": f"API error {resp.status_code}"}
    except Exception as e:
        return {"source": "URLhaus", "checked": False, "flagged": False,
                "risk_score": 0, "details": f"Error: {str(e)[:100]}"}
    


# ── Extract IPs from text ─────────────────────────────────────
def extract_ips(text: str) -> list:
    pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return list(set(pattern.findall(text)))


# ── Main threat intel check ───────────────────────────────────
def run_threat_intel(urls: list, email_text: str = "") -> dict:
    if not THREAT_INTEL_ENABLED:
        return {"enabled": False, "results": [], "total_risk_boost": 0}

    results    = []
    risk_boost = 0

    if urls:
        vt_result = check_virustotal(urls[0])
        results.append(vt_result)
        if vt_result.get("flagged"):
            risk_boost += 30

        # ADD THIS
        urlhaus_result = check_urlhaus(urls[0])
        results.append(urlhaus_result)
        if urlhaus_result.get("flagged"):
            risk_boost += 25

        # ADD THIS 
       
        import time
        time.sleep(2)
        otx_result = check_alienvault_otx(urls[0])
        results.append(otx_result)
        if otx_result.get("flagged"):
            risk_boost += 8
        

    if urls:
        gsb_result = check_google_safe_browsing(urls)
        results.append(gsb_result)
        if gsb_result.get("flagged"):
            risk_boost += 25

    ips = extract_ips(email_text)
    if ips:
        ip_result = check_abuseipdb(ips[0])
        results.append(ip_result)
        if ip_result.get("flagged"):
            risk_boost += 20

    flagged_sources = [r["source"] for r in results if r.get("flagged")]

    return {
        "enabled":         True,
        "results":         results,
        "flagged_sources": flagged_sources,
        "total_risk_boost": min(risk_boost, 40),
        "any_flagged":     len(flagged_sources) > 0,
    }


if __name__ == "__main__":
    print("=" * 55)
    print("Threat Intel Test")
    print("=" * 55)
    result = run_threat_intel(
        urls=["http://malware.testing.google.test/testing/malware/"],
        email_text="Check this link and IP 192.168.1.1"
    )
    print(f"Any flagged: {result['any_flagged']}")
    print(f"Risk boost : +{result['total_risk_boost']}")
    for r in result["results"]:
        print(f"\n  Source  : {r['source']}")
        print(f"  Checked : {r['checked']}")
        print(f"  Flagged : {r.get('flagged', False)}")
        print(f"  Details : {r.get('details', '')}")
