"""Quick smoke test for all tools (no API key needed)."""
import json
import sys

def test_all():
    from agent.tools import (
        url_feature_analysis, dns_lookup, cve_lookup,
        email_header_analysis, port_scan, whois_lookup, web_search
    )

    results = []

    # 1. URL feature analysis
    r = json.loads(url_feature_analysis("http://secure-paypal-login.ml/verify"))
    assert r["risk_score"] > 20, f"Expected risk > 20, got {r['risk_score']}"
    assert r["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")
    results.append(f"  url_feature_analysis: score={r['risk_score']}, level={r['risk_level']} OK")

    r2 = json.loads(url_feature_analysis("https://google.com"))
    assert r2["risk_score"] < 20
    results.append(f"  url_feature_analysis (google): score={r2['risk_score']}, level={r2['risk_level']} OK")

    # 2. CVE lookup (network)
    r = json.loads(cve_lookup("CVE-2021-44228"))
    assert r.get("cvss_score") == 10.0, f"Expected 10.0, got {r.get('cvss_score')}"
    results.append(f"  cve_lookup (Log4Shell): CVSS={r['cvss_score']} {r['cvss_severity']} OK")

    r2 = json.loads(cve_lookup("CVE-2024-3094"))
    assert "cve_id" in r2
    results.append(f"  cve_lookup (XZ backdoor): {r2.get('cvss_severity','N/A')} OK")

    # 3. Email header analysis
    sample_email = """From: support@paypa1-secure.tk
Reply-To: hacker@gmail.com
Subject: URGENT: Account suspended
Date: Mon, 6 May 2024 12:00:00 +0000
Received: from spamserver.ru (45.33.32.156)

Click here: http://paypal-login.tk/verify"""
    r = json.loads(email_header_analysis(sample_email))
    assert r["indicator_count"] >= 3
    results.append(f"  email_header_analysis: {r['indicator_count']} indicators, level={r['risk_level']} OK")

    # 4. DNS lookup (network)
    r = json.loads(dns_lookup("google.com"))
    assert r["records"].get("A")
    results.append(f"  dns_lookup (google.com): A={r['records']['A'][:1]} OK")

    # 5. Web search
    r = json.loads(web_search("CVE-2021-44228 log4shell exploit", max_results=3))
    results.append(f"  web_search: {r.get('result_count', 0)} results OK")

    print("=" * 50)
    print("CYBERSENTINEL TOOL TESTS")
    print("=" * 50)
    for res in results:
        print(f"[PASS]{res}")
    print("=" * 50)
    print(f"All {len(results)} tests passed!")
    return True

if __name__ == "__main__":
    try:
        ok = test_all()
        sys.exit(0 if ok else 1)
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
