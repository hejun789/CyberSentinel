import json
import re
import socket
import urllib.parse
import email as email_lib
import email.header
from datetime import datetime, timezone

import requests
import dns.resolver
import whois as whois_lib

from config import VIRUSTOTAL_API_KEY, TOOL_TIMEOUT, PORT_SCAN_TIMEOUT, COMMON_PORTS

# ─────────────────────────────────────────────────────────────────────────────
# Tool Schemas (JSON Schema definitions for Claude API)
# ─────────────────────────────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "whois_lookup",
        "description": (
            "Perform a WHOIS lookup on a domain to retrieve registration information "
            "including registrar, creation/expiration dates, registrant country, and "
            "name servers. Useful for identifying domain age, ownership, and legitimacy."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain name to look up (e.g., 'example.com'). Do not include http:// prefix."
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "dns_lookup",
        "description": (
            "Perform DNS lookups on a domain to retrieve A records (IP addresses), "
            "MX records (mail servers), NS records (name servers), TXT records (SPF/DMARC), "
            "and CNAME records. Useful for mapping infrastructure and checking email security."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain name to query (e.g., 'example.com')."
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "url_feature_analysis",
        "description": (
            "Analyze a URL or domain for 24 phishing/malicious indicators including "
            "URL length, suspicious TLDs, IP-based URLs, suspicious keywords, URL shorteners, "
            "excessive subdomains, and more. Returns a 0-100 phishing risk score and feature breakdown."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The full URL or domain to analyze (e.g., 'http://suspicious-login.tk/paypal')."
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "web_search",
        "description": (
            "Search the web for threat intelligence, reputation data, and security reports "
            "about a target. Use specific queries like '[domain] malicious threat intel', "
            "'[CVE-ID] exploit proof of concept', or '[IP] abuse reports'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query for threat intelligence gathering."
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 5, max: 10).",
                    "default": 5
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "cve_lookup",
        "description": (
            "Look up details for a CVE (Common Vulnerabilities and Exposures) ID from the "
            "NIST National Vulnerability Database (NVD). Returns description, CVSS score, "
            "severity rating, affected products, and publication date."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier (e.g., 'CVE-2024-3094' or 'CVE-2021-44228')."
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "port_scan",
        "description": (
            "Perform a basic TCP port scan on a domain or IP address to identify open services. "
            "Checks common ports including HTTP (80), HTTPS (443), SSH (22), FTP (21), "
            "MySQL (3306), RDP (3389), Redis (6379), MongoDB (27017), and more. "
            "Open unexpected ports may indicate misconfiguration or compromise."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address or domain name to scan (e.g., '192.168.1.1' or 'example.com')."
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "email_header_analysis",
        "description": (
            "Analyze raw email text (with headers) for phishing indicators. Extracts and "
            "examines From, Reply-To, Return-Path, Received chain, Subject, and body URLs. "
            "Detects header spoofing, authentication failures, and social engineering keywords."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "email_text": {
                    "type": "string",
                    "description": "Raw email text including headers and body content."
                }
            },
            "required": ["email_text"]
        }
    },
    {
        "name": "virustotal_lookup",
        "description": (
            "Query VirusTotal for reputation data on a domain, IP, URL, or file hash. "
            "Returns detection counts from 70+ antivirus engines and security vendors. "
            "NOTE: Requires VIRUSTOTAL_API_KEY to be configured — will skip gracefully if not set."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain, IP address, or URL to check on VirusTotal."
                },
                "target_type": {
                    "type": "string",
                    "enum": ["domain", "ip", "url"],
                    "description": "Type of target: 'domain', 'ip', or 'url'."
                }
            },
            "required": ["target", "target_type"]
        }
    }
]


# ─────────────────────────────────────────────────────────────────────────────
# Tool Implementations
# ─────────────────────────────────────────────────────────────────────────────

def _safe_str(value) -> str:
    """Convert whois values (which may be lists or None) to clean strings."""
    if value is None:
        return "Unknown"
    if isinstance(value, list):
        value = value[0] if value else "Unknown"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value).strip() or "Unknown"


def whois_lookup(domain: str) -> str:
    """Return WHOIS registration data for a domain."""
    # Strip protocol/path if accidentally included
    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()

    try:
        w = whois_lib.whois(domain)

        creation = _safe_str(w.creation_date)
        expiration = _safe_str(w.expiration_date)
        updated = _safe_str(w.updated_date)

        # Calculate domain age
        age_days = None
        try:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if cd and isinstance(cd, datetime):
                if cd.tzinfo is None:
                    cd = cd.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - cd).days
        except Exception:
            pass

        ns = w.name_servers
        if isinstance(ns, list):
            ns = [str(n).lower() for n in ns]
        elif ns:
            ns = [str(ns).lower()]
        else:
            ns = []

        result = {
            "domain": domain,
            "registrar": _safe_str(w.registrar),
            "creation_date": creation,
            "expiration_date": expiration,
            "updated_date": updated,
            "domain_age_days": age_days,
            "registrant_country": _safe_str(w.country),
            "registrant_org": _safe_str(w.org),
            "name_servers": ns[:6],
            "status": _safe_str(w.status),
            "dnssec": _safe_str(getattr(w, 'dnssec', None)),
        }

        if age_days is not None:
            if age_days < 30:
                result["age_warning"] = "CRITICAL: Domain registered within last 30 days"
            elif age_days < 180:
                result["age_warning"] = "WARNING: Domain registered within last 6 months"

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"WHOIS lookup failed: {str(e)}", "domain": domain})


def dns_lookup(domain: str) -> str:
    """Return DNS records for a domain."""
    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()

    results = {"domain": domain, "records": {}}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=TOOL_TIMEOUT)
            if rtype == "MX":
                results["records"][rtype] = [
                    {"preference": r.preference, "exchange": str(r.exchange)}
                    for r in answers
                ]
            elif rtype == "TXT":
                txt_records = [r.to_text().strip('"') for r in answers]
                results["records"][rtype] = txt_records
                # Parse SPF/DMARC
                for txt in txt_records:
                    if txt.startswith("v=spf1"):
                        results["spf_record"] = txt
                    if txt.startswith("v=DMARC1"):
                        results["dmarc_record"] = txt
            else:
                results["records"][rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            results["records"][rtype] = "NXDOMAIN — domain does not exist"
        except dns.resolver.NoAnswer:
            results["records"][rtype] = None
        except Exception as e:
            results["records"][rtype] = f"Error: {str(e)}"

    # Security observations
    observations = []
    if not results.get("spf_record"):
        observations.append("No SPF record found — domain may be used for email spoofing")
    if not results.get("dmarc_record"):
        observations.append("No DMARC record found — no email authentication policy")
    if results["records"].get("A") and isinstance(results["records"]["A"], list):
        for ip in results["records"]["A"]:
            # Check for private/reserved ranges
            if ip.startswith(("10.", "192.168.", "172.", "127.")):
                observations.append(f"Private IP address in A record: {ip}")

    if observations:
        results["security_observations"] = observations

    return json.dumps(results, indent=2)


# Phishing feature analysis constants
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".download", ".link", ".win", ".loan", ".racing",
    ".review", ".science", ".party", ".gdn", ".men", ".date",
    ".faith", ".bid", ".trade", ".stream", ".accountant"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "banking", "paypal",
    "ebay", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "password", "credential", "wallet",
    "crypto", "bitcoin", "urgent", "suspended", "alert", "limited"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bc.vc", "u.to", "j.mp", "shorte.st",
    "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at"
}

SUSPICIOUS_BRANDS_IN_SUBDOMAIN = [
    "paypal", "amazon", "google", "facebook", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "ebay",
    "bankofamerica", "chase", "wellsfargo", "citibank"
]


def url_feature_analysis(url: str) -> str:
    """Extract 24 phishing features from a URL and compute risk score."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return json.dumps({"error": f"Invalid URL: {str(e)}"})

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url.lower()

    features = {}

    # 1. URL length
    features["url_length"] = len(url)
    features["url_length_risk"] = "HIGH" if len(url) > 75 else "MEDIUM" if len(url) > 54 else "LOW"

    # 2. Hostname length
    features["hostname_length"] = len(hostname)

    # 3. Path length
    features["path_length"] = len(path)

    # 4. Has IP address instead of domain
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$|'
        r'^0x[0-9a-fA-F]+$|'
        r'^\d+\.\d+$'
    )
    features["has_ip_address"] = bool(ip_pattern.match(hostname))

    # 5. Has HTTPS
    features["has_https"] = parsed.scheme == "https"

    # 6. Non-standard port
    port = parsed.port
    features["non_standard_port"] = port not in (None, 80, 443) if port else False
    features["port"] = port

    # 7. Suspicious TLD
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    features["tld"] = tld
    features["suspicious_tld"] = tld.lower() in SUSPICIOUS_TLDS

    # 8. Has @ symbol (attacker hides real hostname after @)
    features["has_at_symbol"] = "@" in url

    # 9. Number of dots in hostname
    features["num_dots"] = hostname.count(".")

    # 10. Number of hyphens in domain
    features["num_hyphens"] = hostname.count("-")

    # 11. Number of underscores
    features["num_underscores"] = url.count("_")

    # 12. Number of slashes
    features["num_slashes"] = url.count("/")

    # 13. Number of query parameters
    features["num_query_params"] = len(urllib.parse.parse_qs(query))

    # 14. Has double slash in path (redirect indicator)
    features["has_double_slash_path"] = "//" in path

    # 15. Has redirect parameter
    redirect_params = ["redirect", "url", "return", "returnurl", "goto", "next", "redir"]
    query_keys = [k.lower() for k in urllib.parse.parse_qs(query).keys()]
    features["has_redirect_param"] = any(k in redirect_params for k in query_keys)

    # 16. Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    features["suspicious_keywords"] = found_keywords
    features["has_suspicious_keywords"] = len(found_keywords) > 0

    # 17. URL shortener
    features["is_url_shortener"] = hostname.lower() in URL_SHORTENERS

    # 18. Excessive subdomains (more than 3)
    subdomain_parts = hostname.split(".")
    features["subdomain_count"] = max(0, len(subdomain_parts) - 2)
    features["excessive_subdomains"] = len(subdomain_parts) > 4

    # 19. Brand name in subdomain (typosquatting indicator)
    subdomain = ".".join(subdomain_parts[:-2]) if len(subdomain_parts) > 2 else ""
    found_brands = [brand for brand in SUSPICIOUS_BRANDS_IN_SUBDOMAIN if brand in subdomain.lower()]
    features["brand_in_subdomain"] = found_brands

    # 20. Number of digits in hostname
    features["num_digits_in_hostname"] = sum(c.isdigit() for c in hostname)

    # 21. Prefix-suffix in domain (hyphens indicate fake domain)
    domain_main = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
    features["domain_has_hyphen"] = "-" in domain_main

    # 22. Long query string
    features["long_query_string"] = len(query) > 100

    # 23. HTTPS token in domain name (phishers add 'https' to domain name)
    features["https_in_domain"] = "https" in hostname.lower()

    # 24. Abnormal URL (brand in domain but not official TLD)
    features["abnormal_url_structure"] = (
        any(brand in hostname.lower() for brand in SUSPICIOUS_BRANDS_IN_SUBDOMAIN)
        and tld not in [".com", ".org", ".net", ".gov", ".edu"]
    )

    # ── Risk Score Calculation ──────────────────────────────────────────────
    score = 0
    weights = {
        "has_ip_address": 20,
        "suspicious_tld": 15,
        "has_at_symbol": 15,
        "is_url_shortener": 12,
        "brand_in_subdomain": 10,  # non-zero list = truthy
        "has_suspicious_keywords": 8,
        "excessive_subdomains": 7,
        "domain_has_hyphen": 5,
        "https_in_domain": 8,
        "abnormal_url_structure": 10,
        "has_double_slash_path": 5,
        "has_redirect_param": 5,
        "non_standard_port": 6,
        "long_query_string": 3,
    }
    for feature, weight in weights.items():
        val = features.get(feature)
        if val:  # truthy: True, non-empty list/string
            score += weight

    # URL length bonus
    if features["url_length"] > 75:
        score += 6
    elif features["url_length"] > 54:
        score += 3

    # No HTTPS penalty (minor — phishing sites use HTTPS too)
    if not features["has_https"]:
        score += 4

    score = min(score, 100)

    if score >= 70:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    elif score >= 10:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return json.dumps({
        "url": url,
        "hostname": hostname,
        "tld": tld,
        "risk_score": score,
        "risk_level": risk_level,
        "features": features,
        "top_risk_factors": [
            k for k, w in sorted(weights.items(), key=lambda x: -x[1])
            if features.get(k)
        ][:5]
    }, indent=2)


def web_search(query: str, max_results: int = 5) -> str:
    """Search DuckDuckGo for threat intelligence."""
    max_results = min(int(max_results), 10)
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
        with DDGS() as ddgs:
            raw = list(ddgs.text(query, max_results=max_results))

        results = []
        for r in raw:
            results.append({
                "title": r.get("title", ""),
                "url": r.get("href", ""),
                "snippet": r.get("body", "")[:300]
            })

        return json.dumps({
            "query": query,
            "result_count": len(results),
            "results": results
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "query": query,
            "error": f"Web search failed: {str(e)}",
            "note": "Search unavailable — continue investigation with other tools"
        })


def cve_lookup(cve_id: str) -> str:
    """Fetch CVE details from the NIST NVD API v2.0."""
    cve_id = cve_id.strip().upper()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return json.dumps({"error": f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNNN"})

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        resp = requests.get(url, timeout=TOOL_TIMEOUT, headers={"User-Agent": "CyberSentinel/1.0"})
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return json.dumps({"error": f"CVE {cve_id} not found in NVD database"})

        cve = vulns[0]["cve"]

        # Extract English description
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description available"
        )

        # Extract CVSS scores (try v3.1, then v3.0, then v2)
        cvss_score = None
        cvss_severity = None
        cvss_version = None
        metrics = cve.get("metrics", {})

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version_key in metrics and metrics[version_key]:
                m = metrics[version_key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity") or m.get("baseSeverity")
                cvss_version = cvss_data.get("version", version_key)
                break

        # Extract affected products (CPE)
        affected_products = []
        for config in cve.get("configurations", [])[:3]:
            for node in config.get("nodes", [])[:3]:
                for cpe_match in node.get("cpeMatch", [])[:3]:
                    cpe = cpe_match.get("criteria", "")
                    # Parse CPE: cpe:2.3:a:vendor:product:version
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        affected_products.append(f"{parts[3]} {parts[4]} {parts[5] if len(parts) > 5 else ''}")

        # References
        references = [
            {"url": r.get("url", ""), "tags": r.get("tags", [])}
            for r in cve.get("references", [])[:5]
        ]

        # Severity classification
        if cvss_score:
            if cvss_score >= 9.0:
                risk_label = "CRITICAL — Patch immediately"
            elif cvss_score >= 7.0:
                risk_label = "HIGH — Patch within 30 days"
            elif cvss_score >= 4.0:
                risk_label = "MEDIUM — Patch in next cycle"
            else:
                risk_label = "LOW — Monitor and patch"
        else:
            risk_label = "Severity not available"

        return json.dumps({
            "cve_id": cve_id,
            "description": description,
            "published": cve.get("published", "Unknown"),
            "last_modified": cve.get("lastModified", "Unknown"),
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_version": cvss_version,
            "risk_label": risk_label,
            "affected_products": affected_products[:5],
            "references": references,
            "weaknesses": [
                w.get("description", [{}])[0].get("value", "")
                for w in cve.get("weaknesses", [])[:3]
                if w.get("description")
            ]
        }, indent=2)

    except requests.exceptions.Timeout:
        return json.dumps({"error": "NVD API request timed out. Try again later.", "cve_id": cve_id})
    except requests.exceptions.HTTPError as e:
        return json.dumps({"error": f"NVD API HTTP error: {str(e)}", "cve_id": cve_id})
    except Exception as e:
        return json.dumps({"error": f"CVE lookup failed: {str(e)}", "cve_id": cve_id})


def port_scan(target: str) -> str:
    """Scan common ports on a target host."""
    target = re.sub(r'^https?://', '', target).split('/')[0].strip()

    # Resolve hostname to IP
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return json.dumps({"error": f"Cannot resolve host '{target}': {str(e)}"})

    open_ports = []
    closed_ports = []
    service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    risk_ports = {3389, 3306, 5900, 1433, 27017, 6379, 23, 445}

    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            result = sock.connect_ex((resolved_ip, port))
            sock.close()

            service = service_map.get(port, "Unknown")
            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": service,
                    "risk": "HIGH" if port in risk_ports else "NORMAL"
                })
            else:
                closed_ports.append(port)
        except Exception:
            closed_ports.append(port)

    risk_open = [p for p in open_ports if p["risk"] == "HIGH"]
    observations = []
    if any(p["port"] == 3389 for p in open_ports):
        observations.append("RDP (3389) exposed — risk of brute-force attacks")
    if any(p["port"] == 6379 for p in open_ports):
        observations.append("Redis (6379) exposed — often unauthenticated, high exploitation risk")
    if any(p["port"] == 27017 for p in open_ports):
        observations.append("MongoDB (27017) exposed — check authentication is enabled")
    if any(p["port"] == 3306 for p in open_ports):
        observations.append("MySQL (3306) exposed publicly — database should not be internet-facing")
    if any(p["port"] == 23 for p in open_ports):
        observations.append("Telnet (23) open — unencrypted protocol, replace with SSH")
    if any(p["port"] == 5900 for p in open_ports):
        observations.append("VNC (5900) exposed — remote desktop risk")

    return json.dumps({
        "target": target,
        "resolved_ip": resolved_ip,
        "open_ports": open_ports,
        "closed_port_count": len(closed_ports),
        "high_risk_ports": risk_open,
        "security_observations": observations,
        "scan_summary": f"{len(open_ports)} open ports found out of {len(COMMON_PORTS)} scanned"
    }, indent=2)


def email_header_analysis(email_text: str) -> str:
    """Analyze email headers and body for phishing indicators."""
    results = {
        "headers": {},
        "routing": [],
        "urls_found": [],
        "phishing_indicators": [],
        "authentication": {}
    }

    try:
        msg = email_lib.message_from_string(email_text)

        # Extract key headers
        def decode_header_value(value):
            if not value:
                return None
            try:
                decoded_parts = email.header.decode_header(value)
                parts = []
                for part, charset in decoded_parts:
                    if isinstance(part, bytes):
                        parts.append(part.decode(charset or "utf-8", errors="replace"))
                    else:
                        parts.append(part)
                return " ".join(parts)
            except Exception:
                return str(value)

        results["headers"] = {
            "from": decode_header_value(msg.get("From")),
            "reply_to": decode_header_value(msg.get("Reply-To")),
            "return_path": decode_header_value(msg.get("Return-Path")),
            "to": decode_header_value(msg.get("To")),
            "subject": decode_header_value(msg.get("Subject")),
            "date": decode_header_value(msg.get("Date")),
            "message_id": decode_header_value(msg.get("Message-ID")),
            "x_mailer": decode_header_value(msg.get("X-Mailer")),
            "mime_version": decode_header_value(msg.get("MIME-Version")),
        }

        # Authentication results
        auth_results = msg.get("Authentication-Results", "")
        dkim = msg.get("DKIM-Signature", "")
        spf_result = re.search(r'spf=(\w+)', auth_results or "", re.I)
        dkim_result = re.search(r'dkim=(\w+)', auth_results or "", re.I)
        dmarc_result = re.search(r'dmarc=(\w+)', auth_results or "", re.I)

        results["authentication"] = {
            "spf": spf_result.group(1) if spf_result else ("present" if "v=spf1" in email_text else "not_found"),
            "dkim": dkim_result.group(1) if dkim_result else ("present" if dkim else "not_found"),
            "dmarc": dmarc_result.group(1) if dmarc_result else "not_found",
        }

        # Received chain
        received_headers = msg.get_all("Received") or []
        for rcv in received_headers[:5]:
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', rcv)
            from_match = re.search(r'from\s+(\S+)', rcv, re.I)
            results["routing"].append({
                "raw": rcv[:150],
                "ip": ip_match.group(1) if ip_match else None,
                "from_host": from_match.group(1) if from_match else None
            })

        # Extract body text
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        body += part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
            except Exception:
                body = str(msg.get_payload())

        # Extract URLs from body
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.I)
        urls = list(set(url_pattern.findall(body + email_text)))[:15]
        results["urls_found"] = urls

        # Extract domains from email addresses
        def extract_domain(email_addr):
            if email_addr:
                m = re.search(r'@([\w.-]+)', str(email_addr))
                return m.group(1).lower() if m else None
            return None

        from_domain = extract_domain(results["headers"].get("from"))
        reply_domain = extract_domain(results["headers"].get("reply_to"))
        return_domain = extract_domain(results["headers"].get("return_path"))
        results["extracted_domains"] = list(filter(None, set([from_domain, reply_domain, return_domain])))

        # ── Phishing Indicator Analysis ────────────────────────────────────
        indicators = []

        # Mismatch between From and Reply-To domains
        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(f"Domain mismatch: From={from_domain} but Reply-To={reply_domain} — classic spoofing indicator")

        # Authentication failures
        if results["authentication"].get("spf") in ("fail", "softfail", "not_found"):
            indicators.append(f"SPF check: {results['authentication']['spf']} — sender may not be authorized")
        if results["authentication"].get("dkim") in ("fail", "not_found"):
            indicators.append("DKIM: not found or failed — email integrity not verified")
        if results["authentication"].get("dmarc") in ("fail", "not_found"):
            indicators.append("DMARC: not found or failed — no domain-level email policy enforced")

        # Subject line urgency
        subject = results["headers"].get("subject") or ""
        urgency_words = ["urgent", "immediate", "verify", "suspended", "account", "alert",
                         "action required", "limited time", "click now", "confirm"]
        found_urgency = [w for w in urgency_words if w.lower() in subject.lower()]
        if found_urgency:
            indicators.append(f"Urgency/social engineering in subject: '{subject}' — keywords: {found_urgency}")

        # Suspicious sender domain
        if from_domain:
            fake_tld = "." + from_domain.split(".")[-1]
            if fake_tld in SUSPICIOUS_TLDS:
                indicators.append(f"Sender domain uses suspicious TLD: {from_domain}")

        # URLs in email
        suspicious_urls = []
        for url in urls[:5]:
            url_lower = url.lower()
            if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS[:10]):
                suspicious_urls.append(url)
        if suspicious_urls:
            indicators.append(f"Suspicious URLs in body: {suspicious_urls[:3]}")

        # Message-ID format
        msg_id = results["headers"].get("message_id") or ""
        if msg_id and not re.search(r'@[\w.-]+\.\w{2,}', msg_id):
            indicators.append(f"Malformed Message-ID: {msg_id} — may indicate automated phishing tool")

        results["phishing_indicators"] = indicators
        results["indicator_count"] = len(indicators)
        results["risk_level"] = (
            "CRITICAL" if len(indicators) >= 4
            else "HIGH" if len(indicators) >= 3
            else "MEDIUM" if len(indicators) >= 2
            else "LOW" if len(indicators) >= 1
            else "SAFE"
        )

    except Exception as e:
        results["error"] = f"Email parsing error: {str(e)}"

    return json.dumps(results, indent=2)


def virustotal_lookup(target: str, target_type: str) -> str:
    """Query VirusTotal API for reputation data."""
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({
            "status": "skipped",
            "reason": "VIRUSTOTAL_API_KEY not configured in .env file",
            "note": "Add your free VirusTotal API key to enable this check (https://www.virustotal.com)"
        })

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    base = "https://www.virustotal.com/api/v3"

    try:
        if target_type == "domain":
            url = f"{base}/domains/{target}"
        elif target_type == "ip":
            url = f"{base}/ip_addresses/{target}"
        elif target_type == "url":
            import base64 as b64
            url_id = b64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
            url = f"{base}/urls/{url_id}"
        else:
            return json.dumps({"error": f"Unknown target_type: {target_type}"})

        resp = requests.get(url, headers=headers, timeout=TOOL_TIMEOUT)

        if resp.status_code == 404:
            return json.dumps({"target": target, "status": "not_found", "message": "Target not in VirusTotal database"})
        if resp.status_code == 401:
            return json.dumps({"error": "Invalid VirusTotal API key"})
        if resp.status_code == 429:
            return json.dumps({"error": "VirusTotal API rate limit exceeded — try again later"})

        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Get names of detecting engines
        detections = [
            {"engine": name, "result": res.get("result", ""), "category": res.get("category", "")}
            for name, res in attrs.get("last_analysis_results", {}).items()
            if res.get("category") in ("malicious", "suspicious")
        ][:10]

        result = {
            "target": target,
            "target_type": target_type,
            "detection_ratio": f"{malicious}/{total}" if total else "0/0",
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "harmless_detections": harmless,
            "total_engines": total,
            "reputation": attrs.get("reputation", 0),
            "detecting_engines": detections,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "categories": attrs.get("categories", {}),
            "tags": attrs.get("tags", []),
        }

        if malicious >= 10:
            result["verdict"] = "MALICIOUS — widely detected"
        elif malicious >= 3:
            result["verdict"] = "LIKELY MALICIOUS — multiple engines flagged"
        elif malicious >= 1 or suspicious >= 3:
            result["verdict"] = "SUSPICIOUS — low detection, investigate further"
        else:
            result["verdict"] = "CLEAN — no significant detections"

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"VirusTotal lookup failed: {str(e)}", "target": target})


# ─────────────────────────────────────────────────────────────────────────────
# Tool Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

_TOOL_MAP = {
    "whois_lookup": lambda inp: whois_lookup(inp["domain"]),
    "dns_lookup": lambda inp: dns_lookup(inp["domain"]),
    "url_feature_analysis": lambda inp: url_feature_analysis(inp["url"]),
    "web_search": lambda inp: web_search(inp["query"], inp.get("max_results", 5)),
    "cve_lookup": lambda inp: cve_lookup(inp["cve_id"]),
    "port_scan": lambda inp: port_scan(inp["target"]),
    "email_header_analysis": lambda inp: email_header_analysis(inp["email_text"]),
    "virustotal_lookup": lambda inp: virustotal_lookup(inp["target"], inp["target_type"]),
}


def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Dispatch a tool call by name and return the JSON result string."""
    handler = _TOOL_MAP.get(tool_name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        return handler(tool_input)
    except Exception as e:
        return json.dumps({"error": f"Tool '{tool_name}' raised an exception: {str(e)}"})
