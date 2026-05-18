"""Cross-investigation memory: search past investigations for related context."""

import json
import os
import re

from config import HISTORY_FILE


def search_memory(target: str) -> str:
    """
    Search history for investigations related to this target.
    Returns a formatted context string to prepend to the agent prompt,
    or an empty string if nothing relevant is found.
    """
    history = _load_history()
    if not history:
        return ""

    target_lower = target.lower()
    target_words = set(_extract_keywords(target_lower))

    matches = []
    for entry in history:
        score, reasons = _score_entry(entry, target_lower, target_words)
        if score > 0:
            matches.append((score, reasons, entry))

    if not matches:
        return ""

    matches.sort(key=lambda x: x[0], reverse=True)
    top = matches[:3]

    lines = ["=== MEMORY CONTEXT — Related past investigations found ==="]
    for i, (score, reasons, entry) in enumerate(top, 1):
        lines.append(f"\n[Past Investigation {i}]")
        lines.append(f"Target: {entry.get('target', '')[:200]}")
        lines.append(f"Threat Level: {entry.get('threat_level', 'UNKNOWN')}")
        lines.append(f"Type: {entry.get('target_type', 'Unknown')}")
        lines.append(f"Date: {entry.get('timestamp', '')[:10]}")
        lines.append(f"Summary: {entry.get('executive_summary', '')[:300]}")
        lines.append(f"Relevance: {', '.join(reasons)}")

        iocs = entry.get("iocs") or {}
        ioc_parts = []
        for key in ("malicious_ips", "malicious_domains", "malicious_urls",
                    "cve_ids", "suspicious_emails", "threat_actors"):
            vals = iocs.get(key) or []
            if vals:
                ioc_parts.append(f"{key}: {', '.join(str(v) for v in vals[:5])}")
        if ioc_parts:
            lines.append("Past IOCs: " + " | ".join(ioc_parts))

    lines.append("\n=== Use these past findings to enrich your current investigation ===\n")
    return "\n".join(lines)


def _load_history() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _extract_keywords(text: str) -> list:
    tokens = re.split(r'[^a-z0-9]+', text.lower())
    return [t for t in tokens if len(t) > 4]


def _get_root_domain(text: str) -> str:
    """Extract root domain (e.g., 'evil.com' from 'sub.evil.com/path')."""
    text = re.sub(r'^https?://', '', text)
    text = text.split('/')[0].split('?')[0].split(':')[0]
    parts = text.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return text


_SUSPICIOUS_TLDS = frozenset({
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.pw',
    '.cc', '.su', '.online', '.site', '.click', '.loan', '.win',
})

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)


def _score_entry(entry: dict, target_lower: str, target_words: set) -> tuple:
    score = 0
    reasons = []

    past_target = entry.get("target", "").lower()

    if target_lower and past_target:
        t_root = _get_root_domain(target_lower)
        p_root = _get_root_domain(past_target)
        if t_root and p_root and t_root == p_root and len(t_root) > 4:
            score += 10
            reasons.append(f"same domain: {t_root}")
        elif target_lower in past_target or past_target in target_lower:
            score += 5
            reasons.append("target substring match")

    # CVE match
    target_cves = {m.upper() for m in _CVE_RE.findall(target_lower)}
    if target_cves:
        past_cves = {m.upper() for m in _CVE_RE.findall(past_target)}
        ioc_cves = {str(c).upper() for c in (entry.get("iocs") or {}).get("cve_ids", [])}
        for cve in target_cves:
            if cve in past_cves:
                score += 10
                reasons.append(f"same CVE: {cve}")
            elif cve in ioc_cves:
                score += 5
                reasons.append(f"CVE in past IOCs: {cve}")

    # IP overlap in IOCs
    target_ips = set(_IP_RE.findall(target_lower))
    iocs = entry.get("iocs") or {}
    past_ips = set(iocs.get("malicious_ips") or [])
    overlap_ips = target_ips & past_ips
    if overlap_ips:
        score += 8
        reasons.append(f"shared IPs: {', '.join(list(overlap_ips)[:3])}")

    # Domain overlap in IOCs
    past_domains = {d.lower() for d in (iocs.get("malicious_domains") or [])}
    t_root = _get_root_domain(target_lower)
    if t_root and any(t_root in d for d in past_domains):
        score += 6
        reasons.append(f"domain in past IOCs: {t_root}")

    # Shared suspicious TLD — compare root domains so URLs like
    # "http://evil.tk/path" are matched the same as plain "evil.tk"
    t_domain = _get_root_domain(target_lower)
    p_domain  = _get_root_domain(past_target)
    for tld in _SUSPICIOUS_TLDS:
        if t_domain.endswith(tld) and p_domain.endswith(tld):
            score += 2
            reasons.append(f"same suspicious TLD: {tld}")
            break

    # Keyword overlap
    past_words = set(_extract_keywords(past_target))
    meaningful = {w for w in (target_words & past_words) if len(w) > 5}
    if meaningful:
        score += len(meaningful)
        reasons.append(f"shared keywords: {', '.join(list(meaningful)[:3])}")

    return score, reasons
