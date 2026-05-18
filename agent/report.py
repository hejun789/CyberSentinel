import re
from datetime import datetime, timezone


THREAT_COLORS = {
    "CRITICAL": {"bg": "#ff0033", "text": "#ffffff", "glow": "#ff003380"},
    "HIGH":     {"bg": "#ff6600", "text": "#ffffff", "glow": "#ff660080"},
    "MEDIUM":   {"bg": "#ffaa00", "text": "#000000", "glow": "#ffaa0080"},
    "LOW":      {"bg": "#00cc44", "text": "#ffffff", "glow": "#00cc4480"},
    "INFORMATIONAL": {"bg": "#0088ff", "text": "#ffffff", "glow": "#0088ff80"},
    "UNKNOWN":  {"bg": "#666666", "text": "#ffffff", "glow": "#66666680"},
}


def parse_report(raw_text: str) -> dict:
    """
    Parse the structured text report from the agent into a dict.
    Falls back to graceful defaults if any section is missing.
    """
    # Clean up the raw text
    text = raw_text.strip()

    # Check if the report block is present
    has_report = "---CYBERSENTINEL REPORT---" in text and "---END REPORT---" in text

    if has_report:
        # Extract the report block
        start = text.find("---CYBERSENTINEL REPORT---")
        end = text.find("---END REPORT---") + len("---END REPORT---")
        report_block = text[start:end]
    else:
        report_block = text

    def extract_field(pattern, default="Unknown"):
        m = re.search(pattern, report_block, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else default

    def extract_list(header_pattern) -> list[str]:
        m = re.search(
            rf'{header_pattern}\s*\n((?:\s*[-•*]\s*.+\n?)+)',
            report_block,
            re.IGNORECASE
        )
        if not m:
            return []
        items_text = m.group(1)
        items = re.findall(r'[-•*]\s*(.+)', items_text)
        return [item.strip() for item in items if item.strip()]

    threat_level = extract_field(r'THREAT_LEVEL:\s*([A-Z]+)', "UNKNOWN").upper()
    if threat_level not in THREAT_COLORS:
        threat_level = "UNKNOWN"

    executive_summary = extract_field(
        r'EXECUTIVE_SUMMARY:\s*(.+?)(?=\n[A-Z_]+:|$)',
        "Investigation complete. See findings below."
    )

    target = extract_field(r'TARGET:\s*(.+?)(?=\n[A-Z_]+:|$)', "Unknown")
    target_type = extract_field(r'TARGET_TYPE:\s*(.+?)(?=\n[A-Z_]+:|$)', "Unknown")

    findings = extract_list(r'FINDINGS:')
    if not findings:
        # Try alternative parse — any bullet points after FINDINGS:
        m = re.search(r'FINDINGS:(.*?)(?:RISK_INDICATORS:|RECOMMENDED_ACTIONS:|---END)', report_block, re.DOTALL | re.I)
        if m:
            findings = [l.strip().lstrip('-•* ') for l in m.group(1).strip().split('\n') if l.strip().lstrip('-•* ')]

    risk_indicators = extract_list(r'RISK_INDICATORS:')
    if not risk_indicators:
        m = re.search(r'RISK_INDICATORS:(.*?)(?:RECOMMENDED_ACTIONS:|CONFIDENCE_LEVEL:|---END)', report_block, re.DOTALL | re.I)
        if m:
            risk_indicators = [l.strip().lstrip('-•* ') for l in m.group(1).strip().split('\n') if l.strip().lstrip('-•* ')]

    recommended_actions = extract_list(r'RECOMMENDED_ACTIONS:')
    if not recommended_actions:
        m = re.search(r'RECOMMENDED_ACTIONS:(.*?)(?:CONFIDENCE_LEVEL:|---END)', report_block, re.DOTALL | re.I)
        if m:
            recommended_actions = [l.strip().lstrip('-•* ') for l in m.group(1).strip().split('\n') if l.strip().lstrip('-•* ')]

    confidence_raw = extract_field(r'CONFIDENCE_LEVEL:\s*(.+?)(?=\n[A-Z_]+:|$|---END)', "MEDIUM")
    # Split confidence level from explanation
    conf_parts = confidence_raw.split('—', 1)
    if len(conf_parts) == 1:
        conf_parts = confidence_raw.split('-', 1)
    confidence_level = conf_parts[0].strip().upper() if conf_parts else "MEDIUM"
    confidence_note = conf_parts[1].strip() if len(conf_parts) > 1 else ""

    # Any preamble text before the report block
    preamble = ""
    if has_report and start > 0:
        preamble = text[:start].strip()

    colors = THREAT_COLORS.get(threat_level, THREAT_COLORS["UNKNOWN"])

    return {
        "threat_level": threat_level,
        "threat_colors": colors,
        "executive_summary": executive_summary,
        "target": target,
        "target_type": target_type,
        "findings": findings,
        "risk_indicators": risk_indicators,
        "recommended_actions": recommended_actions,
        "confidence_level": confidence_level,
        "confidence_note": confidence_note,
        "preamble": preamble,
        "raw_report": raw_text,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
