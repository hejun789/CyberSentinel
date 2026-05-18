"""Extract structured Indicators of Compromise from investigation reports using AI."""

import json

from config import PROVIDER, MODEL_ID, GEMINI_API_KEY, ANTHROPIC_API_KEY

_IOC_KEYS = (
    "malicious_ips",
    "malicious_domains",
    "malicious_urls",
    "cve_ids",
    "suspicious_emails",
    "attack_techniques",
    "threat_actors",
    "infrastructure",
)

EMPTY_IOCS = {k: [] for k in _IOC_KEYS}

_SYSTEM = (
    "You are a cybersecurity IOC extractor. "
    "Extract indicators from investigation reports and return ONLY valid JSON. "
    "No markdown fences, no explanation — raw JSON only."
)

_PROMPT_TMPL = """Extract all Indicators of Compromise (IOCs) from this cybersecurity investigation.

REPORT:
{report}

TOOL OUTPUTS (abbreviated):
{tools}

Return a single JSON object with exactly these keys (each value is a list of strings, use [] if none):
- malicious_ips       : IP addresses flagged as malicious or suspicious
- malicious_domains   : domains flagged as malicious, phishing, or suspicious
- malicious_urls      : full URLs flagged as malicious or phishing
- cve_ids             : CVE identifiers (format: CVE-YYYY-NNNNN)
- suspicious_emails   : email addresses flagged as suspicious or spam sources
- attack_techniques   : attack methods referenced (e.g. "phishing", "Log4Shell RCE")
- threat_actors       : specific threat actor names/groups mentioned
- infrastructure      : infrastructure notes (hosting providers, ASNs, bulletproof hosters)"""


def extract_iocs(report_text: str, steps: list) -> dict:
    """
    Extract structured IOCs from the investigation report via a single AI call.
    Returns a dict with IOC category keys; falls back to EMPTY_IOCS on any error.
    """
    if not (report_text and report_text.strip()):
        return EMPTY_IOCS

    tool_snippets = "\n".join(
        f"[{s.get('tool', '?')}] {s.get('result_snippet', '')}"
        for s in (steps or [])[:8]
    )
    prompt = _PROMPT_TMPL.format(
        report=report_text[:3000],
        tools=tool_snippets[:1500],
    )

    try:
        if PROVIDER == "anthropic":
            return _extract_anthropic(prompt)
        if PROVIDER == "gemini":
            return _extract_gemini(prompt)
    except Exception:
        pass

    return EMPTY_IOCS


# ─── Provider implementations ────────────────────────────────────────────────

def _extract_anthropic(prompt: str) -> dict:
    from anthropic import Anthropic
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    response = client.messages.create(
        model=MODEL_ID,
        max_tokens=1024,
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    return _normalize(_parse_json(text))


def _extract_gemini(prompt: str) -> dict:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=GEMINI_API_KEY)
    response = client.models.generate_content(
        model=MODEL_ID,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            system_instruction=_SYSTEM,
        ),
    )
    return _normalize(_parse_json(response.text.strip()))


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_json(text: str) -> dict:
    # Strip possible markdown code fences
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.split("```")[0]
    return json.loads(text.strip())


def _normalize(raw: dict) -> dict:
    """Ensure all expected keys exist and every value is a list of non-empty strings."""
    result = {}
    for key in _IOC_KEYS:
        vals = raw.get(key, [])
        if isinstance(vals, list):
            result[key] = [str(v).strip() for v in vals if v and str(v).strip()]
        else:
            result[key] = []
    return result
