import json
from datetime import datetime, timezone
from typing import Callable, Optional

from anthropic import Anthropic

from config import ANTHROPIC_API_KEY, MODEL_ID, MAX_TOKENS, MAX_ITERATIONS
from agent.prompts import SYSTEM_PROMPT
from agent.tools import TOOL_SCHEMAS, execute_tool


class CyberSentinelAgent:
    """
    Autonomous cybersecurity threat intelligence agent.

    Implements a multi-turn agentic loop:
    Claude ← messages + tools → tool_use blocks → execute_tool()
    → tool_result → Claude again → repeat until end_turn
    """

    def __init__(self):
        self.client = Anthropic(api_key=ANTHROPIC_API_KEY)

    def investigate(
        self,
        target: str,
        progress_callback: Optional[Callable[[dict], None]] = None
    ) -> tuple[str, list[dict]]:
        """
        Run the full investigation loop on a target.

        Args:
            target: The domain, IP, CVE ID, URL, or email text to investigate.
            progress_callback: Optional callable invoked on each agent event.
                               Receives a dict with keys: type, tool, input, result, message.

        Returns:
            (final_report_text, investigation_steps)
        """
        messages = [
            {
                "role": "user",
                "content": (
                    f"Investigate this target for cybersecurity threats and produce "
                    f"a complete threat intelligence report:\n\n{target}"
                )
            }
        ]

        investigation_steps: list[dict] = []

        if progress_callback:
            progress_callback({
                "type": "start",
                "message": f"Starting investigation of: {target}",
                "timestamp": _now()
            })

        for iteration in range(MAX_ITERATIONS):
            if progress_callback:
                progress_callback({
                    "type": "thinking",
                    "message": f"Analyzing results, deciding next steps... (iteration {iteration + 1})",
                    "timestamp": _now()
                })

            response = self.client.messages.create(
                model=MODEL_ID,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages
            )

            # ── Final answer: Claude is done ────────────────────────────────
            if response.stop_reason == "end_turn":
                final_text = _extract_text(response.content)

                if progress_callback:
                    progress_callback({
                        "type": "complete",
                        "message": "Investigation complete. Generating report...",
                        "timestamp": _now()
                    })

                return final_text, investigation_steps

            # ── Tool use: execute requested tools ───────────────────────────
            if response.stop_reason == "tool_use":
                tool_results = []

                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    tool_name = block.name
                    tool_input = block.input

                    if progress_callback:
                        progress_callback({
                            "type": "tool_start",
                            "tool": tool_name,
                            "input": tool_input,
                            "message": _tool_start_message(tool_name, tool_input),
                            "timestamp": _now()
                        })

                    result_str = execute_tool(tool_name, tool_input)

                    # Parse for snippet to show in progress
                    try:
                        result_obj = json.loads(result_str)
                        result_snippet = _summarize_result(tool_name, result_obj)
                    except Exception:
                        result_snippet = result_str[:200]

                    if progress_callback:
                        progress_callback({
                            "type": "tool_end",
                            "tool": tool_name,
                            "result_snippet": result_snippet,
                            "message": f"✓ {tool_name} completed: {result_snippet}",
                            "timestamp": _now()
                        })

                    investigation_steps.append({
                        "iteration": iteration + 1,
                        "tool": tool_name,
                        "input": tool_input,
                        "result": result_str,
                        "result_snippet": result_snippet,
                        "timestamp": _now()
                    })

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str
                    })

                # Append assistant message + tool results for next turn
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_results})

            else:
                # Unexpected stop reason — treat any text content as final
                final_text = _extract_text(response.content)
                if final_text:
                    return final_text, investigation_steps
                break

        # Safety limit reached
        timeout_msg = (
            "---CYBERSENTINEL REPORT---\n"
            "THREAT_LEVEL: UNKNOWN\n"
            "EXECUTIVE_SUMMARY: Investigation reached maximum iteration limit before completing.\n"
            "TARGET: " + target + "\n"
            "TARGET_TYPE: Unknown\n\n"
            "FINDINGS:\n- Investigation timed out after maximum tool calls\n\n"
            "RISK_INDICATORS:\n- Unable to complete full analysis\n\n"
            "RECOMMENDED_ACTIONS:\n- Retry the investigation\n- Investigate manually\n\n"
            "CONFIDENCE_LEVEL: LOW — investigation incomplete\n"
            "---END REPORT---"
        )

        if progress_callback:
            progress_callback({
                "type": "error",
                "message": "Maximum iterations reached — investigation truncated",
                "timestamp": _now()
            })

        return timeout_msg, investigation_steps


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_text(content_blocks) -> str:
    return "".join(
        getattr(block, "text", "")
        for block in content_blocks
    ).strip()


def _tool_start_message(tool_name: str, tool_input: dict) -> str:
    messages = {
        "whois_lookup": f"🔍 Running WHOIS lookup on {tool_input.get('domain', '')}...",
        "dns_lookup": f"📡 Querying DNS records for {tool_input.get('domain', '')}...",
        "url_feature_analysis": f"🔗 Analyzing URL features: {tool_input.get('url', '')[:60]}...",
        "web_search": f"🌐 Searching: \"{tool_input.get('query', '')[:60]}\"...",
        "cve_lookup": f"🛡️  Looking up {tool_input.get('cve_id', '')} in NVD database...",
        "port_scan": f"🔌 Scanning ports on {tool_input.get('target', '')}...",
        "email_header_analysis": "📧 Analyzing email headers for phishing indicators...",
        "virustotal_lookup": f"🦠 Checking {tool_input.get('target', '')} on VirusTotal...",
    }
    return messages.get(tool_name, f"⚙️  Running {tool_name}...")


def _summarize_result(tool_name: str, result: dict) -> str:
    """Return a 1-line human-readable summary of a tool result."""
    if "error" in result:
        return f"Error: {result['error'][:100]}"

    summaries = {
        "whois_lookup": lambda r: (
            f"Registrar: {r.get('registrar', 'Unknown')} | "
            f"Age: {r.get('domain_age_days', '?')} days | "
            f"Country: {r.get('registrant_country', 'Unknown')}"
            + (f" | ⚠ {r['age_warning']}" if r.get('age_warning') else "")
        ),
        "dns_lookup": lambda r: (
            f"A: {r.get('records', {}).get('A', 'none')} | "
            f"MX: {'yes' if r.get('records', {}).get('MX') else 'no'} | "
            f"SPF: {'yes' if r.get('spf_record') else 'no'} | "
            f"DMARC: {'yes' if r.get('dmarc_record') else 'no'}"
        ),
        "url_feature_analysis": lambda r: (
            f"Risk score: {r.get('risk_score', 0)}/100 ({r.get('risk_level', 'UNKNOWN')}) | "
            f"Top factors: {', '.join(r.get('top_risk_factors', [])[:3])}"
        ),
        "web_search": lambda r: (
            f"{r.get('result_count', 0)} results found for: \"{r.get('query', '')[:50]}\""
        ),
        "cve_lookup": lambda r: (
            f"CVSS: {r.get('cvss_score', 'N/A')} ({r.get('cvss_severity', 'N/A')}) | "
            f"{r.get('risk_label', 'Unknown severity')}"
        ),
        "port_scan": lambda r: (
            f"Open ports: {[p['port'] for p in r.get('open_ports', [])]} | "
            f"High-risk: {[p['port'] for p in r.get('high_risk_ports', [])]}"
        ),
        "email_header_analysis": lambda r: (
            f"Risk: {r.get('risk_level', 'UNKNOWN')} | "
            f"{r.get('indicator_count', 0)} phishing indicators | "
            f"URLs: {len(r.get('urls_found', []))}"
        ),
        "virustotal_lookup": lambda r: (
            f"Detections: {r.get('detection_ratio', '?')} | {r.get('verdict', 'Unknown')}"
            if r.get("status") != "skipped"
            else "VirusTotal skipped (no API key)"
        ),
    }

    summarizer = summaries.get(tool_name)
    if summarizer:
        try:
            return summarizer(result)
        except Exception:
            pass
    return str(result)[:150]
