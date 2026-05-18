"""
CyberSentinel agent core — supports Anthropic Claude, Groq, and Google Gemini.

Provider is selected automatically based on which API key is set in .env:
  ANTHROPIC_API_KEY → uses Claude claude-sonnet-4-6          (paid, best quality)
  GROQ_API_KEY      → uses Llama 3.3 70B via Groq            (free, 14400 req/day)
  GEMINI_API_KEY    → uses Gemini gemini-2.0-flash-lite       (free, limited regions)
"""

import json
from datetime import datetime, timezone
from typing import Callable, Optional

from config import (
    ANTHROPIC_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY,
    PROVIDER, MODEL_ID, MAX_TOKENS, MAX_ITERATIONS
)
from agent.prompts import SYSTEM_PROMPT
from agent.tools import TOOL_SCHEMAS, execute_tool
from agent.memory import search_memory


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def create_agent():
    """Return the right agent based on which API key is configured."""
    if PROVIDER == "anthropic":
        return _AnthropicAgent()
    if PROVIDER == "groq":
        return _GroqAgent()
    if PROVIDER == "openrouter":
        return _OpenRouterAgent()
    if PROVIDER == "gemini":
        return _GeminiAgent()
    raise RuntimeError(
        "No API key configured. Set OPENROUTER_API_KEY or GROQ_API_KEY in your .env file."
    )


# Public alias
CyberSentinelAgent = create_agent   # app.py calls CyberSentinelAgent() → factory


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic (Claude) implementation
# ─────────────────────────────────────────────────────────────────────────────

class _AnthropicAgent:
    def __init__(self):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=ANTHROPIC_API_KEY)

    def investigate(
        self,
        target: str,
        progress_callback: Optional[Callable[[dict], None]] = None
    ) -> tuple[str, list[dict]]:
        memory_ctx = search_memory(target)
        if memory_ctx:
            _emit(progress_callback, "memory", f"🧠 Memory activated — related past investigations found")
        messages = [{"role": "user", "content": _user_prompt(target, memory_ctx)}]
        investigation_steps: list[dict] = []

        _emit(progress_callback, "start", f"Starting Claude investigation of: {target}")

        for iteration in range(MAX_ITERATIONS):
            _emit(progress_callback, "thinking",
                  f"Analyzing results, deciding next steps... (iteration {iteration + 1})")

            response = self.client.messages.create(
                model=MODEL_ID,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages
            )

            if response.stop_reason == "end_turn":
                final = _extract_text(response.content)
                _emit(progress_callback, "complete", "Investigation complete. Generating report...")
                return final, investigation_steps

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    result_str, snippet = _run_tool(
                        block.name, block.input, progress_callback, iteration
                    )
                    investigation_steps.append(_step(iteration, block.name, block.input, result_str, snippet))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user",      "content": tool_results})
            else:
                final = _extract_text(response.content)
                if final:
                    return final, investigation_steps
                break

        return _timeout_report(target), investigation_steps


# ─────────────────────────────────────────────────────────────────────────────
# Groq (Llama) implementation — OpenAI-compatible, free tier
# ─────────────────────────────────────────────────────────────────────────────

class _GroqAgent:
    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=GROQ_API_KEY)
        self._label = "Groq"
        self._tools = [
            {
                "type": "function",
                "function": {
                    "name": s["name"],
                    "description": s["description"],
                    "parameters": s["input_schema"],
                }
            }
            for s in TOOL_SCHEMAS
        ]

    def investigate(
        self,
        target: str,
        progress_callback: Optional[Callable[[dict], None]] = None
    ) -> tuple[str, list[dict]]:
        memory_ctx = search_memory(target)
        if memory_ctx:
            _emit(progress_callback, "memory", "🧠 Memory activated — related past investigations found")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _user_prompt(target, memory_ctx)},
        ]
        investigation_steps: list[dict] = []

        _emit(progress_callback, "start", f"Starting {self._label}/Llama investigation of: {target}")

        for iteration in range(MAX_ITERATIONS):
            _emit(progress_callback, "thinking",
                  f"Analyzing results, deciding next steps... (iteration {iteration + 1})")

            response = self.client.chat.completions.create(
                model=MODEL_ID,
                max_tokens=MAX_TOKENS,
                messages=messages,
                tools=self._tools,
                tool_choice="auto",
            )

            msg = response.choices[0].message

            if not msg.tool_calls:
                _emit(progress_callback, "complete", "Investigation complete. Generating report...")
                return (msg.content or "").strip(), investigation_steps

            # Serialize assistant message explicitly (avoids SDK object issues)
            messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                tool_name  = tc.function.name
                tool_input = json.loads(tc.function.arguments)
                result_str, snippet = _run_tool(tool_name, tool_input, progress_callback, iteration)
                investigation_steps.append(_step(iteration, tool_name, tool_input, result_str, snippet))
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "content":      result_str[:1000],  # truncate to stay within TPM limits
                })

        return _timeout_report(target), investigation_steps


# ─────────────────────────────────────────────────────────────────────────────
# OpenRouter implementation — uses openai SDK with OpenRouter base URL
# ─────────────────────────────────────────────────────────────────────────────

class _OpenRouterAgent:
    def __init__(self):
        from openai import OpenAI
        self.client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://cybersentinel-9d1d.onrender.com",
                "X-Title": "CyberSentinel",
            },
        )
        self._tools = [
            {
                "type": "function",
                "function": {
                    "name": s["name"],
                    "description": s["description"],
                    "parameters": s["input_schema"],
                }
            }
            for s in TOOL_SCHEMAS
        ]

    def investigate(
        self,
        target: str,
        progress_callback: Optional[Callable[[dict], None]] = None
    ) -> tuple[str, list[dict]]:
        memory_ctx = search_memory(target)
        if memory_ctx:
            _emit(progress_callback, "memory", "🧠 Memory activated — related past investigations found")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _user_prompt(target, memory_ctx)},
        ]
        investigation_steps: list[dict] = []

        _emit(progress_callback, "start", f"Starting OpenRouter/Llama investigation of: {target}")

        for iteration in range(MAX_ITERATIONS):
            _emit(progress_callback, "thinking",
                  f"Analyzing results, deciding next steps... (iteration {iteration + 1})")

            response = self.client.chat.completions.create(
                model=MODEL_ID,
                max_tokens=MAX_TOKENS,
                messages=messages,
                tools=self._tools,
                tool_choice="auto",
            )

            msg = response.choices[0].message

            if not msg.tool_calls:
                _emit(progress_callback, "complete", "Investigation complete. Generating report...")
                return (msg.content or "").strip(), investigation_steps

            messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                tool_name  = tc.function.name
                tool_input = json.loads(tc.function.arguments)
                result_str, snippet = _run_tool(tool_name, tool_input, progress_callback, iteration)
                investigation_steps.append(_step(iteration, tool_name, tool_input, result_str, snippet))
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "content":      result_str[:1000],
                })

        return _timeout_report(target), investigation_steps


# ─────────────────────────────────────────────────────────────────────────────
# Gemini (Google) implementation  — uses new google-genai SDK
# ─────────────────────────────────────────────────────────────────────────────

def _to_gemini_schema(schema: dict) -> dict:
    """Convert JSON Schema (lowercase types) to Gemini schema (uppercase types)."""
    if not schema:
        return {}
    result = {}
    if "type" in schema:
        result["type"] = schema["type"].upper()
    if "description" in schema:
        result["description"] = schema["description"]
    if "properties" in schema:
        result["properties"] = {k: _to_gemini_schema(v) for k, v in schema["properties"].items()}
    if "required" in schema:
        result["required"] = schema["required"]
    if "enum" in schema:
        result["enum"] = schema["enum"]
    if "items" in schema:
        result["items"] = _to_gemini_schema(schema["items"])
    return result


class _GeminiAgent:
    def __init__(self):
        from google import genai
        from google.genai import types

        self._client = genai.Client(api_key=GEMINI_API_KEY)
        self._types  = types

        # Build Gemini function declarations from Anthropic-style schemas
        declarations = [
            types.FunctionDeclaration(
                name=s["name"],
                description=s["description"],
                parameters=_to_gemini_schema(s["input_schema"]),
            )
            for s in TOOL_SCHEMAS
        ]
        self._tool    = types.Tool(function_declarations=declarations)
        self._chat_config = types.GenerateContentConfig(
            tools=[self._tool],
            system_instruction=SYSTEM_PROMPT,
        )

    def investigate(
        self,
        target: str,
        progress_callback: Optional[Callable[[dict], None]] = None
    ) -> tuple[str, list[dict]]:
        types = self._types
        chat  = self._client.chats.create(model=MODEL_ID, config=self._chat_config)
        investigation_steps: list[dict] = []

        memory_ctx = search_memory(target)
        if memory_ctx:
            _emit(progress_callback, "memory", f"🧠 Memory activated — related past investigations found")

        _emit(progress_callback, "start", f"Starting Gemini investigation of: {target}")

        response = chat.send_message(_user_prompt(target, memory_ctx))

        for iteration in range(MAX_ITERATIONS):
            # Collect function calls from response parts
            fn_calls = []
            for part in response.candidates[0].content.parts:
                if part.function_call and part.function_call.name:
                    fn_calls.append(part.function_call)

            if not fn_calls:
                # No tool calls → extract final text
                final = ""
                for part in response.candidates[0].content.parts:
                    if hasattr(part, "text") and part.text:
                        final += part.text
                _emit(progress_callback, "complete", "Investigation complete. Generating report...")
                return final.strip(), investigation_steps

            _emit(progress_callback, "thinking",
                  f"Analyzing results, deciding next steps... (iteration {iteration + 1})")

            fn_response_parts = []
            for fn in fn_calls:
                tool_name  = fn.name
                tool_input = dict(fn.args)

                result_str, snippet = _run_tool(tool_name, tool_input, progress_callback, iteration)
                investigation_steps.append(_step(iteration, tool_name, tool_input, result_str, snippet))

                try:
                    result_dict = json.loads(result_str)
                    if not isinstance(result_dict, dict):
                        result_dict = {"output": str(result_dict)}
                except Exception:
                    result_dict = {"output": result_str}

                fn_response_parts.append(
                    types.Part.from_function_response(
                        name=tool_name,
                        response=_clean_none(result_dict),
                    )
                )

            response = chat.send_message(fn_response_parts)

        return _timeout_report(target), investigation_steps


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _user_prompt(target: str, memory_ctx: str = "") -> str:
    prefix = (memory_ctx + "\n") if memory_ctx else ""
    return (
        f"{prefix}Investigate this target for cybersecurity threats and produce "
        f"a complete threat intelligence report:\n\n{target}"
    )


def _emit(cb, event_type: str, message: str, **extra):
    if cb:
        cb({"type": event_type, "message": message, "timestamp": _now(), **extra})


def _run_tool(
    tool_name: str,
    tool_input: dict,
    progress_callback,
    iteration: int,
) -> tuple[str, str]:
    _emit(progress_callback, "tool_start",
          _tool_start_message(tool_name, tool_input),
          tool=tool_name, input=tool_input)

    result_str = execute_tool(tool_name, tool_input)

    try:
        result_obj = json.loads(result_str)
        snippet = _summarize_result(tool_name, result_obj)
    except Exception:
        snippet = result_str[:200]

    _emit(progress_callback, "tool_end",
          f"✓ {tool_name} completed: {snippet}",
          tool=tool_name, result_snippet=snippet)

    return result_str, snippet


def _step(iteration: int, tool: str, inp: dict, result: str, snippet: str) -> dict:
    return {
        "iteration": iteration + 1,
        "tool": tool,
        "input": inp,
        "result": result,
        "result_snippet": snippet,
        "timestamp": _now(),
    }


def _extract_text(content_blocks) -> str:
    return "".join(getattr(b, "text", "") for b in content_blocks).strip()


def _clean_none(obj):
    """Recursively remove None values so Gemini proto can serialize."""
    if isinstance(obj, dict):
        return {k: _clean_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_clean_none(v) for v in obj if v is not None]
    return obj


def _tool_start_message(tool_name: str, tool_input: dict) -> str:
    msgs = {
        "whois_lookup":          f"🔍 Running WHOIS lookup on {tool_input.get('domain', '')}...",
        "dns_lookup":            f"📡 Querying DNS records for {tool_input.get('domain', '')}...",
        "url_feature_analysis":  f"🔗 Analyzing URL features: {tool_input.get('url', '')[:60]}...",
        "web_search":            f"🌐 Searching: \"{tool_input.get('query', '')[:60]}\"...",
        "cve_lookup":            f"🛡️  Looking up {tool_input.get('cve_id', '')} in NVD database...",
        "port_scan":             f"🔌 Scanning ports on {tool_input.get('target', '')}...",
        "email_header_analysis": "📧 Analyzing email headers for phishing indicators...",
        "virustotal_lookup":     f"🦠 Checking {tool_input.get('target', '')} on VirusTotal...",
    }
    return msgs.get(tool_name, f"⚙️  Running {tool_name}...")


def _summarize_result(tool_name: str, result: dict) -> str:
    if "error" in result:
        return f"Error: {result['error'][:100]}"
    summaries = {
        "whois_lookup":          lambda r: (
            f"Registrar: {r.get('registrar','?')} | Age: {r.get('domain_age_days','?')}d | "
            f"Country: {r.get('registrant_country','?')}"
            + (f" | ⚠ {r['age_warning']}" if r.get('age_warning') else "")
        ),
        "dns_lookup":            lambda r: (
            f"A: {r.get('records',{}).get('A','none')} | "
            f"SPF: {'yes' if r.get('spf_record') else 'no'} | "
            f"DMARC: {'yes' if r.get('dmarc_record') else 'no'}"
        ),
        "url_feature_analysis":  lambda r: (
            f"Risk: {r.get('risk_score',0)}/100 ({r.get('risk_level','?')}) | "
            f"Factors: {', '.join(r.get('top_risk_factors',[])[:3])}"
        ),
        "web_search":            lambda r: f"{r.get('result_count',0)} results for: \"{r.get('query','')[:40]}\"",
        "cve_lookup":            lambda r: (
            f"CVSS: {r.get('cvss_score','N/A')} ({r.get('cvss_severity','N/A')}) | {r.get('risk_label','?')}"
        ),
        "port_scan":             lambda r: (
            f"Open: {[p['port'] for p in r.get('open_ports',[])]} | "
            f"High-risk: {[p['port'] for p in r.get('high_risk_ports',[])]}"
        ),
        "email_header_analysis": lambda r: (
            f"Risk: {r.get('risk_level','?')} | {r.get('indicator_count',0)} indicators | "
            f"URLs: {len(r.get('urls_found',[]))}"
        ),
        "virustotal_lookup":     lambda r: (
            f"Detections: {r.get('detection_ratio','?')} | {r.get('verdict','?')}"
            if r.get("status") != "skipped" else "VirusTotal skipped (no API key)"
        ),
    }
    fn = summaries.get(tool_name)
    if fn:
        try:
            return fn(result)
        except Exception:
            pass
    return str(result)[:150]


def _timeout_report(target: str) -> str:
    return (
        "---CYBERSENTINEL REPORT---\n"
        "THREAT_LEVEL: UNKNOWN\n"
        "EXECUTIVE_SUMMARY: Investigation reached maximum iteration limit before completing.\n"
        f"TARGET: {target}\n"
        "TARGET_TYPE: Unknown\n\n"
        "FINDINGS:\n- Investigation timed out after maximum tool calls\n\n"
        "RISK_INDICATORS:\n- Unable to complete full analysis\n\n"
        "RECOMMENDED_ACTIONS:\n- Retry the investigation\n- Investigate manually\n\n"
        "CONFIDENCE_LEVEL: LOW — investigation incomplete\n"
        "---END REPORT---"
    )
