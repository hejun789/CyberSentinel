import json
import os
import queue
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from agent.core import CyberSentinelAgent
from agent.report import parse_report
from agent.ioc_extractor import extract_iocs, EMPTY_IOCS
from config import (
    HISTORY_FILE, MAX_HISTORY, FLASK_DEBUG, FLASK_PORT,
    VIRUSTOTAL_API_KEY, PROVIDER, MODEL_ID,
    ANTHROPIC_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY,
)

app = Flask(__name__)

_active_investigations: dict[str, queue.Queue] = {}
_inv_lock = threading.Lock()

# ─── History helpers ──────────────────────────────────────────────────────────

_history_lock = threading.Lock()


def _load_history() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_history_entry(entry: dict) -> None:
    with _history_lock:
        history = _load_history()
        history.insert(0, entry)
        history = history[:MAX_HISTORY]
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)


def _get_investigation(inv_id: str) -> dict | None:
    for entry in _load_history():
        if entry.get("id") == inv_id:
            return entry
    return None


def _append_chat_to_history(inv_id: str, user_msg: str, assistant_reply: str) -> None:
    with _history_lock:
        history = _load_history()
        for entry in history:
            if entry.get("id") == inv_id:
                if "chat_history" not in entry:
                    entry["chat_history"] = []
                entry["chat_history"].append({"role": "user",      "content": user_msg})
                entry["chat_history"].append({"role": "assistant", "content": assistant_reply})
                break
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/investigate", methods=["POST"])
def start_investigation():
    if not PROVIDER:
        return jsonify({
            "error": (
                "No API key configured. "
                "Add GEMINI_API_KEY (free) from https://aistudio.google.com "
                "or ANTHROPIC_API_KEY from https://console.anthropic.com to your .env file."
            )
        }), 503

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400
    if len(target) > 10000:
        return jsonify({"error": "Target too long (max 10000 characters)"}), 400

    inv_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()

    with _inv_lock:
        _active_investigations[inv_id] = q

    def _run():
        agent = CyberSentinelAgent()

        def _progress(event: dict):
            q.put({"type": "progress", "data": event})

        try:
            report_text, steps = agent.investigate(target, _progress)
            parsed = parse_report(report_text)

            # Extract IOCs with a separate AI call
            _progress({"type": "ioc", "message": "🔎 Extracting Indicators of Compromise...",
                        "timestamp": datetime.now(timezone.utc).isoformat()})
            iocs = extract_iocs(report_text, steps)

            _save_history_entry({
                "id": inv_id,
                "target": target,
                "threat_level": parsed["threat_level"],
                "target_type": parsed["target_type"],
                "executive_summary": parsed["executive_summary"][:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step_count": len(steps),
                "raw_report": report_text,
                "iocs": iocs,
            })

            q.put({
                "type": "done",
                "data": {
                    "id": inv_id,
                    "target": target,
                    "report": parsed,
                    "steps": steps,
                    "iocs": iocs,
                }
            })
        except Exception as exc:
            q.put({"type": "error", "data": {"message": _sanitize_error(str(exc))}})

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"id": inv_id})


@app.route("/api/stream/<inv_id>")
def stream_investigation(inv_id: str):
    with _inv_lock:
        q = _active_investigations.get(inv_id)

    if q is None:
        return jsonify({"error": "Investigation not found"}), 404

    def _generate():
        try:
            while True:
                try:
                    event = q.get(timeout=180)
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                    continue

                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

                if event.get("type") in ("done", "error"):
                    break
        finally:
            with _inv_lock:
                _active_investigations.pop(inv_id, None)

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


@app.route("/api/chat", methods=["POST"])
def chat():
    """Answer questions about a completed investigation using the AI."""
    if not PROVIDER:
        return jsonify({"error": "No AI provider configured"}), 503

    data = request.get_json(silent=True) or {}
    inv_id  = (data.get("investigation_id") or "").strip()
    message = (data.get("message") or "").strip()
    history = data.get("history") or []

    if not message:
        return jsonify({"error": "No message provided"}), 400

    entry = _get_investigation(inv_id) if inv_id else None
    raw_report = (entry or {}).get("raw_report", "")
    iocs = (entry or {}).get("iocs") or {}

    # Build chat system prompt with report context
    ioc_summary = _format_iocs_for_prompt(iocs)
    system = (
        "You are CyberSentinel, an expert cybersecurity AI analyst. "
        "The user is asking follow-up questions about a specific threat investigation you conducted.\n\n"
        + (f"INVESTIGATION REPORT:\n{raw_report[:4000]}\n\n" if raw_report else "")
        + (f"KEY IOCs EXTRACTED:\n{ioc_summary}\n\n" if ioc_summary else "")
        + "Answer concisely and technically. Do not re-investigate; use only information from the report above."
    )

    try:
        reply = _chat_with_ai(system, history, message)
        if inv_id:
            _append_chat_to_history(inv_id, message, reply)
        return jsonify({"reply": reply})
    except Exception as exc:
        return jsonify({"error": _sanitize_error(str(exc))}), 500


def _sanitize_error(raw: str) -> str:
    """Convert verbose SDK exception strings into short, readable messages."""
    import re as _re
    msg = raw[:2000]

    if "rate_limit_exceeded" in msg or ("rate limit" in msg.lower() and "groq" in msg.lower()):
        m = _re.search(r"Please try again in (\d+\.?\d*)s", msg)
        wait = f" Retry in {m.group(1)}s." if m else " Wait 60 seconds and retry."
        return f"Rate limit reached (Groq free tier).{wait}"

    if "RESOURCE_EXHAUSTED" in msg or "quota" in msg.lower():
        m = _re.search(r"retryDelay['\": ]+(\d+)s", msg)
        wait = f" Retry in {m.group(1)}s." if m else ""
        return f"Rate limit reached (Gemini free tier: 20 req/day).{wait}"

    if "FAILED_PRECONDITION" in msg and "location" in msg.lower():
        return "Gemini API is not available from this server's region. Use ANTHROPIC_API_KEY instead."

    # Use specific phrases, not status codes that appear in unrelated content
    if "UNAUTHENTICATED" in msg or "API_KEY_INVALID" in msg or "invalid api key" in msg.lower():
        return "API authentication error — check your GEMINI_API_KEY in .env."

    if "UNAVAILABLE" in msg or "Service Unavailable" in msg:
        return "AI service temporarily unavailable. Please try again."

    if "timeout" in msg.lower() or "timed out" in msg.lower() or "DeadlineExceeded" in msg:
        return "Request timed out. Please try again."

    # Show first 300 chars of unknown errors so they can be diagnosed
    return raw[:300]


def _format_iocs_for_prompt(iocs: dict) -> str:
    if not iocs:
        return ""
    parts = []
    for key, vals in iocs.items():
        if vals:
            parts.append(f"{key}: {', '.join(str(v) for v in vals[:10])}")
    return "\n".join(parts)


def _chat_with_ai(system: str, history: list, message: str) -> str:
    if PROVIDER == "anthropic":
        return _chat_anthropic(system, history, message)
    if PROVIDER == "groq":
        return _chat_groq(system, history, message)
    if PROVIDER == "openrouter":
        return _chat_openrouter(system, history, message)
    if PROVIDER == "gemini":
        return _chat_gemini(system, history, message)
    raise RuntimeError("No provider")


def _chat_openrouter(system: str, history: list, message: str) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
        default_headers={
            "HTTP-Referer": "https://cybersentinel-9d1d.onrender.com",
            "X-Title": "CyberSentinel",
        },
    )
    messages = [{"role": "system", "content": system}]
    for turn in history:
        role = turn.get("role")
        content = turn.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": message})
    response = client.chat.completions.create(model=MODEL_ID, max_tokens=1024, messages=messages)
    return response.choices[0].message.content.strip()


def _chat_groq(system: str, history: list, message: str) -> str:
    from groq import Groq
    client = Groq(api_key=GROQ_API_KEY)
    messages = [{"role": "system", "content": system}]
    for turn in history:
        role = turn.get("role")
        content = turn.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": message})
    response = client.chat.completions.create(
        model=MODEL_ID,
        max_tokens=1024,
        messages=messages,
    )
    return response.choices[0].message.content.strip()


def _chat_anthropic(system: str, history: list, message: str) -> str:
    from anthropic import Anthropic
    client = Anthropic(api_key=ANTHROPIC_API_KEY)

    messages = []
    for turn in history:
        role = turn.get("role")
        content = turn.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": message})

    response = client.messages.create(
        model=MODEL_ID,
        max_tokens=1024,
        system=system,
        messages=messages,
    )
    return response.content[0].text.strip()


def _chat_gemini(system: str, history: list, message: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=GEMINI_API_KEY)
    chat_history = []
    for turn in history:
        role = turn.get("role")
        content = turn.get("content", "")
        if role == "user" and content:
            chat_history.append(types.Content(role="user", parts=[types.Part(text=content)]))
        elif role == "assistant" and content:
            chat_history.append(types.Content(role="model", parts=[types.Part(text=content)]))

    chat = client.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(system_instruction=system),
        history=chat_history,
    )
    response = chat.send_message(message)
    return response.text.strip()


@app.route("/api/history")
def get_history():
    history = _load_history()
    # Strip raw_report from list view to keep response small
    slim = [
        {k: v for k, v in h.items() if k not in ("raw_report", "chat_history")}
        for h in history
    ]
    return jsonify({"history": slim, "count": len(slim)})


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    with _history_lock:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)
    return jsonify({"message": "History cleared"})


@app.route("/api/investigation/<inv_id>")
def get_investigation_detail(inv_id: str):
    entry = _get_investigation(inv_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "provider": PROVIDER or "none",
        "model": MODEL_ID or "not configured",
        "anthropic_key_set": bool(ANTHROPIC_API_KEY),
        "groq_key_set": bool(GROQ_API_KEY),
        "gemini_key_set": bool(GEMINI_API_KEY),
        "virustotal_key_set": bool(VIRUSTOTAL_API_KEY),
        "ready": bool(PROVIDER),
    })


if __name__ == "__main__":
    if PROVIDER == "anthropic":
        ai_status = f"✓ Provider: Anthropic Claude ({MODEL_ID})"
    elif PROVIDER == "groq":
        ai_status = f"✓ Provider: Groq / Llama ({MODEL_ID}) — FREE"
    elif PROVIDER == "openrouter":
        ai_status = f"✓ Provider: OpenRouter / Llama ({MODEL_ID}) — FREE"
    elif PROVIDER == "gemini":
        ai_status = f"✓ Provider: Google Gemini ({MODEL_ID}) — FREE"
    else:
        ai_status = "✗ No AI provider — add GROQ_API_KEY or ANTHROPIC_API_KEY to .env"
    vt_status = "✓ VirusTotal configured" if VIRUSTOTAL_API_KEY else "○ VirusTotal optional (not set)"
    print(f"""
╔═══════════════════════════════════════════════════════╗
║       CyberSentinel — Threat Intelligence Agent       ║
╠═══════════════════════════════════════════════════════╣
║  {ai_status:<53}║
║  {vt_status:<53}║
╠═══════════════════════════════════════════════════════╣
║  Open: http://localhost:{FLASK_PORT:<31}║
╚═══════════════════════════════════════════════════════╝
    """)
    if not PROVIDER:
        print("  ⚠  FREE option: get a Gemini API key at https://aistudio.google.com")
        print("  Add GEMINI_API_KEY=your_key to the .env file, then restart.\n")
    app.run(host="0.0.0.0", debug=FLASK_DEBUG, port=FLASK_PORT, threaded=True)
