import json
import os
import queue
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from agent.core import CyberSentinelAgent
from agent.report import parse_report
from config import HISTORY_FILE, MAX_HISTORY, FLASK_DEBUG, FLASK_PORT, VIRUSTOTAL_API_KEY

app = Flask(__name__)

# In-memory store of active investigation queues {inv_id: Queue}
_active_investigations: dict[str, queue.Queue] = {}
_inv_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# History helpers
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/investigate", methods=["POST"])
def start_investigation():
    """Start an investigation and return an investigation ID immediately."""
    from config import ANTHROPIC_API_KEY as _key
    if not _key:
        return jsonify({
            "error": "ANTHROPIC_API_KEY is not configured. "
                     "Edit your .env file and add your API key from https://console.anthropic.com"
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

            # Save to history (lightweight entry)
            _save_history_entry({
                "id": inv_id,
                "target": target,
                "threat_level": parsed["threat_level"],
                "target_type": parsed["target_type"],
                "executive_summary": parsed["executive_summary"][:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step_count": len(steps),
            })

            q.put({
                "type": "done",
                "data": {
                    "id": inv_id,
                    "target": target,
                    "report": parsed,
                    "steps": steps,
                }
            })
        except Exception as exc:
            q.put({"type": "error", "data": {"message": str(exc)}})
        finally:
            # Keep the queue alive for a short while so the SSE stream can drain
            pass

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({"id": inv_id})


@app.route("/api/stream/<inv_id>")
def stream_investigation(inv_id: str):
    """SSE endpoint — streams agent progress events for an investigation."""
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
                    # Heartbeat to keep connection alive
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


@app.route("/api/history")
def get_history():
    """Return past investigation summaries."""
    history = _load_history()
    return jsonify({"history": history, "count": len(history)})


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """Clear all investigation history."""
    with _history_lock:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)
    return jsonify({"message": "History cleared"})


@app.route("/api/health")
def health():
    from config import ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY
    return jsonify({
        "status": "ok",
        "anthropic_key_set": bool(ANTHROPIC_API_KEY),
        "virustotal_key_set": bool(VIRUSTOTAL_API_KEY),
        "model": "claude-sonnet-4-6",
    })


if __name__ == "__main__":
    from config import ANTHROPIC_API_KEY
    key_status = "✓ API key configured" if ANTHROPIC_API_KEY else "✗ API key MISSING — add to .env"
    vt_status  = "✓ VirusTotal configured" if VIRUSTOTAL_API_KEY else "○ VirusTotal optional (not set)"
    print(f"""
╔═══════════════════════════════════════════════════════╗
║       CyberSentinel — Threat Intelligence Agent       ║
╠═══════════════════════════════════════════════════════╣
║  {key_status:<53}║
║  {vt_status:<53}║
╠═══════════════════════════════════════════════════════╣
║  Open: http://localhost:{FLASK_PORT:<31}║
╚═══════════════════════════════════════════════════════╝
    """)
    if not ANTHROPIC_API_KEY:
        print("  ⚠  Add your Anthropic API key to .env before investigating targets")
        print("  Get a key at: https://console.anthropic.com\n")
    app.run(debug=FLASK_DEBUG, port=FLASK_PORT, threaded=True)
