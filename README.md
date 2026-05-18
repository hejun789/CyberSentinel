# CyberSentinel — Autonomous Cybersecurity Threat Intelligence Agent

> An AI-powered autonomous agent that investigates domains, IPs, CVEs, URLs, and emails — then delivers structured threat intelligence reports.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Anthropic](https://img.shields.io/badge/Claude-claude--sonnet--4--6-orange?logo=anthropic)](https://anthropic.com)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-purple)](LICENSE)

---

## What It Does

You give CyberSentinel a target — a domain, IP address, CVE ID, suspicious URL, or raw email — and the agent autonomously:

1. **Plans** an investigation strategy based on the input type
2. **Executes** a multi-step tool-calling loop (WHOIS, DNS, port scan, CVE lookup, web search, email analysis, VirusTotal)
3. **Reasons** over intermediate results using Claude's native tool-use API — not prompt chaining
4. **Generates** a structured Threat Intelligence Report with severity rating, findings, risk indicators, and recommended actions

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     BROWSER (Dark UI)                         │
│  Target Input → POST /api/investigate → GET /api/stream/{id}  │
│          SSE progress feed → Final Report Card                │
└────────────────────────┬──────────────────────────────────────┘
                         │ HTTP / SSE
┌────────────────────────▼──────────────────────────────────────┐
│                    Flask App  (app.py)                        │
│  /api/investigate  →  Start background thread                 │
│  /api/stream/{id}  →  SSE event stream (real-time progress)   │
│  /api/history      →  Past investigations (JSON file)         │
└────────────────────────┬──────────────────────────────────────┘
                         │
┌────────────────────────▼──────────────────────────────────────┐
│                CyberSentinelAgent  (agent/core.py)            │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │             AGENTIC LOOP (max 10 iterations)            │  │
│  │                                                         │  │
│  │  messages → Claude API (claude-sonnet-4-6)              │  │
│  │       ↓                                                 │  │
│  │  stop_reason == "tool_use"?                             │  │
│  │       ↓ Yes                                             │  │
│  │  execute_tool(name, input) → result string              │  │
│  │       ↓                                                 │  │
│  │  append {tool_result} → call Claude again               │  │
│  │       ↓                                                 │  │
│  │  stop_reason == "end_turn"? → return final report       │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────┬──────────────────────────────────────┘
                         │
┌────────────────────────▼──────────────────────────────────────┐
│                   Tools  (agent/tools.py)                     │
│                                                               │
│  whois_lookup        → python-whois → domain age, registrar  │
│  dns_lookup          → dnspython   → A/MX/NS/TXT/DMARC/SPF   │
│  url_feature_analysis→ built-in    → 24 phishing features     │
│  web_search          → DuckDuckGo  → open-source threat intel │
│  cve_lookup          → NIST NVD API→ CVSS score, description  │
│  port_scan           → socket      → 20 common ports          │
│  email_header_analysis→ email lib  → spoofing, phishing       │
│  virustotal_lookup   → VT API v3   → 70+ engine detections    │
└───────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer     | Technology                        |
|-----------|-----------------------------------|
| AI Brain  | Anthropic Claude claude-sonnet-4-6 (tool_use) |
| Backend   | Python 3.11+, Flask 3.0           |
| Streaming | Server-Sent Events (SSE)          |
| WHOIS     | python-whois                      |
| DNS       | dnspython                         |
| Search    | duckduckgo-search                 |
| CVE Data  | NIST NVD API v2.0 (free)          |
| Port Scan | Python socket library             |
| Frontend  | Vanilla HTML/CSS/JS (dark cyberpunk theme) |
| Fonts     | Orbitron, Share Tech Mono (Google Fonts) |

---

## Setup

### Prerequisites
- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com)
- Optional: [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free tier)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CyberSentinel.git
cd CyberSentinel

# Create virtual environment
python -m venv venv
venv\Scripts\activate    # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Configuration

Edit `.env`:
```env
ANTHROPIC_API_KEY=sk-ant-...        # Required
VIRUSTOTAL_API_KEY=...              # Optional — VirusTotal checks skipped if absent
FLASK_PORT=5000                     # Optional, default 5000
FLASK_DEBUG=false                   # Optional, set true for development
```

### Run

```bash
python app.py
```

Open your browser at `http://localhost:5000`

---

## Usage

### Web UI
1. Enter a target in the investigation box:
   - **Domain**: `suspicious-site.tk`
   - **IP**: `45.33.32.156`
   - **CVE**: `CVE-2024-3094`
   - **URL**: `http://secure-paypal-login.ml/verify`
   - **Email**: Paste raw email text with headers
2. The UI auto-detects the input type
3. Click **Investigate** or press `Ctrl+Enter`
4. Watch the real-time investigation feed
5. Read the structured threat report

### API

**Start an investigation:**
```http
POST /api/investigate
Content-Type: application/json

{"target": "suspicious-domain.tk"}
```
Response: `{"id": "abc12345"}`

**Stream progress (SSE):**
```http
GET /api/stream/abc12345
Accept: text/event-stream
```
Events: `{"type": "progress", "data": {...}}` / `{"type": "done", "data": {...}}`

**Get investigation history:**
```http
GET /api/history
```

**Health check:**
```http
GET /api/health
```

---

## Report Format

CyberSentinel produces a structured report with:

| Field | Description |
|-------|-------------|
| **Threat Level** | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| **Executive Summary** | 2-3 sentence overview of key findings |
| **Findings** | Evidence-backed observations from all tools |
| **Risk Indicators** | Specific red flags with supporting data |
| **Recommended Actions** | Concrete, prioritized security steps |
| **Confidence Level** | HIGH/MEDIUM/LOW with data quality note |
| **Investigation Timeline** | Every tool called, with inputs and results |

---

## Tools Reference

| Tool | Input | What It Returns |
|------|-------|-----------------|
| `whois_lookup` | domain | Registrar, creation date, age, country, name servers |
| `dns_lookup` | domain | A, AAAA, MX, NS, TXT, CNAME records; SPF/DMARC check |
| `url_feature_analysis` | url | 24 phishing features, 0-100 risk score |
| `web_search` | query | DuckDuckGo results for threat intel |
| `cve_lookup` | CVE ID | CVSS score, severity, description, affected products |
| `port_scan` | domain/IP | Open/closed ports, service identification, risk flags |
| `email_header_analysis` | email text | Spoofing indicators, auth results, extracted URLs |
| `virustotal_lookup` | domain/IP/URL | Detection ratio from 70+ security engines |

---

## Key Implementation Details

### Agentic Loop (`agent/core.py`)
The agent runs a bounded loop (default max 10 iterations):
```
while iterations < MAX_ITERATIONS:
    response = claude.messages.create(tools=TOOL_SCHEMAS, messages=messages)
    if response.stop_reason == "end_turn":
        return final_report
    if response.stop_reason == "tool_use":
        for each tool_use block:
            result = execute_tool(tool_name, tool_input)
        messages += [assistant_msg, tool_result_msg]
        continue
```

### Native Tool Use
All 8 tools are defined as proper JSON schemas and passed to the Claude API — the agent decides *which tools to call, in what order, and how many times* based on what it finds.

### Real-time Streaming
The backend uses Python `threading.Thread` + `queue.Queue` to run the agent asynchronously, then streams progress via SSE (`text/event-stream`). The frontend uses the native `EventSource` API.

### Graceful Degradation
- If WHOIS fails → agent notes it and continues with DNS
- If web search is rate-limited → skipped, investigation continues
- If VirusTotal key absent → tool returns skip message, agent adapts
- Max iterations reached → returns partial report with what was found

---

## Project Structure

```
CyberSentinel/
├── agent/
│   ├── __init__.py
│   ├── core.py          # Agentic loop — multi-turn tool-use
│   ├── tools.py         # 8 tools: schemas + Python implementations
│   ├── prompts.py       # CyberSentinel system prompt
│   └── report.py        # Report text parser → structured dict
├── templates/
│   └── index.html       # Single-page dark cyberpunk UI
├── static/
│   ├── css/style.css    # Cyberpunk design system
│   └── js/app.js        # SSE client, report renderer, history
├── data/
│   └── history.json     # Investigation history (auto-generated)
├── app.py               # Flask app — routes, SSE streaming
├── config.py            # Environment variable loader
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Example Investigations

### Suspicious Domain
```
Target: free-bitcoin-winner.tk
Expected: HIGH/CRITICAL — new domain, suspicious TLD, phishing keywords
```

### Log4Shell CVE
```
Target: CVE-2021-44228
Expected: CRITICAL — CVSS 10.0, widely exploited, RCE vulnerability
```

### XZ Utils Backdoor
```
Target: CVE-2024-3094
Expected: CRITICAL — supply chain backdoor, SSH authentication bypass
```

### Legitimate Domain
```
Target: google.com
Expected: LOW/INFORMATIONAL — established domain, clean reputation
```

---

## Future Improvements

- [ ] Shodan API integration for advanced port/service intelligence
- [ ] AlienVault OTX threat feed lookup
- [ ] Abuse.ch malware database check
- [ ] PDF export of threat reports
- [ ] Webhook support for alerting (Slack, Discord)
- [ ] Batch investigation mode for multiple targets
- [ ] Historical trend analysis across investigations
- [ ] Docker containerization
- [ ] API key management UI
- [ ] STIX/TAXII threat intelligence format export

---

## Screenshots

> *[Add screenshots of the dark UI, investigation feed, and report card here]*

---

## Ethical Use

This tool is designed for:
- **Authorized security testing** of systems you own or have permission to test
- **Educational purposes** and learning cybersecurity concepts
- **Threat intelligence research** and defensive security work

Do not use this tool to investigate targets without authorization. Port scanning, WHOIS lookups, and DNS queries should only be performed on systems you have permission to analyze.

---

## Author

Built as a portfolio project by a student in Information System Security exploring the intersection of AI and cybersecurity.

---

*Powered by [Anthropic Claude](https://anthropic.com) — Autonomous AI with native tool use*
