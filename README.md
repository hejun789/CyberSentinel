# CyberSentinel — Autonomous Cybersecurity Threat Intelligence Agent

> An AI-powered autonomous agent that investigates domains, IPs, CVEs, URLs, and emails — then delivers structured threat intelligence reports with IOC extraction, cross-investigation memory, and interactive follow-up chat.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green?logo=flask)](https://flask.palletsprojects.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5--flash--lite-orange?logo=google)](https://aistudio.google.com)
[![Anthropic](https://img.shields.io/badge/Claude-claude--sonnet--4--6-purple?logo=anthropic)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## What It Does

You give CyberSentinel a target — a domain, IP address, CVE ID, suspicious URL, or raw email — and the agent autonomously:

1. **Remembers** — searches past investigations for related targets, IOCs, or CVEs before starting
2. **Plans & Executes** — runs a multi-step tool-calling loop (WHOIS, DNS, port scan, CVE lookup, web search, email analysis, VirusTotal)
3. **Reasons** — the AI decides which tools to call, in what order, and how many times based on what it finds
4. **Reports** — generates a structured Threat Intelligence Report with severity rating, findings, risk indicators, and recommended actions
5. **Extracts IOCs** — automatically pulls out structured Indicators of Compromise (IPs, domains, CVEs, attack techniques, threat actors)
6. **Chats** — lets you ask follow-up questions about any investigation using the full report as context

---

## AI Features

### Autonomous Investigation Engine
The core agentic loop uses native `tool_use` — not prompt chaining. The AI calls tools in any order, as many times as needed, until it has enough evidence to write a report. Supports both **Google Gemini** (free) and **Anthropic Claude** (paid).

### Cross-Investigation Memory
Before every investigation, CyberSentinel searches your past history for related findings — matching by domain, IP overlap, CVE IDs, shared IOCs, and suspicious TLDs. Relevant context is injected into the agent's prompt so it builds on previous intelligence.

### IOC Extractor
After each investigation, a separate AI call with JSON-mode output extracts 8 structured IOC categories from the full report: malicious IPs, domains, URLs, CVE IDs, suspicious emails, attack techniques, threat actors, and infrastructure notes. Results are stored in history and displayed as a color-coded grid.

### Follow-up Chat
After any investigation completes, a chat panel opens. Ask anything about the report — the full investigation text and IOCs are injected as context. Supports multi-turn conversation with history. Works on past investigations too (click any history entry).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      BROWSER (Dark UI)                          │
│  Target Input → POST /api/investigate → GET /api/stream/{id}    │
│       IOC Grid ← POST /api/chat → Follow-up Chat Panel         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP / SSE
┌──────────────────────────▼──────────────────────────────────────┐
│                     Flask App  (app.py)                         │
│  /api/investigate  → Start background thread                    │
│  /api/stream/{id}  → SSE event stream (real-time progress)      │
│  /api/chat         → Follow-up Q&A with report context          │
│  /api/history      → Past investigations (JSON file)            │
│  /api/investigation/<id> → Full detail with raw report + IOCs   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│              CyberSentinelAgent  (agent/core.py)                │
│                                                                 │
│  1. search_memory(target) → inject related past findings        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │            AGENTIC LOOP  (max 10 iterations)              │  │
│  │                                                           │  │
│  │  messages → Gemini / Claude API                           │  │
│  │       ↓                                                   │  │
│  │  tool_use? → execute_tool(name, input) → result           │  │
│  │       ↓                                                   │  │
│  │  append tool result → call AI again                       │  │
│  │       ↓                                                   │  │
│  │  end_turn → return final report                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  2. extract_iocs(report, steps) → structured JSON IOCs          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Tools  (agent/tools.py)                      │
│                                                                 │
│  whois_lookup         → python-whois → domain age, registrar   │
│  dns_lookup           → dnspython   → A/MX/NS/TXT/DMARC/SPF    │
│  url_feature_analysis → built-in    → 24 phishing features      │
│  web_search           → DuckDuckGo  → open-source threat intel  │
│  cve_lookup           → NIST NVD API→ CVSS score, description   │
│  port_scan            → socket      → 20 common ports           │
│  email_header_analysis→ email lib   → spoofing, phishing        │
│  virustotal_lookup    → VT API v3   → 70+ engine detections     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| AI (free) | Google Gemini 2.5 Flash Lite — `google-genai` SDK |
| AI (paid) | Anthropic Claude `claude-sonnet-4-6` — native `tool_use` |
| Backend | Python 3.11+, Flask 3.0 |
| Streaming | Server-Sent Events (SSE) |
| WHOIS | python-whois |
| DNS | dnspython |
| Search | DuckDuckGo Search (`ddgs`) |
| CVE Data | NIST NVD API v2.0 (free, no key needed) |
| Port Scan | Python socket library |
| Frontend | Vanilla HTML/CSS/JS — dark cyberpunk theme |
| Fonts | Orbitron, Share Tech Mono (Google Fonts) |

---

## Setup

### Prerequisites
- Python 3.11+
- A free [Google AI Studio key](https://aistudio.google.com/app/apikey) **or** a paid [Anthropic API key](https://console.anthropic.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CyberSentinel.git
cd CyberSentinel

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — add your API key (see below)
```

### Configuration

Edit `.env`:

```env
# FREE — Google Gemini (20 req/day, no billing required)
GEMINI_API_KEY=AIzaSy...your_key_here

# OR PAID — Anthropic Claude (better quality, pay-per-use)
# ANTHROPIC_API_KEY=sk-ant-...your_key_here

# Optional — VirusTotal (free tier, skipped if absent)
# VIRUSTOTAL_API_KEY=...
```

> If both keys are set, Anthropic takes priority.

### Run

```bash
python app.py
```

Open your browser at `http://localhost:5000`

**Important:** Restart the server after any `.env` change — API keys are loaded at startup.

---

## Usage

### Investigate a target
1. Enter a target in the investigation box:
   - **Domain**: `suspicious-site.tk`
   - **IP**: `45.33.32.156`
   - **CVE**: `CVE-2024-3094`
   - **URL**: `http://secure-paypal-login.ml/verify`
   - **Email**: paste raw email text with headers
2. The UI auto-detects the input type
3. Click **Investigate** or press `Ctrl+Enter`
4. Watch the real-time investigation feed
5. Read the structured threat report and IOC grid
6. Ask follow-up questions in the chat panel below

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/investigate` | Start investigation, returns `{"id": "..."}` |
| `GET` | `/api/stream/{id}` | SSE stream of investigation progress |
| `POST` | `/api/chat` | Follow-up chat with report context |
| `GET` | `/api/history` | List past investigations (no raw reports) |
| `GET` | `/api/investigation/{id}` | Full detail with raw report + IOCs |
| `DELETE` | `/api/history` | Clear all history |
| `GET` | `/api/health` | Provider status and configuration check |

**Start an investigation:**
```http
POST /api/investigate
Content-Type: application/json

{"target": "suspicious-domain.tk"}
```

**Follow-up chat:**
```http
POST /api/chat
Content-Type: application/json

{
  "investigation_id": "abc123",
  "message": "What immediate actions should I take?",
  "history": []
}
```

---

## Report Structure

| Field | Description |
|-------|-------------|
| **Threat Level** | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| **Executive Summary** | 2–3 sentence overview of key findings |
| **Findings** | Evidence-backed observations from all tools |
| **Risk Indicators** | Specific red flags with supporting data |
| **Recommended Actions** | Concrete, prioritized security steps |
| **Confidence Level** | HIGH / MEDIUM / LOW with data quality note |
| **Investigation Timeline** | Every tool called, with inputs and results |
| **IOCs** | 8 structured categories: IPs, domains, URLs, CVEs, emails, techniques, actors, infrastructure |

---

## Tools Reference

| Tool | Input | What It Returns |
|------|-------|-----------------|
| `whois_lookup` | domain | Registrar, creation date, age, country |
| `dns_lookup` | domain | A/AAAA/MX/NS/TXT records; SPF/DMARC presence |
| `url_feature_analysis` | URL | 24 phishing features, 0–100 risk score |
| `web_search` | query | DuckDuckGo results for threat intel |
| `cve_lookup` | CVE ID | CVSS score, severity, description, affected products |
| `port_scan` | domain/IP | Open ports, service names, high-risk flags |
| `email_header_analysis` | email text | Spoofing indicators, auth results, embedded URLs |
| `virustotal_lookup` | domain/IP/URL | Detection ratio across 70+ security engines |

---

## Project Structure

```
CyberSentinel/
├── agent/
│   ├── core.py           # Agentic loop — dual-provider (Gemini + Claude)
│   ├── memory.py         # Cross-investigation memory search
│   ├── ioc_extractor.py  # Structured IOC extraction via AI JSON mode
│   ├── tools.py          # 8 tools: JSON schemas + Python implementations
│   ├── prompts.py        # CyberSentinel system prompt
│   ├── report.py         # Report text parser → structured dict
│   └── __init__.py
├── templates/
│   └── index.html        # Single-page dark cyberpunk UI
├── static/
│   ├── css/style.css     # Cyberpunk design system
│   └── js/app.js         # SSE client, report renderer, IOC grid, chat
├── data/
│   └── history.json      # Auto-generated, gitignored
├── app.py                # Flask app — routes, SSE streaming, chat
├── config.py             # Environment variable loader
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Example Investigations

| Target | Expected Result |
|--------|----------------|
| `free-bitcoin-winner.tk` | HIGH/CRITICAL — new domain, suspicious TLD, phishing keywords |
| `CVE-2021-44228` | CRITICAL — Log4Shell, CVSS 10.0, RCE |
| `CVE-2024-3094` | CRITICAL — XZ Utils supply chain backdoor |
| `google.com` | INFORMATIONAL — established domain, clean reputation |
| `http://secure-paypal-login.ml/verify` | HIGH/CRITICAL — phishing URL features |

---

## Key Design Decisions

- **Native tool use, not prompt chaining** — tools are real JSON schemas passed to the AI; the model decides the investigation strategy
- **Dual AI provider** — Gemini for free access, Claude for quality; identical tool schemas work for both
- **SSE streaming** — progress appears in real time via `EventSource`, no polling
- **Memory across sessions** — history is persisted to JSON and scored by relevance before each new investigation
- **IOC extraction is a separate AI call** — uses Gemini's `response_mime_type="application/json"` for reliable structured output

---

## Future Improvements

- [ ] Shodan API integration for advanced port/service intelligence
- [ ] AlienVault OTX threat feed lookup
- [ ] PDF export of threat reports
- [ ] Webhook support for alerting (Slack, Discord)
- [ ] Batch investigation mode for multiple targets
- [ ] Docker containerization
- [ ] STIX/TAXII threat intelligence format export

---

## Screenshots

<img width="1915" height="905" alt="Screenshot 2026-05-08 111048" src="https://github.com/user-attachments/assets/352f55be-a3b4-46ac-87c7-48f8b83e8d8d" />
<img width="1918" height="911" alt="Screenshot 2026-05-08 111106" src="https://github.com/user-attachments/assets/a551033d-d181-41c5-94aa-65e08e2463a7" />
<img width="1918" height="902" alt="Screenshot 2026-05-08 111117" src="https://github.com/user-attachments/assets/93793fad-6feb-4074-83ce-2a2dae5ed34b" />
<img width="1912" height="907" alt="Screenshot 2026-05-08 111144" src="https://github.com/user-attachments/assets/ae6bfe6c-4ce2-4f3a-a2b7-e95d910cde06" />


---

## Ethical Use

This tool is for:
- **Authorized security testing** of systems you own or have permission to test
- **Educational purposes** and learning cybersecurity concepts
- **Threat intelligence research** and defensive security work

Do not investigate targets without authorization.

---

## Author

Built as a portfolio project exploring the intersection of AI and cybersecurity.

---

*Supports [Google Gemini](https://aistudio.google.com) (free) and [Anthropic Claude](https://anthropic.com) (paid)*
