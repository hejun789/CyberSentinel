import os
from dotenv import load_dotenv

load_dotenv()

def _load_key(env_var: str) -> str | None:
    val = os.getenv(env_var, "")
    return val if (val and not val.startswith("YOUR_") and len(val) > 10) else None

ANTHROPIC_API_KEY   = _load_key("ANTHROPIC_API_KEY")
GROQ_API_KEY        = _load_key("GROQ_API_KEY")
OPENROUTER_API_KEY  = _load_key("OPENROUTER_API_KEY")
GEMINI_API_KEY      = _load_key("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY  = _load_key("VIRUSTOTAL_API_KEY")

# Provider selection priority: Anthropic > Groq > OpenRouter > Gemini
if ANTHROPIC_API_KEY:
    PROVIDER = "anthropic"
    MODEL_ID  = "claude-sonnet-4-6"
elif GROQ_API_KEY:
    PROVIDER = "groq"
    MODEL_ID  = "llama-3.1-8b-instant"
elif OPENROUTER_API_KEY:
    PROVIDER = "openrouter"
    MODEL_ID  = "mistralai/mistral-7b-instruct:free"
elif GEMINI_API_KEY:
    PROVIDER = "gemini"
    MODEL_ID  = "gemini-2.0-flash-lite"
else:
    PROVIDER = None
    MODEL_ID  = None

MAX_TOKENS     = 8096
MAX_ITERATIONS = 10

FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
FLASK_PORT  = int(os.getenv("PORT") or os.getenv("FLASK_PORT", 5000))  # PORT is set by Railway/Render

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "history.json")
MAX_HISTORY  = 50

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 3306, 3389, 5900, 6379, 8080, 8443, 27017]

TOOL_TIMEOUT      = 10
PORT_SCAN_TIMEOUT = 1.5
