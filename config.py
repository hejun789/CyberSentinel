import os
from dotenv import load_dotenv

load_dotenv()

_raw_key = os.getenv("ANTHROPIC_API_KEY", "")
# Reject placeholder values
ANTHROPIC_API_KEY = _raw_key if (_raw_key and not _raw_key.startswith("YOUR_") and len(_raw_key) > 20) else None
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

MODEL_ID = "claude-sonnet-4-6"
MAX_TOKENS = 8096
MAX_ITERATIONS = 10

FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "history.json")
MAX_HISTORY = 50

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 3306, 3389, 5900, 6379, 8080, 8443, 27017]

TOOL_TIMEOUT = 10
PORT_SCAN_TIMEOUT = 1.5
