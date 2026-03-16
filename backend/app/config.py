import os
from dotenv import load_dotenv

load_dotenv()

# ── AI / LLM settings ──────────────────────────────────────────────────────────
# Set these in your .env file to enable LLM-powered finding enrichment.
# Any OpenAI-compatible API endpoint works (OpenAI, Azure OpenAI, Ollama, etc.)
AI_BASE_URL: str = os.getenv("AI_BASE_URL", "")   # e.g. https://api.openai.com/v1
AI_API_KEY:  str = os.getenv("AI_API_KEY",  "")   # your API key
AI_MODEL:    str = os.getenv("AI_MODEL",    "")   # e.g. gpt-4o, gpt-3.5-turbo

# ── Scan defaults ──────────────────────────────────────────────────────────────
DEFAULT_PORT_RANGE: str  = os.getenv("DEFAULT_PORT_RANGE", "1-1024")
SCAN_TIMEOUT_SEC:   int  = int(os.getenv("SCAN_TIMEOUT_SEC", "120"))