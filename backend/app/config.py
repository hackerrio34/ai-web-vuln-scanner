import os
from dotenv import load_dotenv

# Load variables from .env at project root
load_dotenv()

AI_BASE_URL = os.getenv("AI_BASE_URL") or ""
AI_API_KEY = os.getenv("AI_API_KEY") or ""
AI_MODEL = os.getenv("AI_MODEL") or ""
