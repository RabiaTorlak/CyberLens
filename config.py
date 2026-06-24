import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

CURSOR_API_KEY = os.getenv("CURSOR_API_KEY", "")
CURSOR_MODEL = os.getenv("CURSOR_MODEL", "composer-2.5")
# auto = Cursor SDK if key exists, else heuristic | cursor | heuristic
AI_ANALYSIS_MODE = os.getenv("AI_ANALYSIS_MODE", "auto")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_DIR = BASE_DIR / "data" / "logs"
REPORTS_DIR = BASE_DIR / "data" / "reports"
