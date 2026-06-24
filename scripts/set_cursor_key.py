"""Write or update CURSOR_API_KEY in the project .env file."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


def upsert_env_key(key: str, value: str) -> None:
    line = f"{key}={value}"
    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
        if pattern.search(content):
            content = pattern.sub(line, content)
        else:
            content = content.rstrip() + "\n" + line + "\n"
    else:
        content = line + "\n"

    ENV_FILE.write_text(content, encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/set_cursor_key.py <cursor_api_key>", file=sys.stderr)
        print("Get your key: https://cursor.com/dashboard/integrations", file=sys.stderr)
        sys.exit(1)

    api_key = sys.argv[1].strip()
    if not (api_key.startswith("cursor_") or api_key.startswith("crsr_")):
        print("Warning: Unexpected Cursor API key format", file=sys.stderr)

    upsert_env_key("CURSOR_API_KEY", api_key)
    upsert_env_key("AI_ANALYSIS_MODE", "auto")
    print(f"CURSOR_API_KEY saved to {ENV_FILE}")


if __name__ == "__main__":
    main()
