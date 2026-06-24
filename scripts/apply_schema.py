"""Apply Supabase migrations using a direct PostgreSQL connection."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
MIGRATION_DIR = ROOT_DIR / "supabase" / "migrations"
sys.path.insert(0, str(ROOT_DIR))

from src.logging_config import get_logger

logger = get_logger("apply_schema")

POOLER_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "ap-south-1",
    "ap-northeast-2",
    "ap-southeast-2",
    "ca-central-1",
    "sa-east-1",
    "me-central-1",
    "ap-southeast-3",
]


def _get_credentials() -> tuple[str, str, str]:
    import os

    load_dotenv(ROOT_DIR / ".env")

    supabase_url = os.getenv("SUPABASE_URL", "")
    password = os.getenv("SUPABASE_DB_PASSWORD", "")

    match = re.search(r"https://([^.]+)\.supabase\.co", supabase_url)
    if not match:
        raise ValueError("SUPABASE_URL is invalid or missing.")

    if not password:
        raise ValueError(
            "Set SUPABASE_DB_PASSWORD or SUPABASE_DB_URL in .env.\n"
            "Password: Supabase Dashboard > Project Settings > Database"
        )

    return match.group(1), password, os.getenv("SUPABASE_DB_REGION", "")


def _resolve_ipv6(host: str) -> str | None:
    import subprocess

    result = subprocess.run(
        ["nslookup", host],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if "Address:" in line and ":" in line.split("Address:")[-1]:
            candidate = line.split("Address:")[-1].strip()
            if ":" in candidate and not candidate.startswith("192.168"):
                return candidate
    return None


def _connect_pooler(project_ref: str, password: str, region: str, prefix: str):
    return psycopg2.connect(
        host=f"{prefix}-{region}.pooler.supabase.com",
        port=5432,
        user=f"postgres.{project_ref}",
        password=password,
        dbname="postgres",
        sslmode="require",
        connect_timeout=15,
    )


def connect_db():
    import os

    load_dotenv(ROOT_DIR / ".env")

    if db_url := os.getenv("SUPABASE_DB_URL"):
        return psycopg2.connect(db_url, sslmode="require")

    project_ref, password, region = _get_credentials()
    regions = [region] if region else POOLER_REGIONS
    last_error: Exception | None = None

    for pooler_region in regions:
        for prefix in ("aws-1", "aws-0"):
            try:
                return _connect_pooler(project_ref, password, pooler_region, prefix)
            except psycopg2.OperationalError as exc:
                message = str(exc).lower()
                if "password authentication failed" in message:
                    raise ValueError(
                        "Database password is incorrect. "
                        "Check SUPABASE_DB_PASSWORD in .env."
                    ) from exc
                last_error = exc

    host = f"db.{project_ref}.supabase.co"
    params = {
        "host": host,
        "port": 5432,
        "user": "postgres",
        "password": password,
        "dbname": "postgres",
        "sslmode": "require",
        "connect_timeout": 20,
    }

    hostaddr = _resolve_ipv6(host)
    if hostaddr:
        try:
            return psycopg2.connect(**params, hostaddr=hostaddr)
        except psycopg2.OperationalError as exc:
            last_error = exc

    if last_error:
        raise last_error

    return psycopg2.connect(**params)


def apply_schema() -> None:
    migrations = sorted(MIGRATION_DIR.glob("*.sql"))
    if not migrations:
        raise FileNotFoundError(f"No migrations found in {MIGRATION_DIR}")

    with connect_db() as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            for migration in migrations:
                logger.info("Applying migration: %s", migration.name)
                cur.execute(migration.read_text(encoding="utf-8"))

    logger.info("Applied %d migration(s) successfully", len(migrations))


if __name__ == "__main__":
    try:
        apply_schema()
    except Exception as exc:
        logger.exception("Schema migration failed")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
