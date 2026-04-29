"""
Google OAuth2 flow using google-auth-oauthlib + SQLite token persistence.
Handles /auth/google/start and /auth/google/callback.
"""

import os
import asyncio
import sqlite3
from datetime import timezone
from functools import partial
from pathlib import Path

from google_auth_oauthlib.flow import Flow

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID",     "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://meisentinel.onrender.com/auth/google/callback",
)

SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
]

DB_PATH = Path("tokens.db")

# ── SQLite ─────────────────────────────────────────────────────────────────────

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            domain        TEXT PRIMARY KEY,
            admin_email   TEXT NOT NULL,
            access_token  TEXT NOT NULL,
            refresh_token TEXT,
            token_expiry  TEXT,
            created_at    TEXT DEFAULT (datetime('now')),
            updated_at    TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def save_tokens(domain: str, admin_email: str, creds) -> None:
    expiry = creds.expiry.replace(tzinfo=timezone.utc).isoformat() if creds.expiry else None
    conn   = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO tenants (domain, admin_email, access_token, refresh_token, token_expiry, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(domain) DO UPDATE SET
            admin_email   = excluded.admin_email,
            access_token  = excluded.access_token,
            refresh_token = COALESCE(excluded.refresh_token, tenants.refresh_token),
            token_expiry  = excluded.token_expiry,
            updated_at    = datetime('now')
    """, (domain, admin_email, creds.token, creds.refresh_token, expiry))
    conn.commit()
    conn.close()


def get_stored_tokens(domain: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute(
        "SELECT domain, admin_email, access_token, refresh_token, token_expiry, updated_at "
        "FROM tenants WHERE domain = ?",
        (domain,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "domain":        row[0],
        "admin_email":   row[1],
        "access_token":  row[2],
        "refresh_token": row[3],
        "token_expiry":  row[4],
        "updated_at":    row[5],
    }


def list_tenants() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT domain, admin_email, token_expiry, updated_at FROM tenants ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [{"domain": r[0], "admin_email": r[1], "token_expiry": r[2], "updated_at": r[3]} for r in rows]


# ── OAuth flow helpers ─────────────────────────────────────────────────────────

def _client_config() -> dict:
    return {
        "web": {
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
            "token_uri":     "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI],
        }
    }


def get_auth_url(state: str) -> str:
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=GOOGLE_REDIRECT_URI)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes=False,
        prompt="consent",
        state=state,
    )
    return auth_url


def _sync_exchange(code: str, state: str):
    """Blocking token exchange — run via executor."""
    flow = Flow.from_client_config(
        _client_config(), scopes=SCOPES, redirect_uri=GOOGLE_REDIRECT_URI, state=state,
    )
    flow.fetch_token(code=code)
    return flow.credentials


async def exchange_code(code: str, state: str):
    """Async wrapper around the blocking google-auth-oauthlib token exchange."""
    loop  = asyncio.get_running_loop()
    creds = await loop.run_in_executor(None, partial(_sync_exchange, code, state))
    return creds
