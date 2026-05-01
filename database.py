"""
Supabase/Postgres persistence for scan results.
Gracefully no-ops when DATABASE_URL is not set (dev / free-Render mode).
"""

import os
import json
import asyncio
import logging

import asyncpg

DATABASE_URL: str = os.getenv("DATABASE_URL", "")

_pool: asyncpg.Pool | None = None
_log = logging.getLogger("database")

# ── Pool lifecycle ─────────────────────────────────────────────────────────────

async def init_pool() -> None:
    global _pool
    if not DATABASE_URL:
        _log.info("DATABASE_URL not set — scan persistence disabled")
        return
    try:
        # Supabase connection strings use the postgres:// scheme
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        _pool = await asyncpg.create_pool(url, min_size=1, max_size=5, command_timeout=30)
        await _init_schema()
        _log.info("Postgres pool ready")
    except Exception as exc:
        _log.warning("Could not connect to Postgres (%s) — persistence disabled", exc)
        _pool = None


async def _init_schema() -> None:
    async with _pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                scan_type  TEXT        NOT NULL,
                target     TEXT        NOT NULL,
                sha256     TEXT,
                risk_score INTEGER     NOT NULL,
                risk_tier  TEXT        NOT NULL,
                risk_label TEXT,
                ai_summary TEXT,
                result     JSONB       NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS scans_created_at_idx
                ON scans (created_at DESC);
            CREATE INDEX IF NOT EXISTS scans_risk_tier_idx
                ON scans (risk_tier);
            CREATE INDEX IF NOT EXISTS scans_sha256_idx
                ON scans (sha256) WHERE sha256 IS NOT NULL;
        """)


# ── Write ──────────────────────────────────────────────────────────────────────

async def save_scan(result: dict) -> None:
    """Fire-and-forget: persist a completed scan result. Silent on failure."""
    if _pool is None:
        return
    score = result.get("risk_score", 0)
    tier  = "RED" if score >= 70 else "YELLOW" if score >= 35 else "GREEN"
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scans
                    (scan_type, target, sha256, risk_score, risk_tier, risk_label, ai_summary, result)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                """,
                result.get("type", "unknown"),
                result.get("target", ""),
                result.get("sha256"),
                score,
                tier,
                result.get("risk_label"),
                result.get("summary"),
                json.dumps(result),
            )
    except Exception as exc:
        _log.warning("save_scan failed: %s", exc)


# ── Read ───────────────────────────────────────────────────────────────────────

async def get_scans(
    limit: int = 50,
    offset: int = 0,
    tier: str | None = None,
) -> list[dict]:
    """Return recent scans, newest first. Returns [] when DB unavailable."""
    if _pool is None:
        return []
    try:
        async with _pool.acquire() as conn:
            if tier:
                rows = await conn.fetch(
                    "SELECT id, scan_type, target, sha256, risk_score, risk_tier, risk_label, "
                    "ai_summary, created_at FROM scans WHERE risk_tier = $1 "
                    "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    tier.upper(), limit, offset,
                )
            else:
                rows = await conn.fetch(
                    "SELECT id, scan_type, target, sha256, risk_score, risk_tier, risk_label, "
                    "ai_summary, created_at FROM scans "
                    "ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    limit, offset,
                )
        return [_row_to_dict(r) for r in rows]
    except Exception as exc:
        _log.warning("get_scans failed: %s", exc)
        return []


async def get_scan_by_id(scan_id: str) -> dict | None:
    """Fetch a single scan result blob by UUID."""
    if _pool is None:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, scan_type, target, sha256, risk_score, risk_tier, "
                "risk_label, ai_summary, result, created_at FROM scans WHERE id = $1",
                scan_id,
            )
        if not row:
            return None
        d = _row_to_dict(row)
        d["result"] = json.loads(row["result"])
        return d
    except Exception as exc:
        _log.warning("get_scan_by_id failed: %s", exc)
        return None


async def get_stats() -> dict:
    """Summary counts by tier for the dashboard."""
    if _pool is None:
        return {"total": 0, "red": 0, "yellow": 0, "green": 0, "db_connected": False}
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT risk_tier, COUNT(*) AS n FROM scans GROUP BY risk_tier"
            )
        counts = {r["risk_tier"]: r["n"] for r in rows}
        return {
            "total":        sum(counts.values()),
            "red":          counts.get("RED", 0),
            "yellow":       counts.get("YELLOW", 0),
            "green":        counts.get("GREEN", 0),
            "db_connected": True,
        }
    except Exception as exc:
        _log.warning("get_stats failed: %s", exc)
        return {"total": 0, "red": 0, "yellow": 0, "green": 0, "db_connected": False}


def _row_to_dict(row) -> dict:
    d = dict(row)
    if "id" in d:
        d["id"] = str(d["id"])
    if "created_at" in d and d["created_at"]:
        d["created_at"] = d["created_at"].isoformat()
    return d
