"""
Google Workspace OAuth App Risk Audit.
Handles OAuth2 flow, Directory + Reports API, scoring, and AI summaries.
No external google-auth dependency — all calls are plain REST via httpx.
"""

import os
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlencode
import httpx

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID",     "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://meisentinel.onrender.com/workspace/callback",
)

_SCOPES = " ".join([
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
])

# ── Classification ─────────────────────────────────────────────────────────────

_AI_KEYWORDS = frozenset([
    "chatgpt", "openai", "claude", "anthropic", "gemini", "bard", "copilot",
    "jasper", "copy.ai", "copyai", "otter.ai", "otter", "fireflies", "fathom",
    "perplexity", "grammarly", "writesonic", "rytr", "tome", "gamma",
    "beautiful.ai", "reclaim", "motion", "clockwise", "gong", "chorus",
    "avoma", "krisp", "tl;dv", "tldv", "tactiq", "runway", "elevenlabs",
    "hyperwrite", "wordtune", "notion ai", "ai writer", "ai assistant",
])

# Scope URI substring → (human label, severity)
_SCOPE_META: list[tuple[str, str, str]] = [
    ("mail.google.com",             "Full Gmail access",       "critical"),
    ("/auth/gmail.send",            "Send mail as user",       "critical"),
    ("/auth/gmail.modify",          "Read + modify Gmail",     "critical"),
    ("/auth/gmail.readonly",        "Read all Gmail",          "high"),
    ("/auth/gmail",                 "Gmail access",            "high"),
    ("/auth/drive.readonly",        "Read all Drive files",    "high"),
    ("/auth/drive.file",            "Access Drive files",      "medium"),
    ("/auth/drive",                 "Full Drive access",       "critical"),
    ("/auth/spreadsheets",          "Edit Sheets",             "high"),
    ("/auth/documents",             "Edit Docs",               "high"),
    ("/auth/calendar.readonly",     "Read Calendar",           "low"),
    ("/auth/calendar",              "Full Calendar access",    "medium"),
    ("/auth/contacts.readonly",     "Read Contacts",           "low"),
    ("/auth/contacts",              "Read/write Contacts",     "medium"),
    ("/auth/admin.directory",       "Admin directory",         "critical"),
    ("/auth/admin",                 "Admin access",            "critical"),
    ("/auth/userinfo.email",        "Email address",           "low"),
    ("/auth/userinfo.profile",      "Profile info",            "low"),
    ("openid",                      "Sign in with Google",     "low"),
]

_SCOPE_SENSITIVITY = {"critical": 95, "high": 75, "medium": 45, "low": 10}
_TIER_ORDER        = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# VT free tier: 4 req/min — serialize with a semaphore + 15s sleep
_VT_SEM = None

def _get_vt_sem():
    global _VT_SEM
    if _VT_SEM is None:
        _VT_SEM = asyncio.Semaphore(1)
    return _VT_SEM


# ── Auth helpers ───────────────────────────────────────────────────────────────

def build_auth_url(state: str) -> str:
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id":              GOOGLE_CLIENT_ID,
        "redirect_uri":           GOOGLE_REDIRECT_URI,
        "response_type":          "code",
        "scope":                  _SCOPES,
        "access_type":            "offline",
        "prompt":                 "consent",
        "include_granted_scopes": "false",
        "state":                  state,
    })


async def exchange_code(code: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri":  GOOGLE_REDIRECT_URI,
                "grant_type":    "authorization_code",
            },
        )
        r.raise_for_status()
        return r.json()


async def get_admin_email(access_token: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if r.status_code == 200:
                return r.json().get("email", "")
    except Exception:
        pass
    return ""


# ── Directory API ──────────────────────────────────────────────────────────────

async def _list_users(access_token: str) -> list[dict]:
    headers, users, npt = {"Authorization": f"Bearer {access_token}"}, [], None
    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            params = {"customer": "my_customer", "maxResults": 500, "orderBy": "email"}
            if npt:
                params["pageToken"] = npt
            r = await client.get(
                "https://admin.googleapis.com/admin/directory/v1/users",
                headers=headers, params=params,
            )
            if r.status_code == 403:
                raise RuntimeError(
                    "Access denied — you must be a Google Workspace super-admin."
                )
            r.raise_for_status()
            data = r.json()
            users.extend(data.get("users", []))
            npt = data.get("nextPageToken")
            if not npt:
                break
    return users


async def _list_user_tokens(
    access_token: str, email: str, client: httpx.AsyncClient
) -> list[dict]:
    try:
        r = await client.get(
            f"https://admin.googleapis.com/admin/directory/v1/users/{email}/tokens",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if r.status_code == 200:
            return r.json().get("items", [])
    except Exception:
        pass
    return []


# ── Reports API ────────────────────────────────────────────────────────────────

async def _fetch_all_token_events(
    access_token: str, days_back: int = 180
) -> dict[str, dict]:
    """Single paginated call → {client_id: {first_seen, last_seen}}."""
    headers = {"Authorization": f"Bearer {access_token}"}
    start   = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    events: dict[str, dict] = {}
    npt = None
    async with httpx.AsyncClient(timeout=60) as client:
        for _ in range(50):
            params = {"maxResults": 1000, "startTime": start}
            if npt:
                params["pageToken"] = npt
            try:
                r = await client.get(
                    "https://admin.googleapis.com/admin/reports/v1/activity/"
                    "users/all/applications/token",
                    headers=headers, params=params,
                )
                if r.status_code in (400, 403):
                    break
                r.raise_for_status()
                data = r.json()
                for item in data.get("items", []):
                    ts_str = item.get("id", {}).get("time", "")
                    cid    = next(
                        (
                            p.get("value", "")
                            for ev in item.get("events", [])
                            for p in ev.get("parameters", [])
                            if p.get("name") == "client_id"
                        ),
                        "",
                    )
                    if not cid or not ts_str:
                        continue
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except Exception:
                        continue
                    if cid not in events:
                        events[cid] = {"first_seen": ts, "last_seen": ts}
                    else:
                        if ts < events[cid]["first_seen"]:
                            events[cid]["first_seen"] = ts
                        if ts > events[cid]["last_seen"]:
                            events[cid]["last_seen"] = ts
                npt = data.get("nextPageToken")
                if not npt:
                    break
            except Exception:
                break
    return events


# ── Scoring ────────────────────────────────────────────────────────────────────

def _scope_label(scope: str) -> tuple[str, str]:
    for pat, label, sev in _SCOPE_META:
        if pat in scope:
            return label, sev
    return scope.split("/")[-1].replace(".", " ").title(), "low"


def _scope_sensitivity(scopes: list[str]) -> int:
    best = "low"
    for scope in scopes:
        for pat, _, sev in _SCOPE_META:
            if pat in scope:
                if _TIER_ORDER.get(sev, 0) > _TIER_ORDER.get(best, 0):
                    best = sev
                break
        else:
            if _TIER_ORDER.get("medium", 0) > _TIER_ORDER.get(best, 0):
                best = "medium"
    return _SCOPE_SENSITIVITY.get(best, 10)


def _inactivity_score(last_seen: Optional[datetime]) -> int:
    if last_seen is None:
        return 80
    days = (datetime.now(timezone.utc) - last_seen).days
    if days <= 7:    return 0
    if days <= 30:   return 15
    if days <= 90:   return 35
    if days <= 180:  return 60
    if days <= 365:  return 80
    return 100


def _is_ai_tool(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in _AI_KEYWORDS)


def _risk_tier(score: int) -> str:
    if score >= 70: return "remove"
    if score >= 35: return "review"
    return "keep"


def _risk_display(score: int) -> tuple[str, str]:
    if score >= 70: return "HIGH RISK",    "risk-high"
    if score >= 35: return "MEDIUM RISK",  "risk-med"
    return "LOW RISK", "risk-low"


def _extract_domain(app_name: str) -> str:
    """Best-effort: extract a checkable domain from app display name."""
    n = app_name.lower().split("(")[0].strip()
    for tld in (".com", ".ai", ".io", ".co", ".net", ".org"):
        if tld in n:
            for word in n.replace(",", " ").replace(";", " ").split():
                if tld in word and len(word) > 3:
                    return word.strip(".")
    return ""


# ── VirusTotal ─────────────────────────────────────────────────────────────────

async def _vt_domain(domain: str, vt_key: str) -> dict:
    if not vt_key or not domain:
        return {"malicious": 0, "suspicious": 0, "penalty": 0}
    async with _get_vt_sem():
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": vt_key},
                )
                if r.status_code not in (200,):
                    return {"malicious": 0, "suspicious": 0, "penalty": 0}
                s     = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal   = s.get("malicious",  0)
                sus   = s.get("suspicious", 0)
                total = sum(s.values()) or 1
                pen   = min(100, round(((mal / total * 80) + (sus / total * 20)) * 100))
                return {"malicious": mal, "suspicious": sus, "penalty": pen}
        except Exception:
            return {"malicious": 0, "suspicious": 0, "penalty": 0}
        finally:
            await asyncio.sleep(15)


# ── Claude summary ─────────────────────────────────────────────────────────────

async def _llm_app_summary(app: dict, anthropic_key: str) -> str:
    if not anthropic_key:
        return "AI summary unavailable — ANTHROPIC_API_KEY not configured."

    last_txt = "unknown"
    ls = app.get("last_seen")
    if ls:
        if isinstance(ls, str):
            ls = datetime.fromisoformat(ls)
        days = (datetime.now(timezone.utc) - ls).days
        last_txt = "today" if days == 0 else "yesterday" if days == 1 else f"{days} days ago"

    inst_txt = "unknown"
    fs = app.get("first_seen")
    if fs:
        if isinstance(fs, str):
            fs = datetime.fromisoformat(fs)
        months = (datetime.now(timezone.utc) - fs).days // 30
        inst_txt = f"~{months} months ago" if months > 0 else "this month"

    scopes_str = ", ".join(_scope_label(s)[0] for s in (app.get("scopes") or []))
    vt = app.get("vt") or {}
    vt_txt = (
        f"{vt['malicious']} malicious + {vt['suspicious']} suspicious detections on VirusTotal"
        if vt.get("malicious") or vt.get("suspicious")
        else "no VirusTotal detections"
    )

    prompt = (
        "You are a Google Workspace security analyst. Write a 2-3 sentence plain-English "
        "risk summary for a non-technical IT manager.\n\n"
        f"App: {app['name']}\n"
        f"Granted scopes: {scopes_str or 'none'}\n"
        f"Users with access: {len(app.get('users') or [])}\n"
        f"Installed: {inst_txt}\n"
        f"Last activity: {last_txt}\n"
        f"Vendor reputation: {vt_txt}\n"
        f"Risk score: {app['score']}/100\n\n"
        "State what the app can access, whether the activity level justifies keeping it, "
        "and what action to take. No bullet points. Plain paragraph only."
    )

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={
                    "model":      "claude-haiku-4-5",
                    "max_tokens": 200,
                    "messages":   [{"role": "user", "content": prompt}],
                },
            )
            r.raise_for_status()
            return r.json()["content"][0]["text"]
    except Exception:
        return f"AI summary temporarily unavailable. Risk score: {app['score']}/100."


# ── Main orchestrator ──────────────────────────────────────────────────────────

async def fetch_and_score_all_apps(
    access_token:  str,
    vt_key:        str,
    anthropic_key: str,
    session:       dict,
) -> None:
    """
    Full pipeline. Writes results into `session` dict in-place.
    Must be called as asyncio.create_task().
    """

    def _prog(msg: str, **kw):
        session["progress"]["message"] = msg
        session["progress"].update(kw)

    try:
        # 1 — Users
        _prog("Fetching workspace users…")
        users = await _list_users(access_token)
        _prog(f"Found {len(users)} users — scanning tokens…", users_found=len(users))

        # 2 — Tokens (bounded concurrency)
        sem = asyncio.Semaphore(8)

        async def _safe_tokens(email: str) -> list[dict]:
            async with sem:
                async with httpx.AsyncClient(timeout=15) as c:
                    return await _list_user_tokens(access_token, email, c)

        token_lists = await asyncio.gather(
            *[_safe_tokens(u["primaryEmail"]) for u in users],
            return_exceptions=True,
        )

        # 3 — Aggregate by client_id
        _prog("Aggregating app data…")
        raw: dict[str, dict] = {}
        for user, toks in zip(users, token_lists):
            if isinstance(toks, Exception):
                continue
            email = user["primaryEmail"]
            for tok in (toks or []):
                cid = tok.get("clientId", "")
                if not cid:
                    continue
                if cid not in raw:
                    raw[cid] = {
                        "id":           cid,
                        "name":         tok.get("displayText") or "Unknown App",
                        "scopes":       set(),
                        "users":        set(),
                        "first_seen":   None,
                        "last_seen":    None,
                        "is_ai":        False,
                        "vt":           {"malicious": 0, "suspicious": 0, "penalty": 0},
                        "domain":       "",
                        "score":        0,
                        "tier":         "review",
                        "risk_label":   "MEDIUM RISK",
                        "risk_class":   "risk-med",
                        "summary":      "",
                        "scope_details": [],
                    }
                raw[cid]["scopes"].update(tok.get("scopes") or [])
                raw[cid]["users"].add(email)

        total = len(raw)
        _prog(f"Found {total} unique apps — fetching activity…", total_apps=total)

        # 4 — Reports API (single batch call)
        events = await _fetch_all_token_events(access_token)
        for cid, ev in events.items():
            if cid in raw:
                raw[cid]["first_seen"] = ev["first_seen"]
                raw[cid]["last_seen"]  = ev["last_seen"]

        # 5 — Base scoring
        for app in raw.values():
            app["scopes"]        = list(app["scopes"])
            app["users"]         = list(app["users"])
            app["is_ai"]         = _is_ai_tool(app["name"])
            app["domain"]        = _extract_domain(app["name"])
            app["scope_details"] = [
                {"scope": s, "label": _scope_label(s)[0], "severity": _scope_label(s)[1]}
                for s in app["scopes"]
            ]
            app["_ss"] = _scope_sensitivity(app["scopes"])
            app["_ia"] = _inactivity_score(app.get("last_seen"))

        # 6 — VT enrichment (only for apps with extractable domains)
        vt_candidates = [a for a in raw.values() if a["domain"]]
        done = 0
        _prog(f"Checking vendor reputation (0/{len(vt_candidates)})…")

        async def _enrich_vt(app: dict):
            nonlocal done
            app["vt"] = await _vt_domain(app["domain"], vt_key)
            done += 1
            _prog(
                f"Checking reputation… ({done}/{len(vt_candidates)})",
                apps_processed=done,
            )

        await asyncio.gather(*[_enrich_vt(a) for a in vt_candidates])

        # 7 — Final scores
        for app in raw.values():
            app["score"] = min(
                100,
                round(app["_ss"] * 0.40 + app["_ia"] * 0.30 + app["vt"]["penalty"] * 0.30),
            )
            lbl, cls      = _risk_display(app["score"])
            app["risk_label"] = lbl
            app["risk_class"] = cls
            app["tier"]       = _risk_tier(app["score"])
            app.pop("_ss", None)
            app.pop("_ia", None)

        result = sorted(raw.values(), key=lambda a: -a["score"])

        # 8 — Claude summaries for top 20
        _prog("Generating AI summaries…")
        targets  = [a for a in result if a["tier"] in ("remove", "review")][:20]
        sum_sem  = asyncio.Semaphore(4)

        async def _gen(app: dict):
            async with sum_sem:
                app["summary"] = await _llm_app_summary(app, anthropic_key)

        await asyncio.gather(*[_gen(a) for a in targets])

        # 9 — Serialize datetimes for JSON
        for app in result:
            for f in ("first_seen", "last_seen"):
                v = app.get(f)
                if isinstance(v, datetime):
                    app[f] = v.isoformat()

        session["apps"]   = result
        session["status"] = "done"
        _prog(f"Complete — {len(result)} apps audited.", apps_processed=len(result))

    except Exception as exc:
        session["status"] = "error"
        session["error"]  = str(exc)
        session["progress"]["message"] = f"Error: {exc}"
