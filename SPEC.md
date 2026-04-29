# Meisentis — Product Specification

## What We're Building

Meisentis is a security assessment platform for IT and security teams. It has two core products. The first is a **file and URL scanner**: users upload a file (up to 500 MB) or paste a URL, and the system runs it through five analysis dimensions — VirusTotal multi-engine AV (Dim 1), static binary analysis using YARA rules and pefile (Dim 3), Authenticode code-signing validation via osslsigncode (Dim 4), software composition analysis against the OSV CVE database (Dim 5), and abuse.ch threat intelligence from MalwareBazaar, ThreatFox, and URLhaus (Dim 6). Results are blended into a single 0–100 risk score, bucketed into GREEN (safe), YELLOW (review), or RED (block), summarised by Claude AI in plain English, and exportable as a PDF report. The second product is a **Google Workspace OAuth App Risk Audit**: a Workspace super-admin connects their tenant via OAuth, and the system inventories every third-party app that has been granted OAuth access, scores each one for risk, flags AI-related tools, and surfaces Claude-generated removal recommendations per app.

## Architecture

The backend is a FastAPI service deployed on Render (`https://meisentinel.onrender.com`). The frontend is static HTML/CSS/JS on GitHub Pages (`https://meisentis.com`). There is no database yet (Tier B); all session state is held in-memory on the backend. Long-running scan requests use `StreamingResponse` with `\n` keepalive bytes every 10 s to prevent Render's 55-second proxy idle-timeout. The backend also exposes an MCP server at `/mcp` (via `fastapi-mcp`) with four tools — `scan_file_base64_mcp`, `scan_url_mcp`, `scan_hash_mcp`, `health_mcp` — that any Claude-powered agent can call. All free-text fields sourced from scanned content are wrapped in `<scanned_content>` tags as a prompt-injection mitigation.

---

## File / URL Risk Score Formula

```
risk_score = min(100,
    vt_score       × 0.50
  + static_score   × 0.18
  + threat_score   × 0.14
  + signing_score  × 0.08
  + sca_score      × 0.10
)
```

**Hard floors** — any of these forces `risk_score ≥ 35` (YELLOW) regardless of the weighted sum:
- Threat-intel hit (MalwareBazaar / ThreatFox match)
- Any HIGH-severity static finding
- PE file with a signature present but `verified = False`
- Any HIGH-severity CVE (CVSS ≥ 7.0) from SCA

**Risk tiers:** 0–34 = GREEN · 35–69 = YELLOW · 70–100 = RED

---

## Workspace OAuth App Risk Score Formula

```
risk_score = min(100,
    scope_sensitivity × 0.40
  + inactivity        × 0.30
  + vt_reputation     × 0.30
)
```

**Risk tiers:** 0–34 = keep · 35–69 = review · 70–100 = remove

---

## Scope Severity Table (Workspace Audit)

| Severity | Score | Scopes |
|----------|-------|--------|
| critical | 95 | `mail.google.com`, `/auth/gmail.send`, `/auth/gmail.modify`, `/auth/drive` (full), `/auth/admin.*` |
| high     | 75 | `/auth/gmail.readonly`, `/auth/drive.readonly`, `/auth/spreadsheets`, `/auth/documents` |
| medium   | 45 | `/auth/calendar`, `/auth/contacts`, `/auth/drive.file` |
| low      | 10 | `/auth/userinfo.*`, `openid`, `/auth/calendar.readonly`, `/auth/contacts.readonly` |

Unknown scopes (not in the table) are treated as **medium** (45).

**Inactivity score:** 0 days inactive → 0 · ≤30 days → 15 · ≤90 days → 35 · ≤180 days → 60 · ≤365 days → 80 · >365 days or never seen → 100.

---

## AI Vendor Curated List

The following keywords trigger the `is_ai = true` flag on any Workspace OAuth app whose display name contains them (case-insensitive substring match):

```
chatgpt, openai, claude, anthropic, gemini, bard, copilot,
jasper, copy.ai, copyai, otter.ai, otter, fireflies, fathom,
perplexity, grammarly, writesonic, rytr, tome, gamma,
beautiful.ai, reclaim, motion, clockwise, gong, chorus,
avoma, krisp, tl;dv, tldv, tactiq, runway, elevenlabs,
hyperwrite, wordtune, notion ai, ai writer, ai assistant
```

---

## Key Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `VIRUSTOTAL_API_KEY` | Yes | All scan endpoints |
| `ANTHROPIC_API_KEY` | Yes | Claude AI summaries |
| `GOOGLE_CLIENT_ID` | Workspace only | OAuth consent screen |
| `GOOGLE_CLIENT_SECRET` | Workspace only | Token exchange |
| `GOOGLE_REDIRECT_URI` | Workspace only | Must match Cloud Console exactly |
| `MEISENTIS_MCP_TOKEN` | Optional | Bearer auth for `/mcp/*` endpoints |
| `DATABASE_URL` | Tier B | Scan history persistence (not yet active) |

---

## File Layout

```
/
├── main.py               FastAPI backend — all endpoints
├── google_workspace.py   Workspace OAuth audit pipeline
├── static_analysis.py    YARA + pefile (Dim 3)
├── threat_intel.py       abuse.ch lookups (Dim 6)
├── code_signing.py       Authenticode validation (Dim 4)
├── sca.py                OSV CVE scan (Dim 5)
├── pdf_report.py         ReportLab PDF generator
├── mcp_models.py         Pydantic response models for MCP tools
├── rules/static.yar      YARA rules (8 rules)
├── requirements.txt
├── landing.html          Marketing / product page
├── portal.html           File + URL scan UI
├── oauth.html            Workspace OAuth audit dashboard (in progress)
├── dashboard.html        Scan history dashboard
├── shared.js             Shared nav + BACKEND constant
├── .env                  Local secrets (gitignored)
└── .env.example          Committed template — copy to .env and fill in
```
