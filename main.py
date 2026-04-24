import os
import hashlib
import httpx
import asyncio
import json
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pdf_report import generate_pdf
from static_analysis import analyze_static

app = FastAPI(title="SSA Agent MVP")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def vt_poll(client, analysis_id: str) -> dict:
    """Poll a VT analysis until completed, return stats."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    for _ in range(24):          # up to 2 min
        await asyncio.sleep(5)
        r = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
        r.raise_for_status()
        data = r.json()["data"]
        if data["attributes"]["status"] == "completed":
            return data["attributes"]["stats"]
    return {}


async def vt_scan_file(file_bytes: bytes, filename: str) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": (filename, file_bytes)},
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]
        return await vt_poll(client, analysis_id)


async def vt_scan_url(url: str) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient(timeout=120) as client:
        # Step 1: submit URL
        resp = await client.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": url},          # form-encoded, not raw string
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]
        # Step 2: poll for result
        return await vt_poll(client, analysis_id)


# ── Risk scoring ──────────────────────────────────────────────────────────────

def compute_risk_score(vt_stats: dict, static: dict | None = None) -> int:
    malicious  = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)
    total      = sum(vt_stats.values()) or 1
    vt_score   = (malicious / total * 80) + (suspicious / total * 20)
    vt_score   = min(100, round(vt_score * 100))

    if not static or not static.get("findings"):
        return vt_score

    static_score = static["score_contribution"]
    # Blend: VT carries 70%, static 30%; either can independently floor the result
    blended = round(vt_score * 0.7 + static_score * 0.3)
    # A high-severity static finding guarantees at least MEDIUM risk
    high_findings = [f for f in static["findings"] if f["severity"] == "high"]
    if high_findings:
        blended = max(blended, 35)
    return min(100, blended)


def risk_label(score: int) -> tuple:
    if score >= 70:
        return "HIGH RISK", "#ff3b30"
    elif score >= 35:
        return "MEDIUM RISK", "#ff9500"
    return "LOW RISK", "#34c759"


# ── Claude AI summary ─────────────────────────────────────────────────────────

async def llm_summary(target: str, vt_stats: dict, score: int, static: dict | None = None) -> str:
    if not ANTHROPIC_API_KEY:
        return "AI summary unavailable — ANTHROPIC_API_KEY not configured on the server."

    static_section = ""
    if static and static.get("findings"):
        high = [f["detail"] for f in static["findings"] if f["severity"] == "high"]
        med  = [f["detail"] for f in static["findings"] if f["severity"] == "medium"]
        if high or med:
            static_section = (
                f"\nStatic Analysis Findings: {json.dumps({'high': high, 'medium': med})}"
            )

    prompt = (
        f"You are a software security analyst. Summarize this multi-signal scan result "
        f"in 3-4 concise sentences for a non-technical business audience.\n\n"
        f"Target: {target}\n"
        f"Risk Score: {score}/100\n"
        f"VirusTotal Stats: {json.dumps(vt_stats)}"
        f"{static_section}\n\n"
        f"Be direct. State if it's safe or not, why, and what action to take. "
        f"Do not use bullet points. Plain paragraph only."
    )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 300,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    except httpx.HTTPStatusError as e:
        print(f"[Claude error] {e.response.status_code}: {e.response.text}")
        return (
            f"AI summary temporarily unavailable (API error {e.response.status_code}). "
            f"Risk score: {score}/100. "
            f"VirusTotal flagged {vt_stats.get('malicious', 0)} malicious "
            f"and {vt_stats.get('suspicious', 0)} suspicious out of "
            f"{sum(vt_stats.values())} engines."
        )
    except Exception as e:
        print(f"[Claude error] {e}")
        return (
            f"AI summary temporarily unavailable. "
            f"Risk score: {score}/100. "
            f"VirusTotal: {vt_stats.get('malicious', 0)} malicious, "
            f"{vt_stats.get('suspicious', 0)} suspicious."
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(400, "VIRUSTOTAL_API_KEY not set on server")
    file_bytes = await file.read()
    sha256     = hashlib.sha256(file_bytes).hexdigest()

    vt_stats, static = await asyncio.gather(
        vt_scan_file(file_bytes, file.filename),
        analyze_static(file_bytes, file.filename),
    )

    score        = compute_risk_score(vt_stats, static)
    label, color = risk_label(score)
    summary      = await llm_summary(file.filename, vt_stats, score, static)
    return {
        "target":          file.filename,
        "type":            "file",
        "sha256":          sha256,
        "vt_stats":        vt_stats,
        "static_analysis": static,
        "risk_score":      score,
        "risk_label":      label,
        "risk_color":      color,
        "summary":         summary,
    }


@app.post("/scan/url")
async def scan_url(url: str = Form(...)):
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(400, "VIRUSTOTAL_API_KEY not set on server")
    vt_stats     = await vt_scan_url(url)
    score        = compute_risk_score(vt_stats)
    label, color = risk_label(score)
    summary      = await llm_summary(url, vt_stats, score)
    return {
        "target":     url,
        "type":       "url",
        "vt_stats":   vt_stats,
        "risk_score": score,
        "risk_label": label,
        "risk_color": color,
        "summary":    summary,
    }


@app.post("/report/pdf")
async def export_pdf(scan_data: dict):
    try:
        pdf_bytes = generate_pdf(scan_data)
        target    = scan_data.get("target", "report").replace("/", "_").replace(":", "")[:40]
        filename  = f"SSA_Report_{target}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {str(e)}")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "virustotal_key_set": bool(VIRUSTOTAL_API_KEY),
        "anthropic_key_set":  bool(ANTHROPIC_API_KEY),
    }
