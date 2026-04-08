import os
import hashlib
import httpx
import asyncio
import json
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from typing import Optional
from pdf_report import generate_pdf

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

async def vt_scan_file(file_bytes: bytes, filename: str) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": (filename, file_bytes)}
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]
        for _ in range(18):
            await asyncio.sleep(5)
            r = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
            r.raise_for_status()
            data = r.json()["data"]
            if data["attributes"]["status"] == "completed":
                return data["attributes"]["stats"]
    return {}

async def vt_scan_url(url: str) -> dict:
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(f"{VT_BASE}/urls", headers=headers, data=f"url={url}")
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]
        for _ in range(18):
            await asyncio.sleep(5)
            r = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
            r.raise_for_status()
            data = r.json()["data"]
            if data["attributes"]["status"] == "completed":
                return data["attributes"]["stats"]
    return {}

def compute_risk_score(vt_stats: dict) -> int:
    malicious  = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)
    total      = sum(vt_stats.values()) or 1
    raw = (malicious / total * 80) + (suspicious / total * 20)
    return min(100, round(raw * 100))

def risk_label(score: int) -> tuple:
    if score >= 70:
        return "HIGH RISK", "#ff3b30"
    elif score >= 35:
        return "MEDIUM RISK", "#ff9500"
    return "LOW RISK", "#34c759"

async def llm_summary(target: str, vt_stats: dict, score: int) -> str:
    if not ANTHROPIC_API_KEY:
        return "AI summary unavailable — ANTHROPIC_API_KEY not configured on the server."

    prompt = (
        f"You are a software security analyst. Summarize this VirusTotal scan result "
        f"in 3-4 concise sentences for a non-technical business audience.\n\n"
        f"Target: {target}\n"
        f"Risk Score: {score}/100\n"
        f"VirusTotal Stats: {json.dumps(vt_stats)}\n\n"
        f"Be direct. State if it's safe or not, why, and what action to take. "
        f"Do not use bullet points. Plain paragraph only."
    )

    payload = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}]
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    except httpx.HTTPStatusError as e:
        print(f"[Claude API error] {e.response.status_code}: {e.response.text}")
        return (
            f"AI summary temporarily unavailable (API error {e.response.status_code}). "
            f"Risk score: {score}/100. "
            f"VirusTotal flagged {vt_stats.get('malicious', 0)} engines as malicious "
            f"and {vt_stats.get('suspicious', 0)} as suspicious out of "
            f"{sum(vt_stats.values())} total."
        )
    except Exception as e:
        print(f"[Claude API error] {e}")
        return (
            f"AI summary temporarily unavailable. "
            f"Risk score: {score}/100. "
            f"VirusTotal flagged {vt_stats.get('malicious', 0)} malicious "
            f"and {vt_stats.get('suspicious', 0)} suspicious detections."
        )

@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(400, "VIRUSTOTAL_API_KEY not set on server")
    file_bytes   = await file.read()
    sha256       = hashlib.sha256(file_bytes).hexdigest()
    vt_stats     = await vt_scan_file(file_bytes, file.filename)
    score        = compute_risk_score(vt_stats)
    label, color = risk_label(score)
    summary      = await llm_summary(file.filename, vt_stats, score)
    return {
        "target":     file.filename,
        "type":       "file",
        "sha256":     sha256,
        "vt_stats":   vt_stats,
        "risk_score": score,
        "risk_label": label,
        "risk_color": color,
        "summary":    summary
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
        "summary":    summary
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
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
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
