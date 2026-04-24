"""
Tier A full integration test — runs all 5 dimensions locally.
Dims 1 (VirusTotal) and 6 (threat intel) are mocked with realistic data.
Dims 3 (static), 4 (signing), and 5 (SCA) run for real.
"""
import asyncio
import io
import json
import struct
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

# ── Test payloads ─────────────────────────────────────────────────────────────

def make_suspicious_pe() -> bytes:
    """Minimal PE with UPX marker + injection API strings (triggers YARA)."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    pe  = dos + b"\x00" * (64 - len(dos)) + b"PE\x00\x00" + b"\x00" * 50
    return pe + b"UPX0UPX1UPX!" + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"


def make_zip_with_vulns() -> bytes:
    """ZIP containing requirements.txt with known-vulnerable packages."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("requirements.txt", (
            "django==2.2.0\n"       # CVE-2019-14232, CVE-2021-33203, etc.
            "pillow==8.0.0\n"       # CVE-2021-25289, CVE-2021-27921
            "requests==2.25.0\n"   # no known CVEs at this version
            "cryptography==3.2.0\n" # CVE-2020-25659
        ))
    return buf.getvalue()


def make_clean_script() -> bytes:
    return b"#!/usr/bin/env python3\nprint('hello world')\n"


# ── Mock responses ────────────────────────────────────────────────────────────

MOCK_VT_STATS_CLEAN    = {"malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 4}
MOCK_VT_STATS_MODERATE = {"malicious": 3, "suspicious": 2, "harmless": 60, "undetected": 7}
MOCK_VT_STATS_HIGH     = {"malicious": 42, "suspicious": 5, "harmless": 15, "undetected": 10}

MOCK_THREAT_CLEAN = {"findings": [], "score_contribution": 0}
MOCK_THREAT_HIT   = {
    "findings": [{
        "source": "MalwareBazaar",
        "signal": "known_malware_hash",
        "detail": "Hash confirmed in MalwareBazaar — signature: Emotet, type: exe, tags: botnet, loader",
        "severity": "high",
    }],
    "score_contribution": 80,
}

MOCK_OSV_VULNS = {
    "results": [
        {"vulns": [{"id": "GHSA-rhm9-p9w5-fwm7", "aliases": ["CVE-2019-14232"],
                    "summary": "Django denial of service in string filter with large input",
                    "database_specific": {"severity": "HIGH"}}]},
        {"vulns": [{"id": "GHSA-j7hp-h8jx-5ppr", "aliases": ["CVE-2021-25289"],
                    "summary": "Pillow buffer overflow in SGI RLE image files",
                    "database_specific": {"severity": "HIGH"}}]},
        {"vulns": []},
        {"vulns": [{"id": "GHSA-w7pp-m8wf-vj6r", "aliases": ["CVE-2020-25659"],
                    "summary": "cryptography RSA decryption Bleichenbacher timing oracle",
                    "database_specific": {"severity": "MEDIUM"}}]},
    ]
}


# ── Test runner ───────────────────────────────────────────────────────────────

async def run_test(label: str, file_bytes: bytes, filename: str,
                   vt_stats: dict, mock_threat: dict, osv_body: dict):
    from static_analysis import analyze_static
    from code_signing import check_signing
    from sca import scan_sca
    from main import compute_risk_score, risk_label

    print(f"\n{'='*60}")
    print(f"TEST: {label}")
    print(f"File: {filename}  ({len(file_bytes):,} bytes)")
    print("="*60)

    # Mock httpx for OSV (SCA) and abuse.ch (threat intel already mocked via argument)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = osv_body

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("sca.httpx.AsyncClient", return_value=mock_client):
        static, signing, sca = await asyncio.gather(
            analyze_static(file_bytes, filename),
            check_signing(file_bytes, filename),
            scan_sca(file_bytes, filename),
        )

    threat = mock_threat
    score  = compute_risk_score(vt_stats, static, threat, signing, sca)
    label_str, color = risk_label(score)

    result = {
        "vt_stats":        vt_stats,
        "static_analysis": static,
        "threat_intel":    threat,
        "code_signing":    signing,
        "sca":             sca,
        "risk_score":      score,
        "risk_label":      label_str,
        "risk_color":      color,
    }

    # Pretty print per dimension
    def dim_summary(name, data):
        if data is None:
            return f"  {name}: skipped"
        findings = data.get("findings", [])
        sc       = data.get("score_contribution", 0)
        if not findings:
            applicable = data.get("applicable", True)
            if applicable is False:
                return f"  {name}: N/A for this file type"
            signed = data.get("signed")
            if signed is True and data.get("verified") is True:
                return f"  {name}: ✓ valid signature ({data.get('signer') or 'unknown signer'})"
            return f"  {name}: clean (score +{sc})"
        lines = [f"  {name}: {len(findings)} finding(s)  [score +{sc}]"]
        for f in findings[:3]:
            sev = f.get("severity", "?").upper()
            lines.append(f"    [{sev}] {f.get('detail', '')[:80]}")
        return "\n".join(lines)

    print(dim_summary("Dim 1  VirusTotal  ", {"findings": [{"severity": "high", "detail": f"{vt_stats.get('malicious',0)} malicious detections"}] if vt_stats.get('malicious',0) > 0 else [], "score_contribution": 0}))
    print(dim_summary("Dim 3  Static      ", static))
    print(dim_summary("Dim 4  Code signing", signing))
    print(dim_summary("Dim 5  SCA         ", sca))
    print(dim_summary("Dim 6  Threat intel", threat))
    print(f"\n  ▶  RISK SCORE: {score}/100  —  {label_str}  ({color})")


async def main():
    print("\nMeisentis Tier A — Full Integration Test")
    print("Dims 1 & 6 mocked | Dims 3, 4, 5 live\n")

    await run_test(
        label      = "Scenario A: Clean script (no signals)",
        file_bytes = make_clean_script(),
        filename   = "deploy.sh",
        vt_stats   = MOCK_VT_STATS_CLEAN,
        mock_threat= MOCK_THREAT_CLEAN,
        osv_body   = {"results": []},
    )

    await run_test(
        label      = "Scenario B: Suspicious PE (packer + injection APIs)",
        file_bytes = make_suspicious_pe(),
        filename   = "suspicious.exe",
        vt_stats   = MOCK_VT_STATS_MODERATE,
        mock_threat= MOCK_THREAT_CLEAN,
        osv_body   = {"results": []},
    )

    await run_test(
        label      = "Scenario C: ZIP with vulnerable dependencies",
        file_bytes = make_zip_with_vulns(),
        filename   = "release.zip",
        vt_stats   = MOCK_VT_STATS_CLEAN,
        mock_threat= MOCK_THREAT_CLEAN,
        osv_body   = MOCK_OSV_VULNS,
    )

    await run_test(
        label      = "Scenario D: Known malware (all dims firing)",
        file_bytes = make_suspicious_pe(),
        filename   = "malware.exe",
        vt_stats   = MOCK_VT_STATS_HIGH,
        mock_threat= MOCK_THREAT_HIT,
        osv_body   = {"results": []},
    )


asyncio.run(main())
