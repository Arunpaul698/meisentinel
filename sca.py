import asyncio
import io
import json
import re
import zipfile
from typing import NamedTuple

import httpx

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 15
_MAX_PACKAGES = 50  # cap to avoid huge batch requests


class Package(NamedTuple):
    name: str
    version: str
    ecosystem: str


# ── Manifest parsers ──────────────────────────────────────────────────────────

def _parse_requirements_txt(text: str) -> list[Package]:
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match name==version (exact pins only — what OSV needs)
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;,]+)", line)
        if m:
            packages.append(Package(m.group(1), m.group(2), "PyPI"))
    return packages


def _parse_package_json(text: str) -> list[Package]:
    packages = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return packages
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            # Strip semver range operators; OSV needs an exact version
            ver = re.sub(r"^[\^~>=<\s]+", "", ver).split(" ")[0]
            if re.match(r"^\d+\.\d+", ver):
                packages.append(Package(name, ver, "npm"))
    return packages


def _parse_package_lock(text: str) -> list[Package]:
    """package-lock.json v2/v3 — has exact resolved versions."""
    packages = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return packages
    for path, info in data.get("packages", {}).items():
        if not path or not isinstance(info, dict):
            continue
        name = info.get("name") or path.split("node_modules/")[-1]
        ver  = info.get("version", "")
        if name and re.match(r"^\d+\.\d+", ver):
            packages.append(Package(name, ver, "npm"))
    return packages


def _parse_pipfile_lock(text: str) -> list[Package]:
    packages = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return packages
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            ver = meta.get("version", "").lstrip("=")
            if ver and re.match(r"^\d+\.\d+", ver):
                packages.append(Package(name, ver, "PyPI"))
    return packages


_PARSERS = {
    "requirements.txt":  _parse_requirements_txt,
    "package.json":      _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "Pipfile.lock":      _parse_pipfile_lock,
}


def _extract_packages(file_bytes: bytes, filename: str) -> list[Package]:
    """Extract (name, version, ecosystem) from a manifest or archive."""
    fname = filename.lower()

    # Direct manifest upload
    for manifest_name, parser in _PARSERS.items():
        if fname == manifest_name.lower() or fname.endswith(f"/{manifest_name.lower()}"):
            try:
                return parser(file_bytes.decode("utf-8", errors="replace"))
            except Exception:
                return []

    # Archive: scan for embedded manifests
    if not (fname.endswith(".zip") or fname.endswith(".jar")
            or fname.endswith(".war") or fname.endswith(".ear")):
        return []

    packages = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for zname in zf.namelist():
                base = zname.split("/")[-1]
                if base in _PARSERS:
                    try:
                        content = zf.read(zname).decode("utf-8", errors="replace")
                        packages.extend(_PARSERS[base](content))
                    except Exception:
                        continue
    except Exception:
        pass
    return packages


# ── OSV severity helpers ──────────────────────────────────────────────────────

def _cvss_score(vuln: dict) -> float:
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS vector string — extract base score from /AV:... notation
        m = re.search(r"CVSS:\d+\.\d+/.*", score_str)
        if m:
            # Parse base score: last numeric segment before first /
            # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → need to compute
            # Simpler: use database_specific scores if present
            pass
    # Fallback: check database_specific
    db = vuln.get("database_specific", {})
    score = db.get("cvss_score") or db.get("severity_score") or 0
    try:
        return float(score)
    except (TypeError, ValueError):
        pass
    # Infer from severity string
    sev_str = (db.get("severity") or "").upper()
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}.get(sev_str, 0.0)


def _severity_label(vuln: dict) -> str:
    score = _cvss_score(vuln)
    if score >= 9.0:
        return "high"   # critical → high for our model
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    # No score — use aliases to guess
    aliases = " ".join(vuln.get("aliases", [])).upper()
    db_sev = (vuln.get("database_specific", {}).get("severity") or "").upper()
    for label, keywords in [
        ("high",   ["CRITICAL", "HIGH"]),
        ("medium", ["MODERATE", "MEDIUM"]),
        ("low",    ["LOW"]),
    ]:
        if db_sev in keywords or any(k in aliases for k in keywords):
            return label
    return "medium"


_SEV_WEIGHT = {"high": 40, "medium": 12, "low": 3}


# ── Main entry points ─────────────────────────────────────────────────────────

async def scan_sca(file_bytes: bytes, filename: str) -> dict:
    packages = _extract_packages(file_bytes, filename)

    if not packages:
        return {
            "applicable": False,
            "packages_scanned": 0,
            "findings": [],
            "score_contribution": 0,
        }

    packages = packages[:_MAX_PACKAGES]
    queries  = [
        {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
        for p in packages
    ]

    findings = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(_OSV_BATCH, json={"queries": queries})
            resp.raise_for_status()
            results = resp.json().get("results", [])

        for pkg, result in zip(packages, results):
            for vuln in result.get("vulns", []):
                cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                cve_ref = cve_ids[0] if cve_ids else vuln.get("id", "unknown")
                sev     = _severity_label(vuln)
                summary = vuln.get("summary") or vuln.get("details", "")[:120]
                findings.append({
                    "signal":    "known_cve",
                    "cve":       cve_ref,
                    "osv_id":    vuln.get("id"),
                    "package":   f"{pkg.name}@{pkg.version} ({pkg.ecosystem})",
                    "detail":    f"{cve_ref} in {pkg.name}@{pkg.version}: {summary}",
                    "severity":  sev,
                })
    except Exception as exc:
        findings.append({
            "signal":   "sca_error",
            "detail":   f"OSV query failed: {exc}",
            "severity": "low",
        })

    # Deduplicate by CVE (same vuln can appear via multiple packages)
    seen_cves: set[str] = set()
    deduped   = []
    for f in findings:
        key = f.get("cve") or f.get("detail")
        if key not in seen_cves:
            seen_cves.add(key)
            deduped.append(f)

    score = min(100, sum(_SEV_WEIGHT.get(f["severity"], 0) for f in deduped))

    return {
        "applicable":       True,
        "packages_scanned": len(packages),
        "findings":         deduped,
        "score_contribution": score,
    }
