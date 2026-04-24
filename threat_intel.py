import asyncio
import httpx

_TIMEOUT = 10  # abuse.ch APIs are fast; fail quickly rather than block the scan

_SEV_WEIGHT = {"high": 80, "medium": 30, "low": 10}


async def _malwarebazaar(client: httpx.AsyncClient, sha256: str) -> list:
    findings = []
    try:
        r = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") == "ok" and body.get("data"):
            hit = body["data"][0]
            tags = ", ".join(hit.get("tags") or []) or "none"
            findings.append({
                "source": "MalwareBazaar",
                "signal": "known_malware_hash",
                "detail": (
                    f"Hash confirmed in MalwareBazaar — "
                    f"signature: {hit.get('signature') or 'unknown'}, "
                    f"type: {hit.get('file_type') or 'unknown'}, "
                    f"tags: {tags}"
                ),
                "severity": "high",
            })
    except Exception:
        pass
    return findings


async def _threatfox_hash(client: httpx.AsyncClient, sha256: str) -> list:
    findings = []
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_hash", "hash": sha256},
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") == "ok" and body.get("data"):
            for ioc in body["data"][:3]:  # cap at 3 hits
                findings.append({
                    "source": "ThreatFox",
                    "signal": "known_c2_ioc",
                    "detail": (
                        f"Hash linked to {ioc.get('malware') or 'unknown malware'} "
                        f"({ioc.get('threat_type') or 'unknown threat type'}), "
                        f"confidence: {ioc.get('confidence_level', 0)}%"
                    ),
                    "severity": "high",
                })
    except Exception:
        pass
    return findings


async def _urlhaus(client: httpx.AsyncClient, url: str) -> list:
    findings = []
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") == "is_available":
            status = body.get("url_status", "unknown")
            tags   = ", ".join(body.get("tags") or []) or "none"
            findings.append({
                "source": "URLhaus",
                "signal": "malware_distribution_url",
                "detail": (
                    f"URL found in URLhaus malware distribution list — "
                    f"status: {status}, threat: {body.get('threat') or 'unknown'}, "
                    f"tags: {tags}"
                ),
                "severity": "high",
            })
    except Exception:
        pass
    return findings


async def _threatfox_url(client: httpx.AsyncClient, url: str) -> list:
    findings = []
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": url},
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") == "ok" and body.get("data"):
            for ioc in body["data"][:3]:
                findings.append({
                    "source": "ThreatFox",
                    "signal": "known_malicious_url",
                    "detail": (
                        f"URL linked to {ioc.get('malware') or 'unknown malware'} "
                        f"({ioc.get('threat_type') or 'unknown'}), "
                        f"confidence: {ioc.get('confidence_level', 0)}%"
                    ),
                    "severity": "high",
                })
    except Exception:
        pass
    return findings


def _build_result(findings: list) -> dict:
    score = min(100, sum(_SEV_WEIGHT.get(f["severity"], 0) for f in findings))
    return {"findings": findings, "score_contribution": score}


async def lookup_hash(sha256: str) -> dict:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        results = await asyncio.gather(
            _malwarebazaar(client, sha256),
            _threatfox_hash(client, sha256),
        )
    findings = [f for group in results for f in group]
    return _build_result(findings)


async def lookup_url(url: str) -> dict:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        results = await asyncio.gather(
            _urlhaus(client, url),
            _threatfox_url(client, url),
        )
    findings = [f for group in results for f in group]
    return _build_result(findings)
