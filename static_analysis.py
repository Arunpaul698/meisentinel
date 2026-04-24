import asyncio
import math
import os

try:
    import pefile
    _pefile_ok = True
except ImportError:
    _pefile_ok = False

try:
    import yara
    _yara_ok = True
except ImportError:
    _yara_ok = False

_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "static.yar")
_yara_rules = None

_KNOWN_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata",
    ".rsrc", ".reloc", ".pdata", ".tls", ".debug", ".cfg",
    ".rodata", ".got", ".plt",
}

_SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx":       "high",
    "WriteProcessMemory":   "high",
    "CreateRemoteThread":   "high",
    "NtUnmapViewOfSection": "high",
    "ZwUnmapViewOfSection": "high",
    "RtlCreateUserThread":  "high",
    "NtCreateThread":       "high",
    "SetThreadContext":      "high",
    "VirtualAlloc":         "medium",
    "IsDebuggerPresent":    "medium",
    "CheckRemoteDebuggerPresent": "medium",
    "OutputDebugString":    "low",
}

_SEV_WEIGHT = {"high": 30, "medium": 12, "low": 4}


def _load_rules():
    global _yara_rules
    if _yara_rules is None and _yara_ok and os.path.exists(_RULES_PATH):
        try:
            _yara_rules = yara.compile(_RULES_PATH)
        except Exception:
            pass
    return _yara_rules


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _file_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "ZIP"
    if data[:2] == b"\x1f\x8b":
        return "GZIP"
    if data[:4] == b"Rar!":
        return "RAR"
    if data[:3] == b"%PD":
        return "PDF"
    return "BINARY"


def _analyze_pe(file_bytes: bytes) -> tuple[list, dict | None]:
    findings = []
    pe_info = None
    if not _pefile_ok:
        return findings, pe_info
    try:
        pe = pefile.PE(data=file_bytes)
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            ent = _entropy(s.get_data())
            sections.append({"name": name, "entropy": round(ent, 2)})
            if ent > 7.0:
                findings.append({
                    "signal": "high_entropy_section",
                    "detail": f"Section '{name}' entropy {ent:.2f} — likely packed or encrypted",
                    "severity": "high",
                })
            elif name and name not in _KNOWN_SECTIONS:
                findings.append({
                    "signal": "unusual_section_name",
                    "detail": f"Non-standard PE section '{name}'",
                    "severity": "low",
                })

        import_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    if imp.name:
                        fn = imp.name.decode("utf-8", errors="replace")
                        if fn in _SUSPICIOUS_IMPORTS:
                            findings.append({
                                "signal": "suspicious_import",
                                "detail": f"Imports {fn}",
                                "severity": _SUSPICIOUS_IMPORTS[fn],
                            })

        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            findings.append({
                "signal": "zeroed_pe_timestamp",
                "detail": "PE timestamp is zero — deliberate erasure or build tool artifact",
                "severity": "low",
            })

        is_64 = pe.OPTIONAL_HEADER.Magic == 0x20b
        pe_info = {
            "arch": "x64" if is_64 else "x86",
            "sections": sections,
            "import_count": import_count,
        }
        pe.close()
    except Exception as exc:
        findings.append({
            "signal": "pe_parse_error",
            "detail": str(exc),
            "severity": "low",
        })
    return findings, pe_info


def _run_yara(file_bytes: bytes) -> list:
    findings = []
    rules = _load_rules()
    if not rules:
        return findings
    try:
        for m in rules.match(data=file_bytes):
            sev = m.meta.get("severity", "medium")
            findings.append({
                "signal": f"yara:{m.rule}",
                "detail": m.meta.get("description", m.rule),
                "severity": sev,
            })
    except Exception:
        pass
    return findings


def _sync_analyze(file_bytes: bytes, filename: str) -> dict:
    ft = _file_type(file_bytes)
    findings = []
    pe_info = None

    if ft == "PE":
        pe_findings, pe_info = _analyze_pe(file_bytes)
        findings.extend(pe_findings)

    findings.extend(_run_yara(file_bytes))

    # Deduplicate signals that both pefile and YARA caught
    seen = set()
    deduped = []
    for f in findings:
        key = (f["signal"], f["detail"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    score = min(100, sum(_SEV_WEIGHT.get(f["severity"], 0) for f in deduped))

    return {
        "file_type": ft,
        "pe_info": pe_info,
        "findings": deduped,
        "score_contribution": score,
        "engines_available": {"pefile": _pefile_ok, "yara": _yara_ok},
    }


async def analyze_static(file_bytes: bytes, filename: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_analyze, file_bytes, filename)
