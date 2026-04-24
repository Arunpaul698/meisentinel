import asyncio
import os
import re
import shutil
import subprocess
import tempfile

try:
    import pefile as _pefile
    _pefile_ok = True
except ImportError:
    _pefile_ok = False

_OSSLSIGNCODE = shutil.which("osslsigncode")

_SEV_WEIGHT = {"high": 30, "medium": 12, "low": 4}


def _has_security_dir(file_bytes: bytes) -> bool:
    """Return True if the PE has a non-empty security directory entry."""
    if not _pefile_ok:
        return False
    try:
        pe = _pefile.PE(data=file_bytes)
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        pe.close()
        return sec.VirtualAddress != 0 and sec.Size != 0
    except Exception:
        return False


def _is_pe(file_bytes: bytes) -> bool:
    return file_bytes[:2] == b"MZ"


def _parse_osslsigncode(stdout: str, stderr: str) -> dict:
    """Parse osslsigncode verify output into a structured result."""
    out = stdout + "\n" + stderr
    succeeded = "Succeeded" in out
    no_cert_table = "without certificate table" in out

    signer_cn = None
    signer_org = None
    issuer = None

    # Extract Subject CN and O from certificate block
    for line in out.splitlines():
        line = line.strip()
        if m := re.search(r"Subject:.*?CN=([^,\n/]+)", line):
            signer_cn = m.group(1).strip()
        if m := re.search(r"Subject:.*?O=([^,\n/]+)", line):
            signer_org = m.group(1).strip()
        if m := re.search(r"Issuer:.*?CN=([^,\n/]+)", line):
            issuer = m.group(1).strip()

    return {
        "succeeded": succeeded,
        "no_cert_table": no_cert_table,
        "signer_cn": signer_cn,
        "signer_org": signer_org,
        "issuer": issuer,
    }


def _sync_check(file_bytes: bytes, filename: str) -> dict:
    if not _is_pe(file_bytes):
        return {
            "applicable": False,
            "findings": [],
            "score_contribution": 0,
        }

    has_sig = _has_security_dir(file_bytes)
    findings = []

    if not has_sig:
        # Unsigned PE — informational only; many legitimate files are unsigned
        findings.append({
            "signal": "unsigned_pe",
            "detail": "PE file has no Authenticode signature",
            "severity": "low",
        })
        return {
            "applicable": True,
            "signed": False,
            "verified": None,
            "signer": None,
            "findings": findings,
            "score_contribution": _SEV_WEIGHT["low"],
        }

    # File has a signature — verify it
    if not _OSSLSIGNCODE:
        return {
            "applicable": True,
            "signed": True,
            "verified": None,
            "signer": None,
            "findings": [{
                "signal": "signature_not_verified",
                "detail": "PE has an Authenticode signature but osslsigncode is unavailable for verification",
                "severity": "low",
            }],
            "score_contribution": _SEV_WEIGHT["low"],
        }

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(file_bytes)
            tmp = f.name

        result = subprocess.run(
            [_OSSLSIGNCODE, "verify", "-ignore-timestamp", "-in", tmp],
            capture_output=True, text=True, timeout=15,
        )
        parsed = _parse_osslsigncode(result.stdout, result.stderr)

        signer = None
        if parsed["signer_cn"] or parsed["signer_org"]:
            signer = parsed["signer_cn"] or parsed["signer_org"]

        if parsed["succeeded"]:
            # Valid signature — positive signal, no penalty
            return {
                "applicable": True,
                "signed": True,
                "verified": True,
                "signer": signer,
                "issuer": parsed["issuer"],
                "findings": [],
                "score_contribution": 0,
            }
        else:
            # Signature present but failed verification — strong red flag
            findings.append({
                "signal": "invalid_authenticode_signature",
                "detail": (
                    f"PE has an Authenticode signature that failed verification"
                    + (f" (signer: {signer})" if signer else "")
                    + " — file may have been tampered with after signing"
                ),
                "severity": "high",
            })
            return {
                "applicable": True,
                "signed": True,
                "verified": False,
                "signer": signer,
                "issuer": parsed["issuer"],
                "findings": findings,
                "score_contribution": _SEV_WEIGHT["high"],
            }
    except subprocess.TimeoutExpired:
        findings.append({
            "signal": "signature_check_timeout",
            "detail": "Code signing verification timed out",
            "severity": "low",
        })
        return {
            "applicable": True,
            "signed": True,
            "verified": None,
            "signer": None,
            "findings": findings,
            "score_contribution": _SEV_WEIGHT["low"],
        }
    except Exception as exc:
        findings.append({
            "signal": "signature_check_error",
            "detail": str(exc),
            "severity": "low",
        })
        return {
            "applicable": True,
            "signed": True,
            "verified": None,
            "signer": None,
            "findings": findings,
            "score_contribution": _SEV_WEIGHT["low"],
        }
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


async def check_signing(file_bytes: bytes, filename: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_check, file_bytes, filename)
