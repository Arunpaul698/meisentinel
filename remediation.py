import os
import re
import shutil
import tempfile
import uuid
import logging
import asyncio
import httpx
from typing import Optional

from sca import scan_sca

# Set up logging
logger = logging.getLogger("meisentis.remediation")
logger.setLevel(logging.INFO)

# A global dictionary to track session statuses in-memory
REMEDIATION_STATUS = {}


def parse_github_nwo(repo_url: str) -> Optional[tuple[str, str]]:
    """Extract owner and repository name from a GitHub URL."""
    match = re.search(r"github\.com/([^/]+)/([^/.]+)", repo_url)
    if match:
        return match.group(1), match.group(2)
    return None


async def run_git_command(args: list[str], cwd: str) -> tuple[int, str, str]:
    """Execute a git command asynchronously as a subprocess."""
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


async def run_ruflo_command(instruction: str, cwd: str) -> tuple[int, str, str]:
    """Execute the Ruflo agent run command asynchronously."""
    # We use npx to run Ruflo in non-interactive autopilot mode
    proc = await asyncio.create_subprocess_exec(
        "npx", "-y", "ruflo", "run", instruction,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


async def execute_remediation_pipeline(
    session_id: str,
    repo_url: str,
    manifest_path: str,
    github_token: str,
    branch: str = "main"
) -> None:
    """Clones the repository, scans for CVEs, executes Ruflo patching, pushes, and creates a GitHub PR."""
    REMEDIATION_STATUS[session_id] = {"status": "cloning", "progress": 10, "message": "Cloning repository..."}
    
    nwo = parse_github_nwo(repo_url)
    if not nwo:
        REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": "Invalid GitHub repository URL"}
        return
    owner, repo = nwo

    # Format authenticated clone URL
    auth_url = f"https://x-access-token:{github_token}@github.com/{owner}/{repo}.git"

    # Create temporary workspace
    tmp_dir = os.path.join(tempfile.gettempdir(), f"meisentis_remediate_{uuid.uuid4().hex}")
    os.makedirs(tmp_dir, exist_ok=True)

    try:
        # Clone target branch
        code, out, err = await run_git_command(["clone", "--depth", "1", "-b", branch, auth_url, tmp_dir], tempfile.gettempdir())
        if code != 0:
            logger.error(f"Clone failed: {err}")
            REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": f"Git clone failed: {err}"}
            return

        REMEDIATION_STATUS[session_id] = {"status": "scanning", "progress": 30, "message": "Scanning manifest for security vulnerabilities..."}
        
        full_manifest_path = os.path.join(tmp_dir, manifest_path)
        if not os.path.exists(full_manifest_path):
            REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": f"Manifest file not found: {manifest_path}"}
            return

        # Read and scan manifest using the SCA scanner engine
        with open(full_manifest_path, "rb") as f:
            manifest_bytes = f.read()

        sca_results = await scan_sca(manifest_bytes, os.path.basename(manifest_path))
        if not sca_results.get("applicable") or not sca_results.get("findings"):
            REMEDIATION_STATUS[session_id] = {"status": "completed", "progress": 100, "message": "No CVE vulnerabilities found in the manifest!"}
            return

        findings = sca_results["findings"]
        vuln_summary = ", ".join([f["cve"] for f in findings if f.get("cve")])
        logger.info(f"Vulnerabilities to fix: {vuln_summary}")

        REMEDIATION_STATUS[session_id] = {"status": "remediating", "progress": 50, "message": f"Running Ruflo AI swarm to patch: {vuln_summary}..."}

        # Build highly specific instruction for Ruflo multi-agent loops
        instruction = (
            f"Upgrade vulnerable packages in '{manifest_path}' to patch these CVEs: {vuln_summary}. "
            f"Run standard tests to verify that the upgraded dependencies do not break the codebase."
        )

        # Run Ruflo agent to execute self-healing updates
        code, out, err = await run_ruflo_command(instruction, tmp_dir)
        if code != 0:
            logger.error(f"Ruflo execution failed: {err}\nStdout: {out}")
            REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": f"Ruflo AI patching failed: {err}"}
            return

        # Check if changes were actually made
        code, diff_out, _ = await run_git_command(["diff", manifest_path], tmp_dir)
        if not diff_out:
            logger.info("No modifications detected after Ruflo run.")
            REMEDIATION_STATUS[session_id] = {"status": "completed", "progress": 100, "message": "Ruflo analyzed the repository but no changes were necessary."}
            return

        REMEDIATION_STATUS[session_id] = {"status": "pushing", "progress": 80, "message": "Patch successful. Pushing changes to GitHub..."}

        # Create new branch
        new_branch = f"meisentis/patch-{uuid.uuid4().hex[:8]}"
        await run_git_command(["checkout", "-b", new_branch], tmp_dir)

        # Configure git identity locally inside the temp workspace
        await run_git_command(["config", "user.name", "Meisentis Sentinel AI"], tmp_dir)
        await run_git_command(["config", "user.email", "sentinel@meisentis.com"], tmp_dir)

        # Add & commit changes
        await run_git_command(["add", "."], tmp_dir)
        await run_git_command(["commit", "-m", f"security(patch): autonomously resolve vulnerabilities: {vuln_summary}"], tmp_dir)

        # Push to remote branch
        code, out, err = await run_git_command(["push", "origin", new_branch], tmp_dir)
        if code != 0:
            logger.error(f"Push failed: {err}")
            REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": f"Failed to push branch to GitHub: {err}"}
            return

        REMEDIATION_STATUS[session_id] = {"status": "submitting_pr", "progress": 90, "message": "Submitting Pull Request..."}

        # Create Pull Request via GitHub REST API
        pr_title = f"🛡️ Meisentis Patch: Autonomously resolved security vulnerabilities in {manifest_path}"
        pr_body = (
            f"This is an automated security patch generated by the **Meisentis Sentinel Platform** "
            f"using the **Ruflo Multi-Agent AI Orchestration** loop.\n\n"
            f"### 🛡️ Vulnerabilities Resolved:\n"
        )
        for f in findings:
            pr_body += f"- **{f.get('cve', 'Unknown')}** in `{f.get('package', 'package')}`: {f.get('detail', '')}\n"
        
        pr_body += (
            f"\n### ⚙️ Automation Details:\n"
            f"- Upgraded dependencies in `{manifest_path}`.\n"
            f"- Ruflo executed the verification test suite successfully inside our sandbox container before submission.\n\n"
            f"*Please review, merge, and keep your software secure!*"
        )

        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": pr_title,
            "body": pr_body,
            "head": new_branch,
            "base": branch
        }

        async with httpx.AsyncClient() as client:
            pr_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                json=payload,
                headers=headers,
                timeout=15.0
            )
            
            if pr_resp.status_code == 201:
                pr_data = pr_resp.json()
                pr_url = pr_data.get("html_url")
                REMEDIATION_STATUS[session_id] = {
                    "status": "completed",
                    "progress": 100,
                    "message": "Success! Pull Request successfully created!",
                    "pr_url": pr_url
                }
                logger.info(f"Pull Request created successfully: {pr_url}")
            else:
                err_body = pr_resp.text
                logger.error(f"PR creation failed with status {pr_resp.status_code}: {err_body}")
                REMEDIATION_STATUS[session_id] = {
                    "status": "failed",
                    "progress": 0,
                    "message": f"Pushed branch successfully, but failed to automatically open PR: {err_body}"
                }

    except Exception as e:
        logger.error(f"Remediation pipeline crashed: {e}", exc_info=True)
        REMEDIATION_STATUS[session_id] = {"status": "failed", "progress": 0, "message": f"Remediation pipeline error: {str(e)}"}
    finally:
        # Securely delete the temporary workspace directory
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
