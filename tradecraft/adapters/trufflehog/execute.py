"""
Raw execution: materializes targets/URLs and runs trufflehog filesystem against them.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import re
import shutil
import ssl
import subprocess
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Bundled custom-detector config (trufflehog's own --config flag, its
# beta custom-regex-detector feature, confirmed against the real binary
# installed on CT 115, v3.99.7) -- four narrow detectors for ASP.NET
# <machineKey> attributes (validationKey/decryptionKey/validation/
# decryption), confirmed additive on top of every built-in detector,
# never a replacement for them (verified directly: a Stripe-shaped test
# secret and all four custom detectors fired together in the same run).
# Always passed -- this is a fixed, project-maintained detector set, not
# something the model chooses; see config/trufflehog_detectors/
# aspnet_machinekey.yaml's own comments for why each detector is a
# single named regex (trufflehog concatenates multiple named regexes'
# captures into one unseparated string, confirmed against the real
# binary -- not usable for extracting four distinct values that way).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
ASPNET_DETECTORS_CONFIG = str(
    _PROJECT_ROOT / "config" / "trufflehog_detectors" / "aspnet_machinekey.yaml"
)


@dataclass
class RawTruffleHogResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target: str = ""
    scanned_urls: List[str] = field(default_factory=list)
    error: Optional[str] = None


def materialize_urls(urls: List[str], tmp_dir: str, timeout: int = 15) -> List[str]:
    """
    Fetches each URL's content into tmp_dir so trufflehog filesystem can scan it.
    Returns list of successfully fetched URLs.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    fetched: List[str] = []
    for i, url in enumerate(urls):
        url = url.strip()
        if not url:
            continue
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = resp.read()
                parsed = urllib.parse.urlsplit(url)
                base = os.path.basename(parsed.path) or "index.html"
                base = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
                safe_name = f"{i}_{base}"
                with open(os.path.join(tmp_dir, safe_name), "wb") as f:
                    f.write(data)
                fetched.append(url)
        except Exception:
            continue
    return fetched


def build_argv(
    scan_path: str,
    verify: bool = False,
    concurrency: int = 5,
) -> List[str]:
    argv = [
        "trufflehog",
        "filesystem",
        scan_path,
        "--json",
        "--no-update",
        "--no-color",
    ]
    if os.path.isfile(ASPNET_DETECTORS_CONFIG):
        argv.append(f"--config={ASPNET_DETECTORS_CONFIG}")
    if not verify:
        argv.append("--no-verification")
    if concurrency and concurrency != 5:
        argv.extend(["--concurrency", str(max(1, concurrency))])
    return argv


def build_git_argv(repo_url_or_path: str, verify: bool = False) -> List[str]:
    """TruffleHog's own git-history mode -- clones (if given a URL) and
    walks full commit history itself, no local clone management needed."""
    argv = ["trufflehog", "git", repo_url_or_path, "--json", "--no-color"]
    if os.path.isfile(ASPNET_DETECTORS_CONFIG):
        argv.append(f"--config={ASPNET_DETECTORS_CONFIG}")
    if not verify:
        argv.append("--no-verification")
    return argv


def execute(
    target: str,
    urls: str = "",
    verify: bool = False,
    concurrency: int = 5,
    subprocess_timeout: int = 60,
    scan_git_history: bool = False,
) -> RawTruffleHogResult:
    target = target.strip()
    if not target:
        return RawTruffleHogResult(error="Target cannot be empty")

    binary = shutil.which("trufflehog")
    if not binary:
        return RawTruffleHogResult(
            target=target,
            error="trufflehog binary not found on PATH. Install trufflehog to enable secret scanning.",
        )

    # 0. Git-history mode -- checked first and exclusively; urls/
    # filesystem/remote-fetch modes below don't apply when this is set.
    if scan_git_history:
        try:
            argv = build_git_argv(target, verify=verify)
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                # Git history on a real repo can take meaningfully longer
                # than a filesystem scan of an already-fetched directory --
                # give it real headroom, confirm a sane default against a
                # real clone before trusting 300 blindly.
                timeout=max(subprocess_timeout, 300),
            )
            return RawTruffleHogResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
                target=target,
            )
        except subprocess.TimeoutExpired:
            return RawTruffleHogResult(
                target=target,
                error=f"trufflehog git-history scan timed out against {target}",
            )
        except Exception as e:
            return RawTruffleHogResult(
                target=target,
                error=f"trufflehog git-history scan failed: {str(e)}",
            )

    # 1. Local filesystem path mode
    if os.path.exists(target):
        try:
            argv = build_argv(target, verify=verify, concurrency=concurrency)
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=subprocess_timeout,
            )
            return RawTruffleHogResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
                target=target,
            )
        except subprocess.TimeoutExpired:
            return RawTruffleHogResult(
                target=target,
                error=f"trufflehog execution timed out after {subprocess_timeout}s against {target}",
            )
        except Exception as e:
            return RawTruffleHogResult(
                target=target,
                error=f"trufflehog execution failed: {str(e)}",
            )

    # 2. Remote URL / Web JS bundle mode
    url_list: List[str] = []
    if target.startswith("http://") or target.startswith("https://"):
        url_list.append(target)
    elif "." in target and not urls:
        # Bare domain provided without scheme
        url_list.append(f"https://{target}")

    if urls:
        for u in re.split(r"[,\s]+", urls):
            u = u.strip()
            if u:
                if not (u.startswith("http://") or u.startswith("https://")):
                    u = f"https://{u}"
                url_list.append(u)

    if not url_list:
        return RawTruffleHogResult(
            target=target,
            error=f"No valid URLs or existing directory found to scan for target '{target}'",
        )

    tmp_dir = tempfile.mkdtemp(prefix="trufflehog_")
    try:
        fetched_urls = materialize_urls(url_list, tmp_dir)
        if not fetched_urls:
            return RawTruffleHogResult(
                target=target,
                error=f"Could not retrieve content from any of the {len(url_list)} target URL(s)",
            )

        argv = build_argv(tmp_dir, verify=verify, concurrency=concurrency)
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=subprocess_timeout,
        )
        return RawTruffleHogResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target=target,
            scanned_urls=fetched_urls,
        )
    except subprocess.TimeoutExpired:
        return RawTruffleHogResult(
            target=target,
            scanned_urls=url_list,
            error=f"trufflehog execution timed out after {subprocess_timeout}s against {target}",
        )
    except Exception as e:
        return RawTruffleHogResult(
            target=target,
            scanned_urls=url_list,
            error=f"trufflehog execution failed: {str(e)}",
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
