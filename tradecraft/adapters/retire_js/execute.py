"""
Subprocess execution for retire.js.
Fetches page HTML, discovers and downloads external <script src> assets,
and executes retire on the downloaded scripts directory.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests

from tradecraft.memory.evidence import EvidenceStore

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


@dataclass
class RawRetireResult:
    stdout: str
    stderr: str
    returncode: int
    scripts_downloaded: int
    error: Optional[str] = None


def fetch_script_urls(target: str, timeout: int = 15) -> List[str]:
    """Fetches the target URL, extracts <script src> values, resolves against
    target URL, dedupes, and caps at 40 URLs."""
    clean_target = target.strip()
    if not clean_target:
        return []

    url = clean_target if "://" in clean_target else f"https://{clean_target}"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        html = resp.text
    except Exception:
        return []

    urls: List[str] = []
    for match in _SCRIPT_SRC_RE.finditer(html):
        src = match.group(1).strip()
        if not src:
            continue
        resolved = urllib.parse.urljoin(url, src)
        if resolved not in urls:
            urls.append(resolved)
        if len(urls) >= 40:
            break

    return urls


def download_scripts(
    urls: List[str],
    dest_dir: Path,
    timeout: int = 15,
    max_bytes: int = 2_000_000,
) -> List[Path]:
    """Downloads scripts into dest_dir, sanitizing filenames using EvidenceStore._sanitize_component."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded: List[Path] = []

    for idx, u in enumerate(urls):
        try:
            parsed = urllib.parse.urlsplit(u)
            raw_name = Path(parsed.path).name or f"script_{idx}.js"
            if not raw_name.endswith(".js"):
                raw_name = f"{raw_name}.js"
            try:
                safe_name = EvidenceStore._sanitize_component(raw_name)
            except ValueError:
                safe_name = f"script_{idx}.js"

            dest_path = dest_dir / f"{idx}_{safe_name}"

            resp = requests.get(
                u,
                timeout=timeout,
                stream=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code != 200:
                continue

            content = bytearray()
            for chunk in resp.iter_content(chunk_size=16384):
                content.extend(chunk)
                if len(content) > max_bytes:
                    break

            if len(content) <= max_bytes:
                dest_path.write_bytes(content)
                downloaded.append(dest_path)
        except Exception:
            continue

    return downloaded


def execute(target: str, timeout: int = 15) -> RawRetireResult:
    """Creates a temporary directory, fetches and downloads external scripts,
    and runs retire --path <dir> --outputformat json."""
    clean_target = target.strip()
    if not clean_target:
        return RawRetireResult(
            stdout="", stderr="empty target", returncode=1,
            scripts_downloaded=0, error="empty target",
        )

    tmp_dir = tempfile.mkdtemp(prefix="tradecraft_retire_")
    try:
        urls = fetch_script_urls(clean_target, timeout=timeout)
        downloaded = download_scripts(urls, Path(tmp_dir), timeout=timeout)

        # Run retire against the downloaded scripts directory
        argv = ["retire", "--path", tmp_dir, "--outputformat", "json"]
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )

        return RawRetireResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            scripts_downloaded=len(downloaded),
            error=None,
        )
    except FileNotFoundError:
        return RawRetireResult(
            stdout="", stderr="", returncode=-1,
            scripts_downloaded=0, error="retire executable not found",
        )
    except subprocess.TimeoutExpired:
        return RawRetireResult(
            stdout="", stderr="", returncode=-1,
            scripts_downloaded=0, error="retire timed out after 60s",
        )
    except Exception as exc:
        return RawRetireResult(
            stdout="", stderr="", returncode=-1,
            scripts_downloaded=0, error=str(exc),
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
