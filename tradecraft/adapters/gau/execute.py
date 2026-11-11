"""
Raw execution: builds the gau argv and runs it against one target domain. No
parsing here -- that's parse.py's job.

When the gau binary times out or yields zero URLs, a bounded Python fallback
queries the Wayback Machine CDX API and AlienVault OTX directly and merges
their URL lists into the same newline-delimited shape gau emits.
"""
from __future__ import annotations

import concurrent.futures
import logging
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

FALLBACK_TIMEOUT = 10
WAYBACK_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=5000"
)
OTX_URL_LIST = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
)


@dataclass
class RawGauResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_domain: str = ""
    error: Optional[str] = None


def normalize_target_domain(target: str) -> str:
    """Extract clean domain/hostname for passive URL fetching."""
    target = target.strip()
    if not target:
        return ""
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        target = parsed.hostname or target
    elif ":" in target:
        target = target.split(":")[0]
    return target.strip().lower()


def build_argv(
    domain: str,
    include_subs: bool = True,
    providers: str = "wayback,otx",
    timeout: int = 25,
) -> List[str]:
    argv = [
        "gau",
        domain,
        "--providers",
        providers.strip() or "wayback,otx",
        "--timeout",
        str(max(5, timeout)),
    ]
    if include_subs:
        argv.append("--subs")
    return argv


def _fetch_wayback_urls(domain: str) -> List[str]:
    """Wayback CDX text output: one URL per line. Any failure yields []."""
    url = WAYBACK_CDX_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=FALLBACK_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("gau fallback: wayback CDX returned HTTP %s", resp.status_code)
            return []
        return [line.strip() for line in resp.text.splitlines() if line.strip()]
    except Exception as exc:
        logger.warning("gau fallback: wayback CDX request failed: %s", exc)
        return []


def _fetch_otx_urls(domain: str) -> List[str]:
    """OTX url_list JSON: {"url_list": [{"url": ...}, ...]}. Any failure yields []."""
    url = OTX_URL_LIST.format(domain=domain)
    try:
        resp = requests.get(url, timeout=FALLBACK_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("gau fallback: OTX url_list returned HTTP %s", resp.status_code)
            return []
        entries = resp.json().get("url_list") or []
        return [
            str(entry["url"]).strip()
            for entry in entries
            if isinstance(entry, dict) and entry.get("url")
        ]
    except Exception as exc:
        logger.warning("gau fallback: OTX url_list request failed: %s", exc)
        return []


def _has_gau_url_lines(stdout: str) -> bool:
    """True if gau emitted at least one non-log line (log lines start with time=)."""
    return any(
        line.strip() and not line.strip().startswith("time=")
        for line in stdout.splitlines()
    )


def _python_fallback_urls(domain: str, providers: str) -> List[str]:
    """Query only the requested sources, concurrently, and return the
    deduplicated union. Running the two HTTP calls in parallel keeps the
    fallback's worst-case added latency at ~FALLBACK_TIMEOUT instead of
    the sum of both requests' timeouts."""
    requested = {p.strip().lower() for p in (providers or "").split(",") if p.strip()}
    fetchers = []
    if "wayback" in requested:
        fetchers.append(_fetch_wayback_urls)
    if "otx" in requested:
        fetchers.append(_fetch_otx_urls)
    if not fetchers:
        return []

    urls: set = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fetchers)) as pool:
        futures = [pool.submit(fetch, domain) for fetch in fetchers]
        for future in futures:
            urls.update(future.result())
    return sorted(urls)


def execute(
    target: str,
    include_subs: bool = True,
    providers: str = "wayback,otx",
    timeout: Optional[int] = None,
) -> RawGauResult:
    domain = normalize_target_domain(target)
    if not domain:
        return RawGauResult(error="empty target")

    effective_timeout = timeout if timeout is not None else 30

    if shutil.which("gau") is None:
        result = RawGauResult(target_domain=domain, error="gau binary not found on PATH")
    else:
        argv = build_argv(
            domain=domain,
            include_subs=include_subs,
            providers=providers,
            timeout=min(25, effective_timeout),
        )
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            result = RawGauResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                target_domain=domain,
                error=f"gau exited with status {proc.returncode}" if proc.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            result = RawGauResult(
                target_domain=domain,
                error=f"gau timed out after {effective_timeout}s",
            )
        except Exception as exc:
            result = RawGauResult(
                target_domain=domain,
                error=f"{type(exc).__name__}: {exc}",
            )

    if _has_gau_url_lines(result.stdout):
        return result

    fallback_urls = _python_fallback_urls(domain, providers)
    if not fallback_urls:
        return result

    logger.info(
        "gau fallback: %d URLs from wayback/otx for %s (gau: %s)",
        len(fallback_urls), domain, result.error or "zero URLs",
    )
    return RawGauResult(
        stdout="\n".join(fallback_urls) + "\n",
        stderr=result.stderr,
        returncode=result.returncode,
        target_domain=domain,
        error=None,
    )
