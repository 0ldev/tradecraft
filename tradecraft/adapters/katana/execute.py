"""
Raw execution: builds the katana argv and runs it against one target. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawKatanaResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not (target.startswith("http://") or target.startswith("https://")):
        parsed = urllib.parse.urlsplit("//" + target)
        if parsed.port == 80:
            target = f"http://{target}"
        else:
            target = f"https://{target}"
    return target


def build_argv(
    target_url: str,
    depth: int = 2,
    js_crawl: bool = True,
    crawl_duration: int = 15,
    concurrency: int = 10,
    rate_limit: int = 150,
    headless: bool = False,
    system_chrome: bool = True,
) -> List[str]:
    argv = [
        "katana",
        "-u",
        target_url,
        "-d",
        str(max(1, depth)),
        "-fs",
        "rdn",
        "-fsu",
        "-ob",
        "-or",
        "-silent",
        "-j",
        "-c",
        str(max(1, concurrency)),
        "-rl",
        str(max(1, rate_limit)),
        "-ct",
        f"{max(1, crawl_duration)}s",
    ]
    if js_crawl:
        argv.append("-jc")
    if headless:
        argv.extend(["-hl", "-nos"])
        if system_chrome:
            argv.append("-sc")
    return argv


def execute(
    target: str,
    depth: int = 2,
    js_crawl: bool = True,
    crawl_duration: int = 15,
    concurrency: int = 10,
    rate_limit: int = 150,
    timeout: Optional[int] = None,
    headless: bool = False,
    system_chrome: bool = True,
) -> RawKatanaResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawKatanaResult(error="empty target")

    if shutil.which("katana") is None:
        return RawKatanaResult(target_url=target_url, error="katana binary not found on PATH")

    default_margin = 45 if headless else 30
    effective_timeout = timeout if timeout is not None else crawl_duration + default_margin
    argv = build_argv(
        target_url=target_url,
        depth=depth,
        js_crawl=js_crawl,
        crawl_duration=crawl_duration,
        concurrency=concurrency,
        rate_limit=rate_limit,
        headless=headless,
        system_chrome=system_chrome,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
        return RawKatanaResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
            error=f"katana exited with status {proc.returncode}" if proc.returncode != 0 else None,
        )
    except subprocess.TimeoutExpired:
        return RawKatanaResult(
            target_url=target_url,
            error=f"katana timed out after {effective_timeout}s",
        )
    except Exception as exc:
        return RawKatanaResult(
            target_url=target_url,
            error=f"{type(exc).__name__}: {exc}",
        )
