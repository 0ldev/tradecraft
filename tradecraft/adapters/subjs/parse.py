"""
Pure parsing functions for subjs output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import urllib.parse
from typing import List

_JS_EXTENSIONS = (".js", "/js", ".mjs", ".cjs")


def parse_js_urls(stdout: str) -> List[str]:
    """Parse newline-delimited URLs from subjs output.
    Filters URLs whose path component ends in JavaScript extensions (.js, /js, .mjs, .cjs)
    regardless of cache-busting query strings or URL fragments.
    Deduplicates URLs while preserving order."""
    if not stdout or not stdout.strip():
        return []

    seen: set[str] = set()
    js_urls: List[str] = []

    for line in stdout.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue

        try:
            parsed = urllib.parse.urlsplit(url)
        except Exception:
            continue

        path = parsed.path.lower()
        if path.endswith(_JS_EXTENSIONS):
            seen.add(url)
            js_urls.append(url)

    return js_urls
