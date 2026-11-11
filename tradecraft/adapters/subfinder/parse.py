from __future__ import annotations

import re


def parse_subdomains(stdout: str, target: str) -> list[str]:
    root = target.strip().lower().rstrip(".")
    subdomains = set()
    for line in stdout.splitlines():
        hostname = line.strip().lower().rstrip(".")
        labels = hostname.split(".")
        if (
            len(hostname) <= 253
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            and (hostname == root or hostname.endswith("." + root))
        ):
            subdomains.add(hostname)
    return sorted(subdomains)