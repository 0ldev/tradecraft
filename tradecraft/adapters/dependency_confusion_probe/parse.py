"""
Pure parsing for dependency_confusion_probe: a 404/no-result on the
public registry means the name is unclaimed (squattable); a 200/found
result means it's already claimed and not vulnerable this way. No I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from tradecraft.adapters.dependency_confusion_probe.execute import RawDependencyConfusionResult, RawPackageCheck


def _is_unclaimed(check: RawPackageCheck) -> bool:
    if check.ecosystem in ("npm", "pypi"):
        return check.status_code == 404
    if check.ecosystem == "maven":
        try:
            data = json.loads(check.body)
            return data.get("response", {}).get("numFound", 0) == 0
        except Exception:
            return False
    return False


def parse(raw: RawDependencyConfusionResult) -> Dict[str, Any]:
    if raw.error:
        return {"error": raw.error}

    results: List[Dict[str, Any]] = []
    squattable: List[str] = []

    for check in raw.checks:
        if check.error:
            results.append({"name": check.name, "ecosystem": check.ecosystem, "classification": "network_error", "error": check.error})
            continue

        unclaimed = _is_unclaimed(check)
        if unclaimed:
            squattable.append(f"{check.name} ({check.ecosystem})")

        results.append({
            "name": check.name,
            "ecosystem": check.ecosystem,
            "status_code": check.status_code,
            "unclaimed": unclaimed,
            "classification": "squattable" if unclaimed else "already_claimed",
        })

    return {
        "packages_checked": len(raw.checks),
        "squattable_count": len(squattable),
        "squattable_packages": squattable,
        "results": results,
    }
