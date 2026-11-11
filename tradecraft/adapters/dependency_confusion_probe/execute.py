"""
Execution logic for dependency_confusion_probe: checks whether internal
package names are unclaimed (and therefore squattable) on the public
npm, PyPI, or Maven Central registries. GET-only against those public
registries -- never touches the client's own infrastructure. No parsing
here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10
MAX_PACKAGES = 20
VALID_ECOSYSTEMS = ("npm", "pypi", "maven")


@dataclass
class RawPackageCheck:
    name: str
    ecosystem: str
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawDependencyConfusionResult:
    checks: List[RawPackageCheck] = field(default_factory=list)
    error: Optional[str] = None


def parse_packages_param(packages: str) -> List[tuple]:
    """'name:ecosystem' or bare 'name' (ecosystem defaults to npm)."""
    out = []
    for raw in packages.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if ":" in raw:
            name, _, eco = raw.rpartition(":")
            eco = eco.strip().lower()
        else:
            name, eco = raw, "npm"
        if eco not in VALID_ECOSYSTEMS:
            eco = "npm"
        out.append((name.strip(), eco))
    return out[:MAX_PACKAGES]


def _registry_url(name: str, ecosystem: str) -> str:
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{name}"
    if ecosystem == "pypi":
        return f"https://pypi.org/pypi/{name}/json"
    # maven: group:artifact, or a bare artifact name searched across all groups
    if ":" in name:
        group_id, artifact_id = name.split(":", 1)
        query = f"g:{group_id}+AND+a:{artifact_id}"
    else:
        query = f"a:{name}"
    return f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"


def execute(packages: str, timeout: int = DEFAULT_TIMEOUT) -> RawDependencyConfusionResult:
    if requests is None:
        return RawDependencyConfusionResult(error="requests library not available")

    pairs = parse_packages_param(packages)
    if not pairs:
        return RawDependencyConfusionResult(error="no valid package names provided")

    checks: List[RawPackageCheck] = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
    for name, eco in pairs:
        url = _registry_url(name, eco)
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            # Maven's search endpoint always returns 200; "found" is read
            # from the response body (numFound) in parse.py, not the status.
            body = resp.text if eco == "maven" else ""
            checks.append(RawPackageCheck(name=name, ecosystem=eco, status_code=resp.status_code, body=body))
        except requests.RequestException as exc:
            checks.append(RawPackageCheck(name=name, ecosystem=eco, error=str(exc)))
        except Exception as exc:
            checks.append(RawPackageCheck(name=name, ecosystem=eco, error=f"{type(exc).__name__}: {exc}"))

    return RawDependencyConfusionResult(checks=checks)
