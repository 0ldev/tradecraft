"""
Execution logic for unauthenticated artifact-repository exposure probing:
Nexus 3, Artifactory, and Harbor's own REST APIs (not the Docker
Registry v2 pull API registry_tag_enum already covers). Same "one GET
fingerprint, one or two GETs to a normally-gated/baseline-compared
endpoint" shape unauth_datastore_probe/cicd_exposure_probe already use.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_NEXUS_REPOS = ("maven-releases", "npm-hosted", "docker-hosted")


def normalize_base_url(target: str) -> str:
    cleaned = (target or "").strip().rstrip("/")
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


@dataclass
class NexusResult:
    base_url: str = ""
    connected: bool = False
    is_nexus: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "not_nexus", "error", "unexpected_response"
    nexus_version: str = ""
    repository_checked: str = ""
    components_exposed: int = 0
    error: Optional[str] = None


@dataclass
class ArtifactoryResult:
    base_url: str = ""
    connected: bool = False
    is_artifactory: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "not_artifactory", "error", "unexpected_response"
    repositories_exposed: int = 0
    repository_names: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class HarborResult:
    base_url: str = ""
    connected: bool = False
    is_harbor: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "no_over_exposure", "not_harbor", "error", "unexpected_response"
    harbor_version: str = ""
    public_project_count: int = 0
    unauth_project_count: int = 0
    error: Optional[str] = None


@dataclass
class ArtifactRepoExposureResult:
    target: str = ""
    nexus: Optional[NexusResult] = None
    artifactory: Optional[ArtifactoryResult] = None
    harbor: Optional[HarborResult] = None
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def probe_nexus(base_url: str, repositories: Optional[List[str]] = None, timeout: float = 10.0) -> NexusResult:
    res = NexusResult(base_url=base_url)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    headers = {"User-Agent": USER_AGENT}

    try:
        status_resp = requests.get(f"{base_url}/service/rest/v1/status", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    # Nexus Repository Manager sets its own "Server: Nexus/<version>"
    # header on every response -- more reliable than body-matching an
    # endpoint that normally returns an empty 200.
    server_header = status_resp.headers.get("Server", "")
    if status_resp.status_code != 200 or "nexus" not in server_header.lower():
        res.status = "not_nexus"
        return res

    res.connected = True
    res.is_nexus = True
    if "/" in server_header:
        res.nexus_version = server_header.split("/", 1)[1].strip()

    # /service/rest/v1/components normally requires an authenticated
    # session once anonymous access is disabled -- a 200 with a real
    # component list means anonymous read access is still enabled.
    candidates = repositories or list(DEFAULT_NEXUS_REPOS)
    for repo in candidates[:5]:
        try:
            comp_resp = requests.get(
                f"{base_url}/service/rest/v1/components",
                params={"repository": repo}, headers=headers, timeout=timeout, verify=False,
            )
        except requests.RequestException as exc:
            res.status = "error"
            res.error = str(exc)
            return res
        if comp_resp.status_code == 200:
            try:
                comp_data = comp_resp.json()
            except ValueError:
                continue
            items = comp_data.get("items")
            if isinstance(items, list):
                res.unauthenticated_access = True
                res.vulnerable = True
                res.status = "vulnerable"
                res.repository_checked = repo
                res.components_exposed = len(items)
                return res
        elif comp_resp.status_code in (401, 403):
            res.status = "auth_required"

    return res


def probe_artifactory(base_url: str, timeout: float = 10.0) -> ArtifactoryResult:
    res = ArtifactoryResult(base_url=base_url)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    headers = {"User-Agent": USER_AGENT}

    try:
        ping_resp = requests.get(f"{base_url}/artifactory/api/system/ping", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    # /api/system/ping is always public by design and replies with the
    # literal body "OK" -- the standard, documented Artifactory
    # fingerprint, more reliable than guessing from a title/banner.
    if ping_resp.status_code != 200 or ping_resp.text.strip() != "OK":
        res.status = "not_artifactory"
        return res

    res.connected = True
    res.is_artifactory = True

    # /api/repositories normally requires authentication once anonymous
    # access is disabled -- Artifactory ships with anonymous access
    # enabled by default historically, so a 200 here is a real, common
    # finding, not a theoretical one.
    try:
        repos_resp = requests.get(f"{base_url}/artifactory/api/repositories", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if repos_resp.status_code == 200:
        try:
            repos_data = repos_resp.json()
        except ValueError:
            res.status = "unexpected_response"
            return res
        if isinstance(repos_data, list):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            res.repositories_exposed = len(repos_data)
            res.repository_names = [r.get("key", "") for r in repos_data if isinstance(r, dict)][:25]
        else:
            res.status = "unexpected_response"
    elif repos_resp.status_code in (401, 403):
        res.status = "auth_required"
    else:
        res.status = "unexpected_response"
    return res


def probe_harbor(base_url: str, timeout: float = 10.0) -> HarborResult:
    res = HarborResult(base_url=base_url)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    headers = {"User-Agent": USER_AGENT}

    try:
        info_resp = requests.get(f"{base_url}/api/v2.0/systeminfo", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    # /api/v2.0/systeminfo is always public by Harbor's own design -- a
    # 200 with "harbor_version" is fingerprint only, not itself a finding.
    if info_resp.status_code != 200:
        res.status = "not_harbor"
        return res
    try:
        info_data = info_resp.json()
    except ValueError:
        res.status = "not_harbor"
        return res
    if "harbor_version" not in info_data:
        res.status = "not_harbor"
        return res

    res.connected = True
    res.is_harbor = True
    res.harbor_version = info_data.get("harbor_version", "")

    # ?public=true is also public by design -- the baseline. The real
    # question is whether the UNFILTERED listing (no auth) returns MORE
    # projects than that baseline, which would mean private projects are
    # visible without authentication. A bare 200 on the unfiltered call
    # is NOT itself the vulnerability -- Harbor answers it either way.
    try:
        public_resp = requests.get(
            f"{base_url}/api/v2.0/projects", params={"public": "true", "page_size": 100},
            headers=headers, timeout=timeout, verify=False,
        )
        unauth_resp = requests.get(
            f"{base_url}/api/v2.0/projects", params={"page_size": 100},
            headers=headers, timeout=timeout, verify=False,
        )
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if public_resp.status_code != 200 or unauth_resp.status_code not in (200, 401, 403):
        res.status = "unexpected_response"
        return res
    if unauth_resp.status_code in (401, 403):
        res.status = "no_over_exposure"
        return res

    try:
        public_projects = public_resp.json()
        unauth_projects = unauth_resp.json()
    except ValueError:
        res.status = "unexpected_response"
        return res
    if not isinstance(public_projects, list) or not isinstance(unauth_projects, list):
        res.status = "unexpected_response"
        return res

    res.public_project_count = len(public_projects)
    res.unauth_project_count = len(unauth_projects)
    if res.unauth_project_count > res.public_project_count:
        res.unauthenticated_access = True
        res.vulnerable = True
        res.status = "vulnerable"
    else:
        res.status = "no_over_exposure"
    return res


SERVICE_LABELS = {
    "nexus": "Nexus",
    "artifactory": "Artifactory",
    "harbor": "Harbor",
}


def execute(
    target: str,
    service: str = "auto",
    repository: Optional[str] = None,
    timeout: int = 10,
) -> ArtifactRepoExposureResult:
    base_url = normalize_base_url(target)
    if not base_url:
        return ArtifactRepoExposureResult(target=target, error=f"Invalid target: '{target}'")

    effective_timeout = max(1.0, min(float(timeout), 20.0))
    svc = (service or "auto").strip().lower()
    repos = [r.strip() for r in repository.split(",") if r.strip()] if repository else None

    # Built fresh on every call (not at module level) so that patching an
    # individual probe_* name is honored -- same reasoning as
    # unauth_datastore_probe's own execute().
    SERVICE_PROBERS = {
        "nexus": lambda url, timeout: probe_nexus(url, repositories=repos, timeout=timeout),
        "artifactory": probe_artifactory,
        "harbor": probe_harbor,
    }

    results: Dict[str, object] = {}
    if svc in SERVICE_PROBERS:
        results[svc] = SERVICE_PROBERS[svc](base_url, timeout=effective_timeout)
    else:
        for name, prober in SERVICE_PROBERS.items():
            results[name] = prober(base_url, timeout=effective_timeout)

    is_vuln = any(getattr(r, "vulnerable", False) for r in results.values())
    summary_parts = []
    for name, r in results.items():
        label = SERVICE_LABELS[name]
        if getattr(r, "vulnerable", False):
            summary_parts.append(f"{label} VULNERABLE: unauthenticated access")
        else:
            summary_parts.append(f"{label}: {r.status}")

    return ArtifactRepoExposureResult(
        target=target,
        nexus=results.get("nexus"),
        artifactory=results.get("artifactory"),
        harbor=results.get("harbor"),
        vulnerable=is_vuln,
        summary="; ".join(summary_parts),
    )
