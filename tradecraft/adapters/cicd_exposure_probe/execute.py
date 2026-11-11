"""
Execution logic for unauthenticated CI/CD orchestrator exposure probing:
Argo CD and TeamCity guest access. Same "one GET fingerprint, one GET to
a normally-gated endpoint" shape unauth_datastore_probe/jenkins_unauth_probe
already use. 'auto' checks both services -- there are only two of them,
unlike unauth_datastore_probe's nine, so there is no reason to narrow
the default the way that tool does. No parsing here -- that's parse.py's
job.
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


def normalize_base_url(target: str) -> str:
    cleaned = (target or "").strip().rstrip("/")
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


@dataclass
class ArgoCdResult:
    base_url: str = ""
    connected: bool = False
    is_argocd: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "not_argocd", "error", "unexpected_response"
    argocd_version: str = ""
    applications_exposed: int = 0
    application_names: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TeamCityResult:
    base_url: str = ""
    connected: bool = False
    is_teamcity: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "not_teamcity", "error", "unexpected_response"
    teamcity_version: str = ""
    guest_projects_exposed: int = 0
    project_names: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class CicdExposureResult:
    target: str = ""
    argocd: Optional[ArgoCdResult] = None
    teamcity: Optional[TeamCityResult] = None
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def probe_argocd(base_url: str, timeout: float = 10.0) -> ArgoCdResult:
    res = ArgoCdResult(base_url=base_url)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    headers = {"User-Agent": USER_AGENT}

    try:
        version_resp = requests.get(f"{base_url}/api/version", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if version_resp.status_code != 200:
        res.status = "not_argocd"
        return res
    try:
        version_data = version_resp.json()
    except ValueError:
        res.status = "not_argocd"
        return res
    if "Version" not in version_data:
        res.status = "not_argocd"
        return res

    res.connected = True
    res.is_argocd = True
    res.argocd_version = version_data.get("Version", "")

    # /api/v1/applications normally requires an authenticated session
    # (unless the 'anonymous' RBAC policy grants read access) -- a 200
    # here with a real application list means anonymous read access is
    # enabled, exposing every app's name, repo URL, and sync status.
    try:
        apps_resp = requests.get(f"{base_url}/api/v1/applications", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if apps_resp.status_code == 200:
        try:
            apps_data = apps_resp.json()
        except ValueError:
            res.status = "unexpected_response"
            return res
        items = apps_data.get("items") or []
        if isinstance(items, list):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            res.applications_exposed = len(items)
            res.application_names = [
                (a.get("metadata") or {}).get("name", "") for a in items if isinstance(a, dict)
            ][:25]
        else:
            res.status = "unexpected_response"
    elif apps_resp.status_code in (401, 403):
        res.status = "auth_required"
    else:
        res.status = "unexpected_response"
    return res


def probe_teamcity(base_url: str, timeout: float = 10.0) -> TeamCityResult:
    res = TeamCityResult(base_url=base_url)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    try:
        server_resp = requests.get(f"{base_url}/app/rest/server", headers=headers, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if server_resp.status_code != 200:
        res.status = "not_teamcity"
        return res
    try:
        server_data = server_resp.json()
    except ValueError:
        res.status = "not_teamcity"
        return res
    if "version" not in server_data:
        res.status = "not_teamcity"
        return res

    res.connected = True
    res.is_teamcity = True
    res.teamcity_version = str(server_data.get("version", ""))

    # The /guestAuth/ prefix only answers at all when "Allow guest login"
    # is enabled server-wide -- a 200 here (instead of a login redirect/401)
    # confirms guest access is on and exposes the real project tree.
    try:
        projects_resp = requests.get(
            f"{base_url}/guestAuth/app/rest/projects", headers=headers, timeout=timeout, verify=False,
        )
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    if projects_resp.status_code == 200:
        try:
            projects_data = projects_resp.json()
        except ValueError:
            res.status = "unexpected_response"
            return res
        # TeamCity's REST API nests the list under a "project" key rather
        # than returning a bare array.
        projects = projects_data.get("project")
        if isinstance(projects, list):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            res.guest_projects_exposed = len(projects)
            res.project_names = [p.get("name", "") for p in projects if isinstance(p, dict)][:25]
        else:
            res.status = "unexpected_response"
    elif projects_resp.status_code in (401, 403):
        res.status = "auth_required"
    else:
        res.status = "unexpected_response"
    return res


SERVICE_LABELS = {
    "argocd": "Argo CD",
    "teamcity": "TeamCity",
}


def execute(target: str, service: str = "auto", timeout: int = 10) -> CicdExposureResult:
    base_url = normalize_base_url(target)
    if not base_url:
        return CicdExposureResult(target=target, error=f"Invalid target: '{target}'")

    effective_timeout = max(1.0, min(float(timeout), 20.0))
    svc = (service or "auto").strip().lower()

    # Built fresh on every call (not at module level) so that patching an
    # individual probe_* name is honored -- see unauth_datastore_probe's
    # own execute() for the identical reasoning.
    SERVICE_PROBERS = {
        "argocd": probe_argocd,
        "teamcity": probe_teamcity,
    }

    results: Dict[str, object] = {}
    if svc in SERVICE_PROBERS:
        results[svc] = SERVICE_PROBERS[svc](base_url, timeout=effective_timeout)
    else:
        # 'auto' (or any unrecognized value) checks both -- only two
        # services exist here, so there is no "cheapest common call"
        # worth narrowing the way unauth_datastore_probe's nine are.
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

    return CicdExposureResult(
        target=target,
        argocd=results.get("argocd"),
        teamcity=results.get("teamcity"),
        vulnerable=is_vuln,
        summary="; ".join(summary_parts),
    )
