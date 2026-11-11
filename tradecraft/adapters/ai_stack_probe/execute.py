"""
Execution logic for ai_stack_probe: non-destructive verification of exposed,
unauthenticated AI infrastructure, gateways, and orchestration engines
(Ollama, vLLM/LocalAI, Langflow, Flowise, Ray, LiteLLM Proxy, and MLflow).
"""
from __future__ import annotations

import json
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 5

SERVICE_DEFAULT_PORTS = {
    "ollama": 11434,
    "vllm": 8000,
    "langflow": 7860,
    "flowise": 3000,
    "ray": 8265,
    "litellm": 4000,
    "mlflow": 5000,
}


@dataclass
class ServiceCheckResult:
    service: str
    port: int
    accessible: bool = False
    unauthenticated: bool = False
    version: str = ""
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class RawAiStackProbeResult:
    target: str
    host: str
    vulnerable: bool = False
    findings: List[ServiceCheckResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_host_port(target: str, default_port: Optional[int] = None) -> tuple[str, Optional[int], str]:
    """Returns (host, port, scheme)."""
    t = target.strip()
    scheme = "http"
    if t.startswith("http://") or t.startswith("https://"):
        parsed = urllib.parse.urlsplit(t)
        host = parsed.hostname or t
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme
        return host, port, scheme

    if ":" in t:
        parts = t.split(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = default_port
        return host, port, scheme

    return t, default_port, scheme


def is_port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Fast socket probe to check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _safe_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[requests.Response]:
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return resp
    except Exception:
        return None


def probe_ollama(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="ollama", port=port)
    base_url = f"{scheme}://{host}:{port}"
    tags_resp = _safe_get(f"{base_url}/api/tags", timeout=timeout)
    ver_resp = _safe_get(f"{base_url}/api/version", timeout=timeout)

    version = ""
    if ver_resp and ver_resp.status_code == 200:
        try:
            version = ver_resp.json().get("version", "")
        except Exception:
            pass

    if tags_resp and tags_resp.status_code == 200:
        try:
            data = tags_resp.json()
            models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            res.accessible = True
            res.unauthenticated = True
            res.version = version
            res.details = {"models": models, "model_count": len(models)}
            res.summary = f"Exposed Ollama API (version: {version or 'unknown'}) with {len(models)} model(s)"
            return res
        except Exception:
            pass

    if version:
        res.accessible = True
        res.version = version
        res.summary = f"Ollama instance found (version: {version})"
    return res


def probe_vllm(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="vllm", port=port)
    base_url = f"{scheme}://{host}:{port}"
    models_resp = _safe_get(f"{base_url}/v1/models", timeout=timeout)
    if models_resp and models_resp.status_code == 200:
        try:
            data = models_resp.json()
            if data.get("object") == "list" and "data" in data:
                models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
                res.accessible = True
                res.unauthenticated = True
                res.details = {"models": models, "model_count": len(models)}
                res.summary = f"Unauthenticated OpenAI-compatible model server (vLLM/LocalAI) exposing {len(models)} model(s)"
        except Exception:
            pass
    return res


def probe_langflow(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="langflow", port=port)
    base_url = f"{scheme}://{host}:{port}"
    flows_resp = _safe_get(f"{base_url}/api/v1/flows", timeout=timeout)
    ver_resp = _safe_get(f"{base_url}/api/v1/version", timeout=timeout)

    version = ""
    if ver_resp and ver_resp.status_code == 200:
        try:
            version = ver_resp.json().get("version", "")
        except Exception:
            pass

    if flows_resp and flows_resp.status_code == 200:
        try:
            data = flows_resp.json()
            if isinstance(data, list):
                res.accessible = True
                res.unauthenticated = True
                res.version = version
                res.details = {"flow_count": len(data), "flows": [f.get("name") for f in data[:10] if isinstance(f, dict)]}
                res.summary = f"Unauthenticated Langflow API exposing {len(data)} flow(s)"
                return res
        except Exception:
            pass

    if version:
        res.accessible = True
        res.version = version
        res.summary = f"Langflow instance detected (version: {version})"
    return res


def probe_flowise(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="flowise", port=port)
    base_url = f"{scheme}://{host}:{port}"
    flows_resp = _safe_get(f"{base_url}/api/v1/chatflows", timeout=timeout)
    if flows_resp and flows_resp.status_code == 200:
        try:
            data = flows_resp.json()
            if isinstance(data, list):
                res.accessible = True
                res.unauthenticated = True
                res.details = {"chatflow_count": len(data), "chatflows": [f.get("name") for f in data[:10] if isinstance(f, dict)]}
                res.summary = f"Unauthenticated Flowise instance exposing {len(data)} chatflow(s)"
        except Exception:
            pass
    return res


def probe_ray(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="ray", port=port)
    base_url = f"{scheme}://{host}:{port}"
    ver_resp = _safe_get(f"{base_url}/api/version", timeout=timeout)
    jobs_resp = _safe_get(f"{base_url}/api/jobs/", timeout=timeout)

    version = ""
    if ver_resp and ver_resp.status_code == 200:
        try:
            version = ver_resp.json().get("ray_version", "")
        except Exception:
            pass

    if jobs_resp and jobs_resp.status_code == 200:
        res.accessible = True
        res.unauthenticated = True
        res.version = version
        res.summary = f"Unauthenticated Ray Dashboard / Job API exposed (CVE-2023-48022 risk)"
        return res

    if version:
        res.accessible = True
        res.version = version
        res.summary = f"Ray Dashboard API detected (version: {version})"
    return res


def probe_litellm(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="litellm", port=port)
    base_url = f"{scheme}://{host}:{port}"
    health_resp = _safe_get(f"{base_url}/health", timeout=timeout)
    routes_resp = _safe_get(f"{base_url}/routes", timeout=timeout)

    if routes_resp and routes_resp.status_code == 200:
        res.accessible = True
        res.unauthenticated = True
        res.summary = "Unauthenticated LiteLLM Proxy /routes endpoint exposed"
        return res

    if health_resp and health_resp.status_code == 200:
        try:
            text = health_resp.text.lower()
            if "healthy" in text or "status" in text:
                res.accessible = True
                res.summary = "LiteLLM Proxy /health endpoint accessible"
        except Exception:
            pass
    return res


def probe_mlflow(host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    res = ServiceCheckResult(service="mlflow", port=port)
    base_url = f"{scheme}://{host}:{port}"
    exp_resp = _safe_get(f"{base_url}/api/2.0/mlflow/experiments/list", timeout=timeout)
    if not exp_resp or exp_resp.status_code != 200:
        exp_resp = _safe_get(f"{base_url}/ajax-api/2.0/mlflow/experiments/list", timeout=timeout)

    if exp_resp and exp_resp.status_code == 200:
        try:
            data = exp_resp.json()
            if "experiments" in data:
                res.accessible = True
                res.unauthenticated = True
                res.details = {"experiments_count": len(data["experiments"])}
                res.summary = f"Unauthenticated MLflow Tracking Server exposing {len(data['experiments'])} experiment(s)"
        except Exception:
            pass
    return res


def run_prober(srv_name: str, host: str, port: int, scheme: str = "http", timeout: int = DEFAULT_TIMEOUT) -> ServiceCheckResult:
    """Dispatches to the prober function for the given service."""
    mapping = {
        "ollama": probe_ollama,
        "vllm": probe_vllm,
        "langflow": probe_langflow,
        "flowise": probe_flowise,
        "ray": probe_ray,
        "litellm": probe_litellm,
        "mlflow": probe_mlflow,
    }
    func = mapping.get(srv_name)
    if func:
        return func(host, port, scheme=scheme, timeout=timeout)
    return ServiceCheckResult(service=srv_name, port=port)


def execute(
    target: str,
    service: str = "auto",
    port: Optional[int] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawAiStackProbeResult:
    """Executes non-destructive checks against AI infrastructure services."""
    host, detected_port, scheme = normalize_host_port(target, default_port=port)
    if not host:
        return RawAiStackProbeResult(target=target, host="", error="empty target")

    effective_port = port or detected_port
    srv = service.strip().lower()

    findings: List[ServiceCheckResult] = []

    if srv != "auto" and srv in SERVICE_DEFAULT_PORTS:
        target_port = effective_port or SERVICE_DEFAULT_PORTS.get(srv, 80)
        res = run_prober(srv, host, target_port, scheme=scheme, timeout=timeout)
        if res.accessible:
            findings.append(res)
    else:
        # If a specific port was given on target (e.g. target.com:11434), match by port first
        if effective_port:
            for s_name, s_port in SERVICE_DEFAULT_PORTS.items():
                if effective_port == s_port:
                    res = run_prober(s_name, host, effective_port, scheme=scheme, timeout=timeout)
                    if res.accessible:
                        findings.append(res)
            # If not matched by default port, probe all supported services against this port
            if not findings:
                for s_name in SERVICE_DEFAULT_PORTS:
                    res = run_prober(s_name, host, effective_port, scheme=scheme, timeout=timeout)
                    if res.accessible:
                        findings.append(res)
                        break
        else:
            # Full scan: check open TCP ports among standard AI service ports
            for s_name, s_port in SERVICE_DEFAULT_PORTS.items():
                if is_port_open(host, s_port, timeout=1.5):
                    res = run_prober(s_name, host, s_port, scheme=scheme, timeout=timeout)
                    if res.accessible:
                        findings.append(res)

    is_vuln = any(f.unauthenticated for f in findings)
    return RawAiStackProbeResult(
        target=target,
        host=host,
        vulnerable=is_vuln,
        findings=findings,
    )
