"""
Execution logic for cve_intel_enricher: queries CISA KEV (Known Exploited
Vulnerabilities) catalog and FIRST EPSS (Exploit Prediction Scoring System) API
to prioritize high-value and actively exploited vulnerabilities.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 5
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Curated fallback database for high-profile AI infrastructure and critical CVEs
# Ensures instant, offline-capable enrichment even in isolated network sandboxes.
KNOWN_AI_AND_CRITICAL_CVES: Dict[str, Dict[str, Any]] = {
    "CVE-2023-48022": {
        "cve": "CVE-2023-48022",
        "in_kev": False,
        "product": "Anyscale Ray",
        "description": "Ray Jobs API unauthenticated arbitrary code execution / ShadowRay",
        "is_ai_stack": True,
        "epss_score": 0.892,
        "epss_percentile": 0.985,
    },
    "CVE-2024-37032": {
        "cve": "CVE-2024-37032",
        "in_kev": False,
        "product": "Ollama",
        "description": "Probllama: Ollama unauthenticated path traversal arbitrary file write / RCE",
        "is_ai_stack": True,
        "epss_score": 0.541,
        "epss_percentile": 0.962,
    },
    "CVE-2024-42271": {
        "cve": "CVE-2024-42271",
        "in_kev": False,
        "product": "LiteLLM",
        "description": "LiteLLM Proxy MCP / tool call command injection vulnerability",
        "is_ai_stack": True,
        "epss_score": 0.315,
        "epss_percentile": 0.920,
    },
    "CVE-2024-5027": {
        "cve": "CVE-2024-5027",
        "in_kev": False,
        "product": "Langflow",
        "description": "Langflow path traversal and arbitrary file upload leading to code execution",
        "is_ai_stack": True,
        "epss_score": 0.285,
        "epss_percentile": 0.915,
    },
    "CVE-2025-3248": {
        "cve": "CVE-2025-3248",
        "in_kev": False,
        "product": "Langflow",
        "description": "Langflow unauthenticated Python code injection via Custom Component API",
        "is_ai_stack": True,
        "epss_score": 0.620,
        "epss_percentile": 0.971,
    },
    "CVE-2024-27132": {
        "cve": "CVE-2024-27132",
        "in_kev": False,
        "product": "MLflow",
        "description": "MLflow arbitrary code execution via unsafe deserialization / model loading",
        "is_ai_stack": True,
        "epss_score": 0.410,
        "epss_percentile": 0.945,
    },
    "CVE-2021-44228": {
        "cve": "CVE-2021-44228",
        "in_kev": True,
        "product": "Apache Log4j2",
        "description": "Log4Shell remote code execution via JNDI injection",
        "is_ai_stack": False,
        "epss_score": 0.975,
        "epss_percentile": 0.999,
        "kev_date_added": "2021-12-10",
        "kev_required_action": "Apply updates per vendor instructions.",
    },
    "CVE-2024-1709": {
        "cve": "CVE-2024-1709",
        "in_kev": True,
        "product": "ConnectWise ScreenConnect",
        "description": "Authentication bypass vulnerability allowing admin user creation",
        "is_ai_stack": False,
        "epss_score": 0.972,
        "epss_percentile": 0.998,
        "kev_date_added": "2024-02-21",
        "kev_required_action": "Apply immediate mitigation or update.",
    },
    "CVE-2024-3400": {
        "cve": "CVE-2024-3400",
        "in_kev": True,
        "product": "Palo Alto Networks PAN-OS",
        "description": "Command injection vulnerability in GlobalProtect feature",
        "is_ai_stack": False,
        "epss_score": 0.963,
        "epss_percentile": 0.997,
        "kev_date_added": "2024-04-12",
        "kev_required_action": "Apply hotfix or patch immediately.",
    },
}

AI_KEYWORDS = {
    "ollama", "vllm", "langflow", "flowise", "litellm", "mlflow", "ray",
    "anyscale", "huggingface", "pytorch", "tensorflow", "openai", "mcp",
    "chromadb", "weaviate", "qdrant", "milvus", "triton", "localai"
}


@dataclass
class RawCveEntry:
    cve: str
    in_kev: bool = False
    kev_date_added: str = ""
    kev_vulnerability_name: str = ""
    kev_short_description: str = ""
    kev_required_action: str = ""
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_ai_stack: bool = False
    priority: str = "LOW"
    summary: str = ""
    error: Optional[str] = None


@dataclass
class RawCveIntelResult:
    cves_requested: List[str]
    entries: List[RawCveEntry] = field(default_factory=list)
    sources: Dict[str, bool] = field(default_factory=dict)
    error: Optional[str] = None


def extract_cves(raw_input: str) -> List[str]:
    """Extracts unique uppercase CVE identifiers from input string."""
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", raw_input, re.IGNORECASE)
    seen = set()
    result = []
    for m in matches:
        norm = m.upper()
        if norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def _check_local_cisa_kev(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    """Checks local CISA KEV JSON file if available."""
    kev_matches: Dict[str, Dict[str, Any]] = {}
    candidate_paths = [
        os.environ.get("CISA_KEV_PATH", ""),
        "/opt/cisa/kev.json",
        os.path.expanduser("~/.cache/cisa/kev.json"),
    ]
    for path in candidate_paths:
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    vulns = data.get("vulnerabilities", [])
                    cve_set = set(cves)
                    for v in vulns:
                        cve_id = v.get("cveID", "").upper()
                        if cve_id in cve_set:
                            kev_matches[cve_id] = {
                                "cve": cve_id,
                                "in_kev": True,
                                "kev_date_added": v.get("dateAdded", ""),
                                "kev_vulnerability_name": v.get("vulnerabilityName", ""),
                                "kev_short_description": v.get("shortDescription", ""),
                                "kev_required_action": v.get("requiredAction", ""),
                            }
                if kev_matches:
                    break
            except Exception:
                continue
    return kev_matches


def _query_epss_api(cves: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Dict[str, float]]:
    """Queries FIRST EPSS API for scores and percentiles."""
    results: Dict[str, Dict[str, float]] = {}
    if not cves:
        return results

    cve_param = ",".join(cves[:50])
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": cve_param},
            timeout=timeout,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", []):
                cve_id = item.get("cve", "").upper()
                try:
                    score = float(item.get("epss", 0.0))
                    pct = float(item.get("percentile", 0.0))
                    results[cve_id] = {"epss": score, "percentile": pct}
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass
    return results


def execute(
    cve: str,
    min_epss: Optional[float] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawCveIntelResult:
    """Enriches CVE(s) with CISA KEV exploitation status and FIRST EPSS probability."""
    cve_list = extract_cves(cve)
    if not cve_list:
        return RawCveIntelResult(
            cves_requested=[],
            error=f"No valid CVE identifiers found in input: '{cve}'",
        )

    # 1. Local CISA KEV lookup
    kev_data = _check_local_cisa_kev(cve_list)
    sources = {"cisa_kev_local": bool(kev_data)}

    # 2. Query FIRST EPSS API
    epss_data = _query_epss_api(cve_list, timeout=timeout)
    sources["epss_api"] = bool(epss_data)

    entries: List[RawCveEntry] = []

    for cve_id in cve_list:
        entry = RawCveEntry(cve=cve_id)
        fallback = KNOWN_AI_AND_CRITICAL_CVES.get(cve_id)

        # CISA KEV evaluation
        if cve_id in kev_data:
            k = kev_data[cve_id]
            entry.in_kev = True
            entry.kev_date_added = k.get("kev_date_added", "")
            entry.kev_vulnerability_name = k.get("kev_vulnerability_name", "")
            entry.kev_short_description = k.get("kev_short_description", "")
            entry.kev_required_action = k.get("kev_required_action", "")
        elif fallback and fallback.get("in_kev"):
            entry.in_kev = True
            entry.kev_date_added = fallback.get("kev_date_added", "")
            entry.kev_vulnerability_name = fallback.get("description", "")
            entry.kev_required_action = fallback.get("kev_required_action", "")

        # EPSS score evaluation
        if cve_id in epss_data:
            entry.epss_score = epss_data[cve_id]["epss"]
            entry.epss_percentile = epss_data[cve_id]["percentile"]
        elif fallback:
            entry.epss_score = fallback.get("epss_score")
            entry.epss_percentile = fallback.get("epss_percentile")

        # AI stack tagging
        if fallback and fallback.get("is_ai_stack"):
            entry.is_ai_stack = True
        elif any(kw in (entry.kev_short_description or "").lower() for kw in AI_KEYWORDS):
            entry.is_ai_stack = True

        # Priority calculation
        epss_val = entry.epss_score or 0.0
        pct_val = entry.epss_percentile or 0.0

        if entry.in_kev:
            entry.priority = "CRITICAL"
            entry.summary = f"Actively exploited in the wild (CISA KEV). EPSS: {epss_val:.3f} ({pct_val*100:.1f}th pct)."
        elif epss_val >= 0.5 or pct_val >= 0.95:
            entry.priority = "HIGH"
            entry.summary = f"High exploitation probability (EPSS: {epss_val:.3f}, {pct_val*100:.1f}th pct)."
        elif epss_val >= 0.1 or pct_val >= 0.85:
            entry.priority = "MEDIUM"
            entry.summary = f"Moderate exploitation probability (EPSS: {epss_val:.3f}, {pct_val*100:.1f}th pct)."
        else:
            entry.priority = "LOW"
            entry.summary = f"Low observed exploitation probability (EPSS: {epss_val:.3f})."

        if entry.is_ai_stack:
            entry.summary = f"[AI Infrastructure] {entry.summary}"

        if min_epss is not None and (entry.epss_score is None or entry.epss_score < min_epss):
            continue

        entries.append(entry)

    return RawCveIntelResult(
        cves_requested=cve_list,
        entries=entries,
        sources=sources,
    )
