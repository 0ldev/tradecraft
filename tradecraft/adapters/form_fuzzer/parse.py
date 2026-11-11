"""
Pure parsing, form extraction, and response signature detection for form_fuzzer.
No I/O or network requests here.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

SSRF_INDICATORS = [
    "ami-id",
    "instance-id",
    "local-hostname",
    "security-credentials",
    "project-id",
    "computeMetadata",
    "ComputeMetadata",
    "azEnvironment",
    "vmId",
    "169.254.169.254",
]

SQLI_INDICATORS = [
    "syntax error",
    "error in your sql syntax",
    "sql syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL query failed",
    "SQLITE_ERROR",
    "unrecognized token",
    "ODBC Driver",
    "Microsoft OLE DB Provider",
]

DEFAULT_METADATA_URL = "http://169.254.169.254/latest/meta-data/"


@dataclass
class FormInfo:
    action_url: str
    method: str = "get"
    base_data: Dict[str, str] = field(default_factory=dict)
    fields_to_test: List[str] = field(default_factory=list)


@dataclass
class RawVulnerability:
    form_action: str
    parameter: str
    vulnerability_type: str
    payload_used: str
    snippet: str = ""


@dataclass
class RawFormFuzzerResult:
    target: str = ""
    forms_found: int = 0
    fields_tested: int = 0
    vulnerabilities: List[RawVulnerability] = field(default_factory=list)
    error: Optional[str] = None


class _FormHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: List[FormInfo] = []
        self._current_action = ""
        self._current_method = "get"
        self._current_base_data: Dict[str, str] = {}
        self._current_fields: List[str] = []
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        attr_dict = {k.lower(): v or "" for k, v in attrs}

        if tag_lower == "form":
            self._flush_current()
            self._in_form = True
            action = attr_dict.get("action", "")
            self._current_action = urllib.parse.urljoin(self.base_url, action) if action else self.base_url
            self._current_method = attr_dict.get("method", "get").lower()
            self._current_base_data = {}
            self._current_fields = []
        elif self._in_form and tag_lower in ("input", "textarea", "select"):
            name = attr_dict.get("name")
            if not name:
                return

            input_type = attr_dict.get("type", "text").lower()
            if input_type in ("submit", "button", "image", "reset"):
                return

            default_val = attr_dict.get("value", "test")
            self._current_base_data[name] = default_val

            if input_type != "hidden" and name not in self._current_fields:
                self._current_fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            self._flush_current()

    def _flush_current(self) -> None:
        if self._in_form:
            form = FormInfo(
                action_url=self._current_action,
                method=self._current_method,
                base_data=self._current_base_data,
                fields_to_test=self._current_fields,
            )
            self.forms.append(form)
            self._in_form = False
            self._current_action = ""
            self._current_method = "get"
            self._current_base_data = {}
            self._current_fields = []


def normalize_target_url(target: str) -> str:
    """Normalize target to full URL defaulting to http://."""
    target = target.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def parse_host_port(target: str) -> Tuple[str, int]:
    """Extract host and port from target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def extract_forms(html: str, base_url: str) -> List[FormInfo]:
    """Extracts all HTML forms and their input fields from HTML content."""
    if not html:
        return []
    parser = _FormHTMLParser(base_url=base_url)
    try:
        parser.feed(html)
        parser._flush_current()
    except Exception:
        pass
    return parser.forms


def create_synthetic_form(base_url: str, target_param: str = "") -> Optional[FormInfo]:
    """Creates a synthetic GET form for targets with query parameters or explicit target_param."""
    parsed = urllib.parse.urlsplit(base_url)
    query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    base_data = {k: v or "test" for k, v in query_params}
    fields: List[str] = list(base_data.keys())

    if target_param and target_param not in fields:
        fields.append(target_param)
        base_data[target_param] = "test"

    if not fields:
        return None

    clean_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return FormInfo(
        action_url=clean_url or base_url,
        method="get",
        base_data=base_data,
        fields_to_test=fields,
    )


def build_payloads(internal_url: str = "") -> Dict[str, str]:
    """Constructs dictionary of test payloads for SSRF, SQLi, SSTI, and XSS."""
    ssrf_target = internal_url.strip() if internal_url and internal_url.strip() else DEFAULT_METADATA_URL
    return {
        "ssrf": ssrf_target,
        "sqli": "admin' OR 1=1--",
        "xss": "<script>alert(1)</script>",
        "ssti_true": "{{7*7}}",
        "ssti_false": "{{7*6}}",
    }


def check_ssrf_response(status_code: int, body: str) -> Tuple[bool, str, str]:
    """Inspects response for cloud metadata indicators."""
    if status_code != 200 or not body:
        return False, "", ""
    body_lower = body.lower()
    for ind in SSRF_INDICATORS:
        if ind.lower() in body_lower:
            start = max(0, body_lower.find(ind.lower()) - 20)
            end = min(len(body), start + 150)
            return True, "ssrf_cloud_metadata", body[start:end].strip()
    return False, "", ""


def check_sqli_response(body: str) -> Tuple[bool, str, str]:
    """Inspects response for SQL error indicators."""
    if not body:
        return False, "", ""
    body_lower = body.lower()
    for ind in SQLI_INDICATORS:
        if ind.lower() in body_lower:
            start = max(0, body_lower.find(ind.lower()) - 20)
            end = min(len(body), start + 150)
            return True, "sqli_error", body[start:end].strip()
    return False, "", ""


def check_ssti_differential(res_true_body: str, res_false_body: str) -> Tuple[bool, str, str]:
    """Inspects differential response between {{7*7}} and {{7*6}}."""
    has_49_true = "49" in res_true_body
    has_49_false = "49" in res_false_body
    has_42_true = "42" in res_true_body
    has_42_false = "42" in res_false_body

    if has_49_true and not has_49_false and has_42_false and not has_42_true:
        snippet = "Evaluated {{7*7}} -> 49 and {{7*6}} -> 42 differentially"
        return True, "ssti_differential", snippet
    return False, "", ""


def check_xss_response(body: str, payload: str) -> Tuple[bool, str, str]:
    """Inspects response for unescaped XSS payload reflection."""
    if payload in body:
        start = max(0, body.find(payload) - 20)
        end = min(len(body), start + len(payload) + 50)
        return True, "xss_reflection", body[start:end].strip()
    return False, "", ""


def parse_form_fuzzer_result(raw: RawFormFuzzerResult) -> Dict[str, Any]:
    """Transforms raw probe results into structured finding output."""
    vulns = [
        {
            "form_action": v.form_action,
            "parameter": v.parameter,
            "vulnerability_type": v.vulnerability_type,
            "payload_used": v.payload_used,
            "snippet": v.snippet,
        }
        for v in raw.vulnerabilities
    ]

    return {
        "target": raw.target,
        "forms_found": raw.forms_found,
        "fields_tested": raw.fields_tested,
        "vulnerable": len(vulns) > 0,
        "vulnerabilities": vulns,
        "error": raw.error,
    }
