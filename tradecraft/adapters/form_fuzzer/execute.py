"""
Network execution for form_fuzzer: discovers HTML forms and probes input fields.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

from typing import Optional

import requests
import urllib3

from tradecraft.adapters.form_fuzzer import parse as form_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_FORMS = 5
MAX_FIELDS_PER_FORM = 5
MAX_BODY_CHARS = 50000
DEFAULT_TIMEOUT = 10


def execute(
    target: str,
    internal_url: str = "",
    target_param: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None,
) -> form_parse.RawFormFuzzerResult:
    """Executes form discovery and bounded parameter fuzzing against target."""
    target_url = form_parse.normalize_target_url(target)
    if not target_url:
        return form_parse.RawFormFuzzerResult(error="empty target URL")

    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    result = form_parse.RawFormFuzzerResult(target=target_url)
    payloads = form_parse.build_payloads(internal_url=internal_url)

    try:
        # 1. Fetch target HTML page to extract forms
        try:
            resp = session.get(
                target_url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"},
            )
            html_content = resp.text
        except requests.RequestException as e:
            # If target GET fails, still attempt query params if available
            html_content = ""
            result.error = f"Failed to fetch target: {e}"

        forms = form_parse.extract_forms(html_content, target_url)
        if not forms:
            synthetic = form_parse.create_synthetic_form(target_url, target_param=target_param)
            if synthetic:
                forms = [synthetic]

        result.forms_found = len(forms)
        if not forms:
            return result

        # Bound the number of forms tested
        forms_to_probe = forms[:MAX_FORMS]

        for form in forms_to_probe:
            fields = form.fields_to_test
            if target_param:
                # If specific target_param requested, restrict to it
                fields = [f for f in fields if f == target_param]
                if not fields:
                    fields = [target_param]
            fields_to_probe = fields[:MAX_FIELDS_PER_FORM]

            for field in fields_to_probe:
                result.fields_tested += 1

                ssti_res = {}
                for ssti_key in ("ssti_true", "ssti_false"):
                    fuzz_data = form.base_data.copy()
                    fuzz_data[field] = payloads[ssti_key]
                    try:
                        if form.method == "post":
                            r = session.post(
                                form.action_url,
                                data=fuzz_data,
                                timeout=timeout,
                                verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                            )
                        else:
                            r = session.get(
                                form.action_url,
                                params=fuzz_data,
                                timeout=timeout,
                                verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                            )
                        ssti_res[ssti_key] = r.text[:MAX_BODY_CHARS]
                    except requests.RequestException:
                        pass

                if "ssti_true" in ssti_res and "ssti_false" in ssti_res:
                    ssti_vuln, _, ssti_snip = form_parse.check_ssti_differential(
                        ssti_res["ssti_true"], ssti_res["ssti_false"]
                    )
                    if ssti_vuln:
                        result.vulnerabilities.append(
                            form_parse.RawVulnerability(
                                form_action=form.action_url,
                                parameter=field,
                                vulnerability_type="ssti",
                                payload_used="{{7*7}} vs {{7*6}}",
                                snippet=ssti_snip,
                            )
                        )

                # B. SSRF, SQLi, and XSS probes
                for vuln_type in ("ssrf", "sqli", "xss"):
                    payload = payloads[vuln_type]
                    fuzz_data = form.base_data.copy()
                    fuzz_data[field] = payload

                    try:
                        if form.method == "post":
                            r = session.post(
                                form.action_url,
                                data=fuzz_data,
                                timeout=timeout,
                                verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                            )
                        else:
                            r = session.get(
                                form.action_url,
                                params=fuzz_data,
                                timeout=timeout,
                                verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                            )

                        body = r.text[:MAX_BODY_CHARS]

                        if vuln_type == "ssrf":
                            is_v, _, snip = form_parse.check_ssrf_response(r.status_code, body)
                            if is_v:
                                result.vulnerabilities.append(
                                    form_parse.RawVulnerability(
                                        form_action=form.action_url,
                                        parameter=field,
                                        vulnerability_type="ssrf",
                                        payload_used=payload,
                                        snippet=snip,
                                    )
                                )
                        elif vuln_type == "sqli":
                            is_v, _, snip = form_parse.check_sqli_response(body)
                            if is_v:
                                result.vulnerabilities.append(
                                    form_parse.RawVulnerability(
                                        form_action=form.action_url,
                                        parameter=field,
                                        vulnerability_type="sqli",
                                        payload_used=payload,
                                        snippet=snip,
                                    )
                                )
                        elif vuln_type == "xss":
                            is_v, _, snip = form_parse.check_xss_response(body, payload)
                            if is_v:
                                result.vulnerabilities.append(
                                    form_parse.RawVulnerability(
                                        form_action=form.action_url,
                                        parameter=field,
                                        vulnerability_type="xss",
                                        payload_used=payload,
                                        snippet=snip,
                                    )
                                )

                    except requests.RequestException:
                        continue
    finally:
        if close_session:
            session.close()

    return result
