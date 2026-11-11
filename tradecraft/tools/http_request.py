from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.http_request.execute import (
    DEFAULT_TIMEOUT,
    execute as run_http_request,
    normalize_urls,
)
from tradecraft.adapters.http_request.parse import (
    DEFAULT_MAX_BODY_CHARS,
    evidence_target_from_url,
    host_port_from_url,
    parse_http_response,
)
from tradecraft.tools.base import Tool

# Batch mode (more than one URL in a single call) exists to confirm the
# same request shape across several already-known URLs without one call
# per URL -- not to read full response bodies -- so each entry's body
# preview is capped much tighter than the single-URL default.
BATCH_MAX_BODY_CHARS = 300
BATCH_RESULT_CAP = 15

# Hard per-call ceiling on how much body a single response can return,
# so one call can't flood the context no matter what the model asks for.
MAX_BODY_CHARS_CAP = 8000


class HttpRequest(Tool):
    tool_id = "http_request"

    def run(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[str] = None,
        data: Optional[str] = None,
        follow_redirects: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        body_offset: int = 0,
        body_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> Dict[str, Any]:
        urls = normalize_urls(url)
        if len(urls) <= 1:
            return self._run_single(
                url, method, headers, data, follow_redirects, timeout,
                body_offset, body_chars,
            )
        return self._run_many(urls, method, headers, data, follow_redirects, timeout)

    def _run_single(
        self,
        url: str,
        method: str,
        headers: Optional[str],
        data: Optional[str],
        follow_redirects: bool,
        timeout: int,
        body_offset: int = 0,
        body_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> Dict[str, Any]:
        raw = run_http_request(
            url=url,
            method=method,
            headers=headers,
            data=data,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

        chunk = min(max(1, int(body_chars or DEFAULT_MAX_BODY_CHARS)), MAX_BODY_CHARS_CAP)
        parsed = parse_http_response(
            raw, max_body_chars=chunk, body_offset=max(0, int(body_offset or 0)),
        )

        # Store complete untruncated evidence for EvidenceStore
        parsed["_full_evidence"] = {
            "url": parsed.get("url", url),
            "effective_url": parsed.get("effective_url", url),
            "method": parsed.get("method", method),
            "status_code": parsed.get("status_code", 0),
            "headers": parsed.get("headers", {}),
            "raw_body": raw.get("raw_body", ""),
            "duration_seconds": parsed.get("duration_seconds", 0.0),
        }

        return parsed

    def _run_many(
        self,
        urls: List[str],
        method: str,
        headers: Optional[str],
        data: Optional[str],
        follow_redirects: bool,
        timeout: int,
    ) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        full_results: List[Dict[str, Any]] = []
        for u in urls:
            raw = run_http_request(
                url=u, method=method, headers=headers, data=data,
                follow_redirects=follow_redirects, timeout=timeout,
            )
            parsed = parse_http_response(raw, max_body_chars=BATCH_MAX_BODY_CHARS)
            results.append(parsed)
            full_results.append({
                "url": parsed.get("url", u),
                "effective_url": parsed.get("effective_url", u),
                "method": parsed.get("method", method),
                "status_code": parsed.get("status_code", 0),
                # Carried over so extract_facts can derive the same
                # web_servers fact from the untruncated batch (used for
                # every probed URL) as it would from the display-truncated
                # `results` list (used only for the first BATCH_RESULT_CAP).
                "server": parsed.get("server", ""),
                "headers": parsed.get("headers", {}),
                "raw_body": raw.get("raw_body", ""),
                "duration_seconds": parsed.get("duration_seconds", 0.0),
            })

        # status_code == 0 means curl never got a response for that URL
        # (timeout, connection refused, DNS failure, ...) -- the per-item
        # "error" field says so, but a result buried inside a list of N is
        # easy to skim past. A real run POSTed 3 URLs in one call, all 3
        # timed out, and the report's "Verified Clean" section then treated
        # that as a negative result instead of "never got an answer."
        failed_count = sum(1 for r in results if r.get("status_code", 0) == 0)

        joined_target = ",".join(urls)
        res: Dict[str, Any] = {
            "target": joined_target,
            "requested_count": len(urls),
            "succeeded_count": len(urls) - failed_count,
            "failed_count": failed_count,
        }
        if failed_count:
            res["warning"] = (
                f"{failed_count} of {len(urls)} request(s) got no response at all "
                "(see each result's status_code=0/error) -- treat those as untested, not as a clean negative result."
            )
        if len(results) > BATCH_RESULT_CAP:
            res["results"] = results[:BATCH_RESULT_CAP]
            res["omitted_results"] = len(results) - BATCH_RESULT_CAP
            res["note"] = (
                f"{len(results) - BATCH_RESULT_CAP} more requested URLs omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["results"] = results

        res["_full_evidence"] = {"target": joined_target, "results": full_results}
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        url = params.get("url", "")
        # Peek, don't pop: extract_facts (called after this, per
        # tradecraft/execution/loop.py) still needs the untruncated batch here
        # to produce a fact for every requested URL, not just the subset
        # kept in result["results"] for display (BATCH_RESULT_CAP). The
        # loop strips this key from `result` itself once both extractions
        # are done, so it never reaches the model.
        full = result.get("_full_evidence")
        if not url or full is None:
            return None
        urls = normalize_urls(url)
        canonical_url = urls[0] if urls else url
        canonical = evidence_target_from_url(canonical_url) or canonical_url
        aliases = [evidence_target_from_url(u) or u for u in urls[1:]]
        return canonical, full, aliases

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "results" in result:
            # Prefer the untruncated batch (still present pre-loop-cleanup,
            # see extract_evidence above) so every requested URL gets a
            # fact row, not just the subset kept in result["results"] for
            # the model-facing display truncation.
            full_evidence = result.get("_full_evidence")
            entries = full_evidence["results"] if full_evidence else result.get("results", [])
            facts = []
            for entry in entries:
                entry_url = entry.get("url", "")
                if not entry_url:
                    continue
                facts.extend(self._fact_from_single(entry_url, entry, result.get("evidence_id")))
            return facts

        url = params.get("url", "")
        if not url:
            return []
        return self._fact_from_single(url, result, result.get("evidence_id"))

    @staticmethod
    def _fact_from_single(url: str, result: Dict[str, Any], evidence_id: Optional[str]) -> List[Dict[str, Any]]:
        host, port = host_port_from_url(url)
        status_code = result.get("status_code", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}

        if status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403):
            fact["live"] = True

        server = result.get("server")
        if server:
            fact["web_servers"] = [server]

        headers = result.get("headers", {})
        for k, v in headers.items():
            if k.lower() == "x-powered-by" and v:
                fact["technologies"] = [v]
                break

        if evidence_id:
            fact["evidence"] = evidence_id

        if len(fact) > 2:
            return [fact]
        return []
