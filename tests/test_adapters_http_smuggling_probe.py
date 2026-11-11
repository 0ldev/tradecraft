"""
Tests for HTTP smuggling probe adapter (payload construction, execution, parsing).
"""
import socket
import ssl
from unittest.mock import MagicMock, patch

from tradecraft.adapters.http_smuggling_probe.execute import (
    VARIANT_CL_TE,
    VARIANT_TE_CL,
    SmugglingProbeRun,
    VariantResult,
    _count_confirmed_responses,
    _count_status_codes,
    _first_response_end,
    build_cl_te_request,
    build_smuggled_request,
    build_te_cl_request,
    execute,
    normalize_host,
)
from tradecraft.adapters.http_smuggling_probe.parse import (
    VERDICT_CL_TE,
    VERDICT_CONN_ERR,
    VERDICT_NONE,
    VERDICT_TE_CL,
    classify_variant,
    parse,
)

NONCE = "abcdef012345"

# Real-shaped response captured from a Cloudflare-fronted origin (single response).
# Content-Length is derived from the actual body below, not hand-typed --
# a mismatched declared length here would make the boundary-aware
# detection logic (_first_response_end) think the body never finished, so
# this fixture has to be internally consistent the way a real server's
# response always is.
_CLEAN_BODY = b"<html><body>Not Found</body></html>"
CLEAN_RESPONSE = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Date: Sun, 01 Nov 2026 12:00:00 GMT\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(_CLEAN_BODY)).encode() + b"\r\n"
    b"Server: cloudflare\r\n"
    b"CF-RAY: 8f00000000000000-GRU\r\n"
    b"\r\n" + _CLEAN_BODY
)


def _sock_with_chunks(chunks):
    sock = MagicMock()
    sock.recv.side_effect = list(chunks) + [b""]
    return sock


def test_normalize_host():
    assert normalize_host("examplepaint.com.br") == "examplepaint.com.br"
    assert normalize_host("https://examplepaint.com.br/a/b") == "examplepaint.com.br"
    assert normalize_host("192.168.1.1:8080") == "192.168.1.1"


def test_smuggled_request_is_self_contained_get_with_nonce():
    req = build_smuggled_request("example.com", NONCE)
    assert req == (
        b"GET /tradecraft-smuggle-abcdef012345 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )


def test_cl_te_payload_content_length_covers_whole_body():
    payload = build_cl_te_request("example.com", NONCE)
    head, _, body = payload.partition(b"\r\n\r\n")
    assert b"Transfer-Encoding: chunked" in head
    assert f"Content-Length: {len(body)}".encode() in head
    # Chunked terminator comes first, then the embedded self-issued request.
    assert body.startswith(b"0\r\n\r\n")
    assert body.endswith(build_smuggled_request("example.com", NONCE))


def test_te_cl_payload_content_length_covers_only_chunk_size_line():
    payload = build_te_cl_request("example.com", NONCE)
    head, _, body = payload.partition(b"\r\n\r\n")
    smuggled = build_smuggled_request("example.com", NONCE)
    size_line = f"{len(smuggled):x}\r\n".encode()
    assert b"Transfer-Encoding: chunked" in head
    assert f"Content-Length: {len(size_line)}".encode() in head
    assert body.startswith(size_line)
    assert smuggled in body
    assert body.endswith(b"\r\n0\r\n\r\n")


def test_count_status_codes_ignores_1xx():
    data = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<html>ok</html>"
        b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"
    )
    # 404 begins with no newline before it (back-to-back responses), still counted.
    assert _count_status_codes(data) == [200, 404]


def test_confirmed_responses_ignores_status_line_shaped_text_inside_body():
    """The bug this guards against: a verbose error/WAF-block page whose
    *body* happens to quote something that looks like an HTTP status line
    (e.g. echoing the blocked request back) must NOT be read as a second,
    real response. Content-Length here correctly covers the whole body, so
    there is exactly one real response -- the embedded text is decoration,
    not a second message."""
    body = (
        b"<html><body>Blocked by WAF. Offending request: "
        b"HTTP/1.1 404 Not Found (not a real second response)</body></html>"
    )
    data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    # The blind scanner (used only for the loop's early-exit heuristic)
    # over-counts here -- that's expected and harmless on its own.
    assert _count_status_codes(data) == [200, 404]
    # The boundary-aware counter, which the actual verdict is based on,
    # must not be fooled: only the one real response.
    assert _count_confirmed_responses(data) == [200]
    assert _first_response_end(data) == len(data)


def test_confirmed_responses_finds_real_second_response_after_chunked_body():
    first_body = b"ok"
    chunk = f"{len(first_body):x}\r\n".encode() + first_body + b"\r\n0\r\n\r\n"
    first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk
    second = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"
    data = first + second
    assert _first_response_end(data) == len(first)
    assert _count_confirmed_responses(data) == [200, 404]


def test_confirmed_responses_undetermined_boundary_does_not_confirm_second():
    """No Content-Length, not chunked, and not a bodyless status code: the
    real end of this response's body is genuinely unknowable from the
    bytes alone (it's connection-close-delimited). A status-line-shaped
    match appearing later must not be confirmed as a second response."""
    data = (
        b"HTTP/1.1 200 OK\r\n\r\n"
        b"some body text that happens to mention HTTP/1.1 404 Not Found later on"
    )
    assert _first_response_end(data) is None
    assert _count_confirmed_responses(data) == [200]


def test_confirmed_responses_bodyless_status_has_immediate_boundary():
    data = b"HTTP/1.1 204 No Content\r\n\r\n" + b"HTTP/1.1 404 Not Found\r\n\r\n"
    first = b"HTTP/1.1 204 No Content\r\n\r\n"
    assert _first_response_end(data) == len(first)
    assert _count_confirmed_responses(data) == [204, 404]


@patch("socket.socket")
def test_execute_clean_single_response_per_connection(mock_sock_cls):
    mock_sock_cls.side_effect = [
        _sock_with_chunks([CLEAN_RESPONSE]),
        _sock_with_chunks([CLEAN_RESPONSE]),
    ]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=3)
    assert run.error is None
    assert [v.variant for v in run.variants] == [VARIANT_CL_TE, VARIANT_TE_CL]
    assert all(v.status == "ok" and v.responses_seen == 1 for v in run.variants)
    assert parse(run)["verdict"] == VERDICT_NONE


@patch("socket.socket")
def test_execute_second_response_on_same_connection_flags_cl_te(mock_sock_cls):
    two_responses = CLEAN_RESPONSE + b"HTTP/1.1 404 Not Found\r\nServer: cloudflare\r\n\r\n"
    mock_sock_cls.side_effect = [
        _sock_with_chunks([two_responses]),
        _sock_with_chunks([CLEAN_RESPONSE]),
    ]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=3)
    parsed = parse(run)
    assert parsed["verdict"] == VERDICT_CL_TE
    assert parsed["variants"][0]["verdict"] == VERDICT_CL_TE
    assert parsed["variants"][1]["verdict"] == VERDICT_NONE


@patch("socket.socket")
def test_execute_second_response_on_te_cl_connection(mock_sock_cls):
    two_responses = CLEAN_RESPONSE + b"HTTP/1.1 400 Bad Request\r\n\r\n"
    mock_sock_cls.side_effect = [
        _sock_with_chunks([CLEAN_RESPONSE]),
        _sock_with_chunks([two_responses]),
    ]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=3)
    assert parse(run)["verdict"] == VERDICT_TE_CL


@patch("socket.socket")
def test_execute_exactly_two_connections_and_one_send_each(mock_sock_cls):
    socks = [_sock_with_chunks([CLEAN_RESPONSE]), _sock_with_chunks([CLEAN_RESPONSE])]
    mock_sock_cls.side_effect = socks
    execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=3)
    assert mock_sock_cls.call_count == 2
    for s in socks:
        assert s.sendall.call_count == 1


@patch("socket.socket")
def test_execute_no_retry_when_first_connection_refused(mock_sock_cls):
    refused = MagicMock()
    refused.connect.side_effect = ConnectionRefusedError(111, "Connection refused")
    mock_sock_cls.side_effect = [refused, _sock_with_chunks([CLEAN_RESPONSE])]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=3)
    assert mock_sock_cls.call_count == 2
    assert run.variants[0].status == "refused"
    assert run.variants[0].connected is False
    assert parse(run)["verdict"] == VERDICT_NONE


@patch("socket.socket")
def test_execute_all_connections_failed_is_connection_error(mock_sock_cls):
    bad = MagicMock()
    bad.connect.side_effect = socket.timeout()
    mock_sock_cls.side_effect = [bad, bad]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=2)
    assert run.variants[0].status == "timeout"
    assert parse(run)["verdict"] == VERDICT_CONN_ERR


@patch("ssl.create_default_context")
@patch("socket.socket")
def test_execute_tls_wraps_each_connection(mock_sock_cls, mock_ctx_cls):
    raw1, raw2 = MagicMock(), MagicMock()
    mock_sock_cls.side_effect = [raw1, raw2]
    tls1 = _sock_with_chunks([CLEAN_RESPONSE])
    tls2 = _sock_with_chunks([CLEAN_RESPONSE])
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.side_effect = [tls1, tls2]
    mock_ctx_cls.return_value = mock_ctx

    run = execute(target="examplepaint.com.br", port=443, ssl_probe=True, timeout=4)
    assert mock_ctx.wrap_socket.call_count == 2
    assert run.ssl_used is True
    assert run.variants[0].status == "ok"
    assert run.variants[1].status == "ok"


@patch("socket.socket")
def test_execute_timeout_clamped_to_ten_seconds(mock_sock_cls):
    sock = _sock_with_chunks([CLEAN_RESPONSE])
    mock_sock_cls.side_effect = [sock, _sock_with_chunks([CLEAN_RESPONSE])]
    run = execute(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=99)
    assert run.timeout_s == 10.0
    assert sock.settimeout.call_args_list[0].args[0] == 10.0


def test_execute_invalid_port_and_target():
    run = execute(target="examplepaint.com.br", port=70000)
    assert run.error and "Invalid port" in run.error
    assert parse(run)["verdict"] == VERDICT_CONN_ERR

    run = execute(target="   ", port=443)
    assert run.error and "Invalid target" in run.error


def test_classify_variant_thresholds():
    base = dict(variant=VARIANT_CL_TE, status="ok", connected=True, request_head="")
    assert classify_variant(VariantResult(**base, responses_seen=0)) == VERDICT_NONE
    assert classify_variant(VariantResult(**base, responses_seen=1)) == VERDICT_NONE
    assert classify_variant(VariantResult(**base, responses_seen=2)) == VERDICT_CL_TE
    tecl = dict(base, variant=VARIANT_TE_CL)
    assert classify_variant(VariantResult(**tecl, responses_seen=2)) == VERDICT_TE_CL
    assert classify_variant(VariantResult(**dict(base, status="reset"), responses_seen=0)) == VERDICT_CONN_ERR


def test_parse_real_captured_clean_run_shape():
    run = SmugglingProbeRun(
        target="examplepaint.com.br",
        host="examplepaint.com.br",
        port=443,
        ssl_used=True,
        nonce=NONCE,
        timeout_s=5.0,
        variants=[
            VariantResult(
                variant=VARIANT_CL_TE, status="ok", connected=True,
                request_head="POST / HTTP/1.1", responses_seen=1, status_codes=[404],
                bytes_received=len(CLEAN_RESPONSE), first_response_ms=31.2, elapsed_ms=40.1,
                response_head=CLEAN_RESPONSE,
            ),
            VariantResult(
                variant=VARIANT_TE_CL, status="ok", connected=True,
                request_head="POST / HTTP/1.1", responses_seen=1, status_codes=[404],
                bytes_received=len(CLEAN_RESPONSE), first_response_ms=30.8, elapsed_ms=39.7,
                response_head=CLEAN_RESPONSE,
            ),
        ],
    )
    parsed = parse(run)
    assert parsed["verdict"] == VERDICT_NONE
    assert parsed["variants"][0]["status_codes"] == [404]
    assert "note" in parsed
