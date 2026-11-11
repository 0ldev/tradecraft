"""
Execution logic for the HTTP request smuggling differential probe.

Sends exactly two raw HTTP/1.1 requests, each on its own fresh connection,
in sequence: one CL.TE-shaped request and one TE.CL-shaped request. Each
request carries a second request (a GET to a per-invocation nonce path)
embedded where a front-end and a back-end that disagree about message
framing would parse it as a separate request. The probe only ever reads
the responses to its own traffic on its own connection.

Discrepancy signal: if a connection yields more than one non-1xx status
line, the server parsed bytes we sent as an additional request beyond the
one we framed -- a second, unsolicited response on the same connection.

No retries, no loops over attempts, no concurrency. Timeouts are strict.
"""
from __future__ import annotations

import re
import secrets
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Upper bound on bytes read per connection, so a misbehaving peer that
# streams data cannot pin the probe in memory.
_MAX_RESPONSE_BYTES = 64 * 1024
# Stop reading a connection once this many responses have been seen.
_MAX_COUNTED_RESPONSES = 2
_EVIDENCE_HEAD_BYTES = 2048

VARIANT_CL_TE = "cl_te"
VARIANT_TE_CL = "te_cl"


def normalize_host(target: str) -> str:
    """Extracts a bare hostname or IP address from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        return (parsed.hostname or raw).strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            return raw[1 : raw.index("]")]
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip()
    return raw.strip()


@dataclass
class VariantResult:
    variant: str  # VARIANT_CL_TE or VARIANT_TE_CL
    status: str  # "ok", "timeout", "reset", "refused", "ssl_error", "dns_error", "error"
    connected: bool
    request_head: str  # request line + headers sent (body omitted), for evidence
    responses_seen: int = 0
    status_codes: List[int] = field(default_factory=list)
    bytes_received: int = 0
    first_response_ms: Optional[float] = None
    elapsed_ms: float = 0.0
    response_head: bytes = b""
    error: Optional[str] = None


@dataclass
class SmugglingProbeRun:
    target: str
    host: str
    port: int
    ssl_used: bool
    nonce: str
    timeout_s: float
    variants: List[VariantResult] = field(default_factory=list)
    error: Optional[str] = None


def build_smuggled_request(host_header: str, nonce: str) -> bytes:
    """The request embedded inside the probe body. Path is unique per
    invocation so it is identifiable in server logs."""
    return (
        f"GET /tradecraft-smuggle-{nonce} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"\r\n"
    ).encode("latin-1")


def build_cl_te_request(host_header: str, nonce: str) -> bytes:
    """CL.TE shape: Content-Length covers the whole body; Transfer-Encoding
    chunked terminates early with '0\\r\\n\\r\\n', after which the embedded
    request sits. A back-end honoring TE parses that embedded request as a
    second request; a front-end honoring CL forwards it all as one."""
    smuggled = build_smuggled_request(host_header, nonce)
    body = b"0\r\n\r\n" + smuggled
    head = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: tradecraft-smuggling-probe\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode("latin-1")
    return head + body


def build_te_cl_request(host_header: str, nonce: str) -> bytes:
    """TE.CL shape: the embedded request is wrapped as a single chunk, so a
    TE-honoring hop consumes it whole. Content-Length covers only the chunk
    size line, so a CL-honoring back-end stops there and treats the
    embedded request (plus the trailing terminator) as a second request."""
    smuggled = build_smuggled_request(host_header, nonce)
    chunk_size_line = f"{len(smuggled):x}\r\n".encode("latin-1")
    chunked_body = chunk_size_line + smuggled + b"\r\n0\r\n\r\n"
    head = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: tradecraft-smuggling-probe\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(chunk_size_line)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode("latin-1")
    return head + chunked_body


def _request_head_preview(payload: bytes) -> str:
    """Header block of the payload only (everything before the first blank
    line), so evidence shows the framing without dumping the body."""
    idx = payload.find(b"\r\n\r\n")
    head = payload if idx < 0 else payload[: idx + 4]
    return head.decode("latin-1", errors="replace")


def _open_connection(host: str, port: int, ssl_probe: bool, timeout: float) -> socket.socket:
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    conn: socket.socket = raw_sock
    if ssl_probe:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(raw_sock, server_hostname=host)
    conn.connect((host, port))
    return conn


def _run_variant(
    variant: str,
    payload: bytes,
    host: str,
    port: int,
    ssl_probe: bool,
    timeout: float,
) -> VariantResult:
    """One connection, one request, bounded read. Never retries."""
    result = VariantResult(
        variant=variant,
        status="ok",
        connected=False,
        request_head=_request_head_preview(payload),
    )
    t0 = time.monotonic()
    deadline = t0 + timeout
    conn: Optional[socket.socket] = None
    buf = bytearray()

    try:
        conn = _open_connection(host, port, ssl_probe, timeout)
        result.connected = True
        conn.sendall(payload)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            conn.settimeout(remaining)
            chunk = conn.recv(8192)
            if not chunk:
                break  # peer closed
            if result.first_response_ms is None:
                result.first_response_ms = round((time.monotonic() - t0) * 1000.0, 2)
            buf.extend(chunk)
            if len(buf) >= _MAX_RESPONSE_BYTES:
                buf = buf[:_MAX_RESPONSE_BYTES]
                break
            codes = _count_status_codes(bytes(buf))
            if len(codes) >= _MAX_COUNTED_RESPONSES:
                break

    except ConnectionRefusedError as exc:
        result.status = "refused"
        result.error = f"Connection refused: {exc}"
    except ConnectionResetError as exc:
        result.status = "reset"
        result.error = f"Connection reset by peer: {exc}"
    except (socket.timeout, TimeoutError) as exc:
        # A timeout after some bytes arrived is a normal end-of-read, not an error.
        if not buf:
            result.status = "timeout"
            result.error = f"Connection or read timed out after {timeout:.1f}s."
    except ssl.SSLError as exc:
        result.status = "ssl_error"
        result.error = f"SSL/TLS handshake failed: {exc}"
    except socket.gaierror as exc:
        result.status = "dns_error"
        result.error = f"DNS resolution failure for host '{host}': {exc}"
    except Exception as exc:  # noqa: BLE001 - recorded as evidence, not raised
        result.status = "error"
        result.error = str(exc)
    finally:
        result.elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    result.bytes_received = len(buf)
    result.response_head = bytes(buf[:_EVIDENCE_HEAD_BYTES])
    # The verdict basis: boundary-aware, not a blind scan (see
    # `_count_confirmed_responses`'s docstring for why that distinction
    # matters here specifically).
    result.status_codes = _count_confirmed_responses(bytes(buf))
    result.responses_seen = len(result.status_codes)
    return result


_STATUS_LINE_RE = re.compile(rb"HTTP/1\.[01] (\d{3}) ")
_CONTENT_LENGTH_RE = re.compile(rb"(?im)^content-length:[ \t]*(\d+)[ \t]*\r?$")
_TRANSFER_ENCODING_CHUNKED_RE = re.compile(rb"(?im)^transfer-encoding:[ \t]*chunked[ \t]*\r?$")
_BODYLESS_STATUS_CODES = (204, 304)


def _count_status_codes(data: bytes) -> List[int]:
    """Cheap, position-blind scan: every status-line-shaped match in `data`,
    excluding 1xx interim responses. Used only as an early-exit heuristic
    for the read loop below (stop once "probably enough" has arrived) --
    NOT as the basis for a verdict. A verbose error/WAF-block body that
    happens to echo an 'HTTP/1.x NNN ' substring will over-count here, but
    that only makes the loop stop a little earlier; the actual verdict is
    decided by `_count_confirmed_responses`, which checks real boundaries."""
    codes: List[int] = []
    for m in _STATUS_LINE_RE.finditer(data):
        code = int(m.group(1))
        if code >= 200:
            codes.append(code)
    return codes


def _chunked_body_end(data: bytes, start: int) -> Optional[int]:
    """Byte offset right after a chunked body's terminating `0\\r\\n\\r\\n`,
    starting the walk at `start` (the first byte after the response
    headers). Returns None if a chunk-size line or a chunk's declared data
    isn't fully present yet -- i.e. "don't know" rather than a guess.
    Trailers after the terminating chunk are not parsed; the offset
    returned is right after that chunk's own terminating CRLF, and a
    second response found before any trailer would still be an infra-level
    protocol violation worth flagging, so this is deliberately not treated
    as a reason to withhold confidence on the common, trailer-less case."""
    pos = start
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            return None  # chunk-size line not fully received yet
        size_token = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            return None  # malformed chunk size -- can't confirm a boundary
        chunk_data_start = line_end + 2
        if size == 0:
            terminator_end = chunk_data_start
            if data[terminator_end:terminator_end + 2] == b"\r\n":
                return terminator_end + 2
            return terminator_end  # zero-chunk itself is the body's real end
        chunk_data_end = chunk_data_start + size
        after_chunk = chunk_data_end + 2  # each chunk's data is followed by CRLF
        if after_chunk > len(data):
            return None  # this chunk's data hasn't fully arrived yet
        pos = after_chunk


def _first_response_end(data: bytes) -> Optional[int]:
    """Byte offset right after the first real (non-1xx) HTTP response in
    `data`, or None if that boundary can't yet be confirmed. Deliberately
    conservative: with no Content-Length, no chunked Transfer-Encoding, and
    a status code that isn't one of the bodyless ones, there is no way to
    tell where this response's connection-close-delimited body would end
    short of the connection actually closing -- so this returns None rather
    than guess, and a status-line-shaped match found later in such a buffer
    is not trusted as a confirmed second response. This is what prevents a
    verbose error page or WAF block page that echoes an 'HTTP/1.x NNN '
    substring in its own body from being misread as a second response."""
    first = None
    for m in _STATUS_LINE_RE.finditer(data):
        if int(m.group(1)) >= 200:
            first = m
            break
    if first is None:
        return None

    headers_end = data.find(b"\r\n\r\n", first.start())
    if headers_end < 0:
        return None  # headers for the first response aren't fully in yet

    headers_text = data[first.start():headers_end]
    body_start = headers_end + 4
    status_code = int(first.group(1))

    if status_code in _BODYLESS_STATUS_CODES:
        return body_start

    if _TRANSFER_ENCODING_CHUNKED_RE.search(headers_text):
        return _chunked_body_end(data, body_start)

    cl_match = _CONTENT_LENGTH_RE.search(headers_text)
    if cl_match:
        body_end = body_start + int(cl_match.group(1))
        if body_end > len(data):
            return None  # declared body hasn't fully arrived yet
        return body_end

    return None  # no length information at all -- can't confirm a boundary


def _count_confirmed_responses(data: bytes) -> List[int]:
    """Status codes of every HTTP response in `data` that is provably a
    real, separate response rather than a status-line-shaped substring
    inside the first response's own body: the first non-1xx response is
    always counted, and anything after it only counts if it starts at or
    after that first response's own confirmed end offset. If the boundary
    can't be confirmed (see `_first_response_end`), only the first response
    is returned -- under-counting on genuinely ambiguous data, by design,
    rather than risk a false positive."""
    first = None
    for m in _STATUS_LINE_RE.finditer(data):
        if int(m.group(1)) >= 200:
            first = m
            break
    if first is None:
        return []

    codes = [int(first.group(1))]
    boundary = _first_response_end(data)
    if boundary is None:
        return codes

    for m in _STATUS_LINE_RE.finditer(data, boundary):
        code = int(m.group(1))
        if code >= 200:
            codes.append(code)
    return codes


def execute(
    target: str,
    port: int = 443,
    ssl_probe: bool = True,
    timeout: int = 5,
) -> SmugglingProbeRun:
    """Runs the CL.TE probe and then the TE.CL probe, each on its own
    connection, strictly in sequence."""
    host = normalize_host(target)
    nonce = secrets.token_hex(6)

    if not host:
        return SmugglingProbeRun(
            target=target, host=host, port=0, ssl_used=ssl_probe, nonce=nonce,
            timeout_s=0.0, error=f"Invalid target: '{target}'",
        )

    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return SmugglingProbeRun(
            target=target, host=host, port=0, ssl_used=ssl_probe, nonce=nonce,
            timeout_s=0.0, error=f"Invalid port: '{port}' (must be 1-65535)",
        )

    effective_timeout = max(1.0, min(float(timeout), 10.0))

    default_port = 443 if ssl_probe else 80
    host_header = host if port_num == default_port else f"{host}:{port_num}"

    run = SmugglingProbeRun(
        target=target,
        host=host,
        port=port_num,
        ssl_used=ssl_probe,
        nonce=nonce,
        timeout_s=effective_timeout,
    )

    plan: List[Tuple[str, bytes]] = [
        (VARIANT_CL_TE, build_cl_te_request(host_header, nonce)),
        (VARIANT_TE_CL, build_te_cl_request(host_header, nonce)),
    ]
    for variant, payload in plan:
        run.variants.append(
            _run_variant(variant, payload, host, port_num, ssl_probe, effective_timeout)
        )
    return run
