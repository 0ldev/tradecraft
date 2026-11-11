import os
import stat
import tempfile
import pytest

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.tools.evidence_tools import ReadEvidence, SearchEvidence


def test_evidence_store_saves_and_reads_data(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    data = {"findings": [{"id": "heartbleed", "severity": "HIGH"}]}
    key = store.save("example.com", "testssl", data)
    assert key == "testssl:example.com"

    res = store.read("example.com", "testssl")
    assert res["target"] == "example.com"
    assert res["tool"] == "testssl"
    assert res["evidence"] == data


def test_evidence_store_read_missing_returns_error(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    res = store.read("nonexistent.com", "testssl")
    assert "error" in res


def test_evidence_store_last_write_wins(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("example.com", "testssl", {"v": 1})
    store.save("example.com", "testssl", {"v": 2})
    res = store.read("example.com", "testssl")
    assert res["evidence"] == {"v": 2}


def test_evidence_store_url_targets_sanitized_safely(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    data = {"endpoints": ["/admin", "/cpanel"]}
    
    # URL with https and trailing slash
    key = store.save("https://example.com/", "ffuf", data)
    assert key == "ffuf:https://example.com/"
    
    # Reading via bare domain works because both sanitize to example.com
    res = store.read("example.com", "ffuf")
    assert res["evidence"] == data

    # Reading via full URL also works
    res_url = store.read("https://example.com", "ffuf")
    assert res_url["evidence"] == data

    # Subpath target sanitizes cleanly
    store.save("https://example.com/admin", "httpx_probe", {"title": "Admin"})
    res_sub = store.read("https://example.com/admin", "httpx_probe")
    assert res_sub["evidence"]["title"] == "Admin"


def test_evidence_store_prevents_path_traversal(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    with pytest.raises(ValueError, match="traversal"):
        store.save("../../etc", "testssl", {"a": 1})

    res = store.read("../../../passwd", "testssl")
    assert "error" in res


def test_evidence_store_keys_lists_sorted_tool_target_entries(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("host_b", "httpx_probe", {"status": 200})
    store.save("host_a", "nmap_scan", {"ports": [80]})
    store.save("host_a", "dnsx", {"a": ["1.2.3.4"]})

    keys = store.keys()
    assert keys == ["dnsx:host_a", "httpx_probe:host_b", "nmap_scan:host_a"]

    search_res = store.search(query="root", target="../../../etc")
    assert "error" in search_res


def test_evidence_store_directory_and_file_permissions(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path / "sub")
    store.save("example.com", "testssl", {"key": "secret"})

    dir_stat = os.stat(store.base_dir)
    assert (dir_stat.st_mode & 0o777) == 0o700

    file_path = store.base_dir / "example.com" / "testssl.json"
    file_stat = os.stat(file_path)
    assert (file_stat.st_mode & 0o777) == 0o600


def test_evidence_store_search_literal_matching(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("host1.local", "testssl", {"ciphers": ["RC4-SHA", "AES128-SHA"]})
    store.save("host2.local", "httpx", {"headers": ["Server: Apache", "Set-Cookie: session=123"]})

    res = store.search(query="rc4")
    assert res["total_matches"] >= 1
    assert any("RC4" in m["match"] for m in res["matches"])

    res2 = store.search(query="Set-Cookie", target="host2.local")
    assert res2["total_matches"] >= 1
    assert res2["matches"][0]["target"] == "host2.local"

    res_empty = store.search(query="nonexistent_string_xyz")
    assert res_empty["total_matches"] == 0
    assert res_empty["matches"] == []


def test_evidence_store_search_caps_matches_and_line_length(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    long_line = "A" * 300
    store.save("host.local", "tool", {"lines": [f"match_{i}_{long_line}" for i in range(10)]})

    res = store.search(query="match_", max_matches=3, max_line_len=50)
    assert res["total_matches"] == 10
    assert len(res["matches"]) == 3
    assert res["omitted_matches"] == 7
    assert len(res["matches"][0]["match"]) <= 55  # 50 + "..."


def test_read_evidence_validates_tool_id(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    tool = ReadEvidence(store)

    # Valid tool from ALL_TOOLS
    res = tool.run(target="example.com", tool_id="testssl")
    assert "error" in res and "no evidence found" in res["error"]

    res_invalid = tool.run(target="example.com", tool_id="evil_script")
    assert "error" in res_invalid
    assert "unknown tool" in res_invalid["error"]


def test_search_evidence_runs_query(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("host.local", "httpx", {"banner": "Apache 2.4"})
    tool = SearchEvidence(store)

    res = tool.run(query="Apache")
    assert res["total_matches"] >= 1


def test_read_evidence_gau_bulk_safe_truncation(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    bulk_data = {
        "urls": [f"https://example.com/item{i}" for i in range(100)],
        "endpoints": [f"/item{i}" for i in range(100)],
        "parameters": ["id", "action", "search"],
        "subdomains": ["example.com"],
        "total_urls": 100,
    }
    store.save("example.com", "gau", bulk_data)
    res = store.read("example.com", "gau")
    assert res["total_urls"] == 100
    assert len(res["endpoints_sample"]) == 50
    assert res["parameters"] == ["id", "action", "search"]
    assert "truncated to protect conversational context" in res["warning"]


def test_evidence_store_save_binary_and_read_binary(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00"
    key = store.save_binary("https://example.com/login", "gowitness", binary_data, ext="png")
    assert key == "gowitness:https://example.com/login"

    # Reading binary evidence returns metadata rather than json decode error
    res = store.read("https://example.com/login", "gowitness")
    assert res["target"] == "https://example.com/login"
    assert res["tool"] == "gowitness"
    assert res["is_binary"] is True
    assert res["size_bytes"] == len(binary_data)
    assert "cannot be rendered as JSON" in res["note"]

    # Keys listing lists the binary entry
    assert "gowitness:example.com_login" in store.keys()


def test_evidence_store_subdomain_to_parent_fallback(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    bulk_httpx = {
        "target": "example.com,mail.example.com",
        "results": [
            {"host": "example.com", "port": 443, "status_code": 200, "title": "Apex"},
            {"host": "mail.example.com", "port": 443, "status_code": 302, "title": "Webmail"},
        ],
    }
    store.save("example.com", "httpx_probe", bulk_httpx)

    # Direct read on parent works
    res_apex = store.read("example.com", "httpx_probe")
    assert res_apex["evidence"] == bulk_httpx

    res_sub = store.read("mail.example.com", "httpx_probe")
    assert "error" not in res_sub
    assert res_sub["target"] == "mail.example.com"
    assert res_sub["parent_target"] == "example.com"
    assert res_sub["evidence"]["host"] == "mail.example.com"
    assert res_sub["evidence"]["status_code"] == 302
    assert "Found 1 matching item(s)" in res_sub["note"]


def test_evidence_store_subdomain_dnsx_fallback(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    dnsx_data = {
        "target": "example.com",
        "records": [
            {"host": "example.com", "a": ["1.1.1.1"]},
            {"host": "api.example.com", "a": ["2.2.2.2"]},
        ],
    }
    store.save("example.com", "dnsx", dnsx_data)

    res = store.read("api.example.com", "dnsx")
    assert "error" not in res
    assert res["target"] == "api.example.com"
    assert res["evidence"]["host"] == "api.example.com"
    assert res["evidence"]["a"] == ["2.2.2.2"]


def test_evidence_store_subdomain_subfinder_fallback(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    subfinder_data = {
        "target": "example.com",
        "subdomains": ["dev.example.com", "staging.example.com"],
    }
    store.save("example.com", "subfinder", subfinder_data)

    res = store.read("dev.example.com", "subfinder")
    assert "error" not in res
    assert res["target"] == "dev.example.com"
    assert res["found_in_subdomains"] is True


def test_evidence_store_url_with_port_fallback(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("api.example.com", "whatweb", {"tech": ["Nginx"]})

    res = store.read("https://api.example.com:8443/v1", "whatweb")
    assert "error" not in res
    assert res["evidence"]["tech"] == ["Nginx"]


def test_evidence_store_apex_reverse_lookup_notice(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("admin.example.com", "http_request", {"status": 200})

    res = store.read("example.com", "http_request")
    assert "error" in res
    assert "admin.example.com" in res.get("note", "")
    assert res.get("available_subdomains") == ["admin.example.com"]


def test_evidence_store_resolves_bare_host_to_single_path_qualified_sibling(tmp_path):
    """Regression for a real run: http_request fetching a specific path
    (e.g. a JS chunk) now saves evidence under 'host_path', not bare
    'host' (see evidence_target_from_url). A model that still asks for
    the bare host should transparently get that single match back rather
    than a dead-end 'no evidence found'."""
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("dashboard.example.app/_next/static/chunk1.js", "http_request", {"body": "chunk one"})

    res = store.read("dashboard.example.app", "http_request")
    assert "error" not in res
    assert res["resolved_target"] == "dashboard.example.app_next_static_chunk1.js"
    assert res["evidence"] == {"body": "chunk one"}


def test_evidence_store_lists_multiple_path_qualified_siblings(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("dashboard.example.app/chunk1.js", "http_request", {"body": "chunk one"})
    store.save("dashboard.example.app/chunk2.js", "http_request", {"body": "chunk two"})

    res = store.read("dashboard.example.app", "http_request")
    assert "error" in res
    assert len(res["available_paths"]) == 2


def test_evidence_store_search_context_window_centers_on_match(tmp_path):
    """Regression for a real run (example.com, 2026-11-04): json.dumps()
    escapes real newlines inside a string *value* to literal "\\n" rather
    than emitting them as actual line breaks, so a large field (e.g. an
    OpenAPI spec's raw_body) lands entirely on one on-disk line. The old
    head-clip (`line[:max_line_len]`) always returned the first
    max_line_len characters of that one giant line no matter where the
    query actually matched -- every search against such a file returned
    the same useless fragment. Centering the returned window on the
    match fixes this for any line length."""
    store = EvidenceStore(persist_dir=tmp_path)
    # Simulate a single on-disk line far longer than max_line_len, with
    # the real match deep past where a head-clip would ever reach.
    prefix = "x" * 5000
    needle = "example-x-api-key"
    suffix = "y" * 5000
    store.save("api.staging.example.com", "http_request", {"raw_body": f"{prefix}{needle}{suffix}"})

    res = store.search(query=needle, max_line_len=100)
    assert res["total_matches"] == 1
    match = res["matches"][0]["match"]
    assert needle in match
    assert match.startswith("...")
    assert match.endswith("...")
    assert len(match) <= 106  # 100 + up to two "..." markers


def test_evidence_store_search_context_window_short_line_unchanged(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("host.local", "tool", {"note": "short line with a match here"})
    res = store.search(query="match", max_line_len=200)
    # Line fits within max_line_len: returned verbatim, no "..." markers.
    match = res["matches"][0]["match"]
    assert "..." not in match
    assert "match here" in match


def test_evidence_store_batch_alias_resolves_to_filtered_record(tmp_path):
    """Regression for a real run (example.com, 2026-11-04): a single
    httpx_probe call batching 6 hosts
    ('wp.example.com,api.staging.example.com,webhooks.example.com,...') saved
    its full result under only the first host, 'wp.example.com', while
    FactStore attached that same evidence_id to every one of the other 5
    hosts' facts. Before this fix, read_evidence(target='webhooks.example.com',
    tool_id='httpx_probe') always reported "no evidence found" even
    though the real data existed -- just filed under a different host's
    directory. Fixture below is the real captured batch result."""
    store = EvidenceStore(persist_dir=tmp_path)
    real_batch_result = {
        "target": "wp.example.com,api.staging.example.com,webhooks.example.com,staging.example.com,go.example.com,api.example.com",
        "results": [
            {"host": "api.example.com", "port": "443", "url": "https://api.example.com", "status_code": 200, "webserver": "cloudflare"},
            {"host": "webhooks.example.com", "port": "443", "url": "https://webhooks.example.com", "status_code": 405, "webserver": "Kestrel"},
            {"host": "api.staging.example.com", "port": "443", "url": "https://api.staging.example.com", "status_code": 200, "webserver": None},
            {"host": "wp.example.com", "port": "443", "url": "https://wp.example.com", "status_code": 202, "webserver": "nginx"},
            {"host": "go.example.com", "port": "443", "url": "https://go.example.com", "status_code": 200, "webserver": "cloudflare"},
            {"host": "staging.example.com", "port": "443", "url": "https://staging.example.com", "status_code": 200, "webserver": "cloudflare"},
        ],
    }
    aliases = ["api.staging.example.com", "webhooks.example.com", "staging.example.com", "go.example.com", "api.example.com"]
    key = store.save("wp.example.com", "httpx_probe", real_batch_result, aliases=aliases)
    assert key == "httpx_probe:wp.example.com"

    # Canonical host: direct hit, unchanged behavior.
    direct = store.read("wp.example.com", "httpx_probe")
    assert direct["evidence"] == real_batch_result

    # A non-canonical batch member: must resolve via the alias stub and
    # come back scoped to that host's own record, not an error and not
    # the whole batch blob.
    res = store.read("webhooks.example.com", "httpx_probe")
    assert "error" not in res
    assert res["target"] == "webhooks.example.com"
    assert res["parent_target"] == "wp.example.com"
    assert res["evidence"]["status_code"] == 405
    assert res["evidence"]["webserver"] == "Kestrel"

    # Every other alias resolves to its own distinct record too.
    res2 = store.read("go.example.com", "httpx_probe")
    assert res2["evidence"]["status_code"] == 200
    assert res2["evidence"]["webserver"] == "cloudflare"
    assert res2["evidence"]["url"] == "https://go.example.com"


def test_evidence_store_alias_never_clobbers_existing_real_data(tmp_path):
    """A host probed solo earlier (real, direct evidence) must keep its
    own data even if a later batch call lists it as an alias -- an alias
    stub must never overwrite genuine evidence."""
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("api.example.com", "httpx_probe", {"host": "api.example.com", "solo": True})

    # A later batch keyed elsewhere lists api.example.com as an alias.
    store.save("wp.example.com", "httpx_probe", {"target": "batch"}, aliases=["api.example.com"])

    res = store.read("api.example.com", "httpx_probe")
    assert res["evidence"] == {"host": "api.example.com", "solo": True}


def test_evidence_store_alias_missing_canonical_data_reports_error(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("wp.example.com", "httpx_probe", {"target": "batch"}, aliases=["webhooks.example.com"])

    # Canonical data disappears (e.g. a run directory got pruned).
    (store.base_dir / "wp.example.com" / "httpx_probe.json").unlink()

    res = store.read("webhooks.example.com", "httpx_probe")
    assert "error" in res
    assert "webhooks.example.com" in res["error"]


def test_evidence_store_alias_resolves_path_qualified_http_request_batch(tmp_path):
    """http_request batch members are host+path (e.g.
    'a.example.com/v1/payments'), sanitized to underscores on disk
    ('a.example.com_v1_payments') while the stored `url` field keeps real
    slashes -- a plain substring check between the two never matches."""
    store = EvidenceStore(persist_dir=tmp_path)
    full_evidence = {
        "target": "https://a.example.com/v1/products,https://a.example.com/v1/payments",
        "results": [
            {"url": "https://a.example.com/v1/products", "status_code": 401},
            {"url": "https://a.example.com/v1/payments", "status_code": 404},
        ],
    }
    store.save("a.example.com/v1/products", "http_request", full_evidence, aliases=["a.example.com/v1/payments"])

    res = store.read("a.example.com/v1/payments", "http_request")
    assert "error" not in res
    assert res["evidence"]["status_code"] == 404
    assert res["evidence"]["url"] == "https://a.example.com/v1/payments"


def test_evidence_store_search_subdomain_and_parent_cross_lookup(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("example.com", "httpx_probe", {"target": "mail.example.com", "body": "webmail login"})
    store.save("portal.example.com", "whatweb", {"tech": "React"})

    # Search with subdomain target searches parent example.com
    res_sub = store.search(query="webmail", target="mail.example.com")
    assert res_sub["total_matches"] >= 1
    assert res_sub["matches"][0]["target"] == "example.com"

    # Search with apex target searches subdomains as well
    res_apex = store.search(query="React", target="example.com")
    assert res_apex["total_matches"] >= 1
    assert res_apex["matches"][0]["target"] == "portal.example.com"



