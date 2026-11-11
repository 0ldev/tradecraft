from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from tradecraft.cli import main as cli_main
from tradecraft.execution.loop import run_engagement
from tradecraft.execution.run_dir import (
    create_initial_manifest,
    create_run_dir,
    finalize_manifest,
    save_facts_json,
)
from tradecraft.memory.cross_engagement import (
    CrossEngagementMemory,
    compute_local_vector,
    cosine_similarity,
    extract_root_domain,
)
from tradecraft.memory.facts import FactStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.memory_tools import RecallMemory


def test_extract_root_domain_handles_standard_and_compound_tlds():
    assert extract_root_domain("https://api.example.com.br:8443/v1") == "example.com.br"
    assert extract_root_domain("staging.portal.example.co.uk") == "example.co.uk"
    assert extract_root_domain("sub.deep.example.com") == "example.com"
    assert extract_root_domain("192.168.15.27:8080") == "192.168.15.27"
    assert extract_root_domain("example.org") == "example.org"


def test_local_vector_similarity_matches_related_security_terms():
    v1 = compute_local_vector("WordPress Elementor XML-RPC WAF bypass Cloudflare")
    v2 = compute_local_vector("Elementor WordPress xmlrpc bypass on Cloudflare")
    v3 = compute_local_vector("Active Directory Kerberoasting SPN ticket cracking")
    sim_related = cosine_similarity(v1, v2)
    sim_unrelated = cosine_similarity(v1, v3)
    assert sim_related > 0.55
    assert sim_related > sim_unrelated * 3


def test_index_live_run_and_hybrid_search_excludes_retracted_findings(tmp_path):
    store = CrossEngagementMemory(db_path=tmp_path / "memory.db")

    mem1 = EngagementMemory()
    mem1.finding(
        "Spring Boot Actuator /actuator/env exposed credentials behind Cloudflare WAF",
        evidence_id="actuator_probe:api.alpha.com",
    )
    fid_bad = mem1.finding(
        "False positive SQLi on /login",
        evidence_id="sqlmap:api.alpha.com",
    )
    mem1.retract(fid_bad, "Confirmed static error page")
    mem1.note("Target uses custom X-Forwarded-Host header normalization on port 8443")

    facts1 = FactStore()
    facts1.merge_port("api.alpha.com", 443, {"service": "https", "tech": "Spring Boot", "waf": "Cloudflare"})

    inserted = store.index_live_run(
        run_id="20261108T100000Z_111111",
        target="api.alpha.com",
        memory=mem1,
        facts=facts1,
    )
    assert inserted == 3  # 1 active finding + 1 substantive note + 1 port fact (retracted finding excluded)

    # Idempotency check: re-indexing identical run inserts 0 duplicates
    assert store.index_live_run(
        run_id="20261108T100000Z_111111",
        target="api.alpha.com",
        memory=mem1,
        facts=facts1,
    ) == 0

    # Search for Spring Actuator
    results = store.search("Spring Boot Actuator env credentials")
    assert len(results) >= 1
    assert results[0].kind == "finding"
    assert "Actuator" in results[0].text
    assert results[0].evidence_id == "actuator_probe:api.alpha.com"

    # Retracted finding must never appear in search results
    sqli_results = store.search("False positive SQLi")
    assert all("False positive SQLi" not in r.text for r in sqli_results)


def test_neural_embedding_fusion_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_EMBEDDING_MODEL", "openai/text-embedding-3-small")

    fake_embeddings = {
        "keycloak": [0.9, 0.1, 0.0, 0.0],
        "sso": [0.88, 0.12, 0.0, 0.0],
        "redis": [0.0, 0.0, 0.95, 0.05],
    }

    def _mock_litellm_embedding(**kwargs):
        inp = (kwargs.get("input") or [""])[0].lower()
        if "keycloak" in inp or "oidc" in inp:
            vec = fake_embeddings["keycloak"]
        elif "single sign-on" in inp:
            vec = fake_embeddings["sso"]
        else:
            vec = fake_embeddings["redis"]
        return SimpleNamespace(data=[{"embedding": vec}])

    monkeypatch.setattr("tradecraft.memory.cross_engagement.litellm.embedding", _mock_litellm_embedding)

    store = CrossEngagementMemory(db_path=tmp_path / "memory_neural.db")
    store.add_entry(
        run_id="run_1",
        target="auth.corp.com",
        kind="finding",
        text="Keycloak OIDC redirect_uri validation bypass via open redirect",
    )
    store.add_entry(
        run_id="run_2",
        target="cache.corp.com",
        kind="finding",
        text="Unauthenticated Redis datastore on port 6379",
    )

    stats = store.stats()
    assert stats["neural_embedded_entries"] == 2

    # Query using phrasing ("single sign-on") that shares zero exact words with "Keycloak OIDC"
    results = store.search("single sign-on")
    assert len(results) >= 1
    assert results[0].target == "auth.corp.com"
    assert "Keycloak" in results[0].text


def test_recall_memory_tool_filters_and_excludes_current_run(tmp_path):
    store = CrossEngagementMemory(db_path=tmp_path / "memory.db")
    store.add_entry(
        run_id="run_old",
        target="shop.example.com.br",
        kind="finding",
        text="WordPress xmlrpc.php enabled allowing multicall amplification",
        evidence_id="wpscan:shop.example.com.br",
    )
    store.add_entry(
        run_id="run_current",
        target="blog.example.com.br",
        kind="finding",
        text="WordPress current run finding that should be excluded",
    )

    tool = RecallMemory(store=store, current_run_id="run_current")
    res = tool.run(query="WordPress xmlrpc", target="example.com.br", kind="finding", limit=5)
    assert res["match_count"] == 1
    assert res["matches"][0]["run_id"] == "run_old"
    assert "xmlrpc.php" in res["matches"][0]["text"]

    bad_kind = tool.run(query="WordPress", kind="invalid_kind")
    assert "error" in bad_kind


def test_turn_zero_root_domain_seeding_and_auto_indexing_in_loop(tmp_path):
    # Run 1 on api.example.com.br logs a finding and finishes
    _, run_dir_1 = create_run_dir("api.example.com.br", run_id="run_001", tradecraft_home=tmp_path)

    store = CrossEngagementMemory(tradecraft_home=tmp_path)
    store.add_entry(
        run_id="run_000",
        target="portal.example.com.br",
        kind="finding",
        text="Exposed .env file at /api/.env containing staging DB credentials",
        evidence_id="sensitive_file_probe:portal.example.com.br",
    )

    mock_choice = mock.MagicMock()
    mock_choice.message.content = "Final report for api.example.com.br"
    mock_choice.message.tool_calls = None
    mock_choice.finish_reason = "stop"
    mock_response = mock.MagicMock()
    mock_response.choices = [mock_choice]

    with mock.patch("tradecraft.execution.loop._complete_with_retry", return_value=mock_response) as mock_complete:
        run_engagement(
            target="api.example.com.br",
            model="test-model",
            run_dir=run_dir_1,
            run_id="run_001",
            max_turns=1,
        )

    # Verify Turn-0 system prompt automatically received sibling subdomain memory for example.com.br
    sent_messages = mock_complete.call_args.kwargs["messages"]
    sys_prompt = sent_messages[0]["content"]
    assert "Cross-engagement memory for root domain 'example.com.br'" in sys_prompt
    assert "portal.example.com.br" in sys_prompt
    assert "Exposed .env file at /api/.env" in sys_prompt


def test_cli_memory_commands_index_search_stats_clear(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TRADECRAFT_HOME", str(tmp_path))
    rid, rdir = create_run_dir("app.example.com", run_id="20261109T120000Z_abc123", tradecraft_home=tmp_path)
    create_initial_manifest(rdir, rid, "app.example.com", model="test-model")
    facts = FactStore()
    facts.merge_port("app.example.com", 443, {"service": "https", "cms": "CraftCMS"})
    save_facts_json(rdir, facts)
    (rdir / "log.txt").write_text(
        "FINDING #1 [evidence: craftcms_transform_rce_probe:app.example.com]: CraftCMS image transform RCE confirmed\n",
        encoding="utf-8",
    )
    finalize_manifest(rdir, turns_used=3, findings_count=1)

    # 1. Backfill index via CLI
    cli_main(["memory", "index"])
    out_index = capsys.readouterr().out
    assert "indexed 1 run(s)" in out_index

    # 2. Stats via CLI (--json)
    cli_main(["memory", "stats", "--json"])
    stats_data = json.loads(capsys.readouterr().out)
    assert stats_data["total_entries"] == 2
    assert stats_data["indexed_runs"] == 1
    assert stats_data["by_kind"]["finding"] == 1
    assert stats_data["by_kind"]["fact"] == 1

    # 3. Search via CLI (--json)
    cli_main(["memory", "search", "CraftCMS RCE", "--json"])
    search_data = json.loads(capsys.readouterr().out)
    assert len(search_data) >= 1
    assert search_data[0]["kind"] == "finding"
    assert "CraftCMS image transform RCE" in search_data[0]["text"]

    # 4. Clear via CLI
    cli_main(["memory", "clear", "--target", "example.com"])
    out_clear = capsys.readouterr().out
    assert "removed 2 memory entries" in out_clear
