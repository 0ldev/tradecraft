from __future__ import annotations

from types import SimpleNamespace

from tradecraft.adapters.hydra import execute as hydra_execute
from tradecraft.adapters.kerbrute_spray import execute as spray_execute
from tradecraft.policy.credential_budget import TOTAL_BUDGET_PER_ENDPOINT, CredentialLedger
from tradecraft.tools.hydra import Hydra
from tradecraft.tools.kerbrute_spray import KerbruteSpray

EP = ("example.test", 443, "https-post-form", "/admin/login")


def test_request_under_budget_is_not_capped():
    ledger = CredentialLedger()
    assert ledger.allow(EP, 3) == (3, False)


def test_request_over_budget_is_clamped_to_remaining():
    ledger = CredentialLedger()
    assert ledger.allow(EP, 50) == (TOTAL_BUDGET_PER_ENDPOINT, True)


def test_budget_is_total_across_calls_not_just_the_first():
    ledger = CredentialLedger()
    ledger.record(EP, TOTAL_BUDGET_PER_ENDPOINT)
    assert ledger.allow(EP, 50) == (0, True)


def test_budget_tracks_partial_spend_across_calls():
    ledger = CredentialLedger()
    ledger.record(EP, 2)
    assert ledger.allow(EP, 50) == (TOTAL_BUDGET_PER_ENDPOINT - 2, True)
    assert ledger.allow(EP, 2) == (2, False)


def test_zero_attempts_do_not_consume_budget():
    ledger = CredentialLedger()
    ledger.record(EP, 0)
    assert ledger.allow(EP, 50) == (TOTAL_BUDGET_PER_ENDPOINT, True)


def test_endpoints_are_tracked_separately():
    ledger = CredentialLedger()
    ledger.record(EP, 5)
    other = ("example.test", 443, "https-post-form", "/other/login")
    assert ledger.allow(other, 50) == (TOTAL_BUDGET_PER_ENDPOINT, True)


def _capture_hydra_execute(monkeypatch, calls):
    def fake(**kwargs):
        calls.append(kwargs["max_attempts"])
        return SimpleNamespace(
            error=None, service="https-post-form", attempts_run=kwargs["max_attempts"],
            returncode=0, stderr="", stdout="",
        )
    monkeypatch.setattr(hydra_execute, "execute", fake)


def test_hydra_draws_down_a_shared_total_budget_across_calls(monkeypatch):
    calls: list[int] = []
    _capture_hydra_execute(monkeypatch, calls)
    tool = Hydra(CredentialLedger())
    params = {"target": "https://example.test", "service": "https-post-form",
              "form_details": "/admin/login:user=^USER^&pass=^PASS^:F=Invalid",
              "max_attempts": 50}

    first = tool.run(**params)
    second = tool.run(**params)

    assert calls == [TOTAL_BUDGET_PER_ENDPOINT, 0]
    assert first["budget"]["capped_by_budget"] is True
    assert first["budget"]["requested"] == 50
    assert first["budget"]["ran"] == TOTAL_BUDGET_PER_ENDPOINT
    assert first["budget"]["remaining_after_this_call"] == 0
    assert second["budget"]["capped_by_budget"] is True
    assert second["budget"]["ran"] == 0


def test_hydra_default_instances_do_not_share_state(monkeypatch):
    calls: list[int] = []
    _capture_hydra_execute(monkeypatch, calls)
    params = {"target": "https://example.test", "service": "https-post-form",
              "form_details": "/admin/login:user=^USER^&pass=^PASS^:F=Invalid",
              "max_attempts": 50}
    Hydra().run(**params)
    Hydra().run(**params)
    assert calls == [TOTAL_BUDGET_PER_ENDPOINT, TOTAL_BUDGET_PER_ENDPOINT]


def _capture_spray_execute(monkeypatch, calls):
    def fake(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            stdout="", stderr="", returncode=0, domain=kwargs["domain"],
            password=kwargs["password"], valid_credentials=[], attempts_run=1, error=None,
        )
    monkeypatch.setattr(spray_execute, "execute", fake)


def test_kerbrute_spray_consumes_one_unit_per_call_regardless_of_wordlist_size(monkeypatch):
    calls: list[dict] = []
    _capture_spray_execute(monkeypatch, calls)
    ledger = CredentialLedger(total_budget=2)
    tool = KerbruteSpray(ledger)

    first = tool.run(domain="corp.test", password="Summer2024!")
    second = tool.run(domain="corp.test", password="Winter2024!")
    third = tool.run(domain="corp.test", password="Autumn2024!")

    assert len(calls) == 2  # the third call never reached the adapter
    assert first["budget"]["capped_by_budget"] is False
    assert second["budget"]["capped_by_budget"] is False
    assert second["budget"]["remaining_after_this_call"] == 0
    assert third["budget"]["capped_by_budget"] is True
    assert "error" in third
    assert third["valid_credentials"] == []


def test_kerbrute_spray_and_hydra_share_one_ledger_against_different_endpoints():
    ledger = CredentialLedger(total_budget=2)
    ledger.record("corp.test", 2)
    # A domain spend doesn't affect a differently-keyed hydra endpoint.
    assert ledger.allow(EP, 2) == (2, False)


def test_kerbrute_spray_rejected_call_does_not_consume_budget(monkeypatch):
    def fake(**kwargs):
        return SimpleNamespace(
            stdout="", stderr="", returncode=0, domain=kwargs["domain"],
            password="", valid_credentials=[], attempts_run=0, error="empty domain",
        )
    monkeypatch.setattr(spray_execute, "execute", fake)
    ledger = CredentialLedger(total_budget=1)
    tool = KerbruteSpray(ledger)

    tool.run(domain="corp.test", password="")
    assert ledger.remaining("corp.test") == 1


def test_loop_wires_hydra_and_kerbrute_spray_to_the_same_engagement_ledger(monkeypatch):
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(spray_execute, "find_binary", lambda: "/usr/bin/kerbrute")
    monkeypatch.setattr(Hydra, "is_available", lambda self: True)
    memory = EngagementMemory()
    tools = _build_tool_map(
        memory, tool_ids=["hydra", "kerbrute_spray"], allow_destructive=True
    )
    assert tools["hydra"]._ledger is tools["kerbrute_spray"]._ledger


def test_loop_defaults_credential_budget_when_not_given(monkeypatch):
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(Hydra, "is_available", lambda self: True)
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["hydra"], allow_destructive=True)
    assert tools["hydra"]._ledger.total_budget == TOTAL_BUDGET_PER_ENDPOINT


def test_loop_applies_operator_credential_budget(monkeypatch):
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(Hydra, "is_available", lambda self: True)
    memory = EngagementMemory()
    tools = _build_tool_map(
        memory, tool_ids=["hydra"], allow_destructive=True, credential_budget=20
    )
    assert tools["hydra"]._ledger.total_budget == 20
