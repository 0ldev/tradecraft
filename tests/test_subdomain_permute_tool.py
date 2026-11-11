from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.subdomain_permute import SubdomainPermute


def test_tool_identity_and_contract():
    tool = SubdomainPermute()
    assert tool.tool_id == "subdomain_permute"
    assert tool.spec.name == "subdomain_permute"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "subdomain_permute" for t in ALL_TOOLS)


def test_run_returns_candidates_without_network(monkeypatch):
    import requests

    def boom(*a, **k):
        raise AssertionError("subdomain_permute must not make network calls")

    monkeypatch.setattr(requests, "get", boom)
    monkeypatch.setattr(requests, "post", boom)
    out = SubdomainPermute().run(target="https://example.com/", seed_subdomains="api.example.com")
    assert out["target"] == "example.com"
    assert out["candidate_count"] == len(out["candidates"])
    assert "staging.example.com" in out["candidates"]


def test_run_error_is_reported():
    assert SubdomainPermute().run(target="") == {
        "target": "",
        "error": "target is required (an apex domain, e.g. 'example.com')",
    }


def test_extract_facts_is_empty():
    assert SubdomainPermute().extract_facts({"target": "example.com"}, {"candidates": []}) == []
