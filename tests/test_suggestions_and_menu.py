"""Tests for Phase 1: deterministic suggestions + dynamic tool menu."""
from tradecraft.execution.suggestions import render_suggestions, suggest_next_actions
from tradecraft.execution.tool_menu import (
    ALWAYS_ON_TOOLS,
    LoadTool,
    build_tool_menu,
    dynamic_menu_enabled,
    schemas_for,
)


def _records():
    return [
        (
            ("10.0.0.5", 80),
            {
                "http_title": "Login",
                "arjun_params_discovered": "redirect,next",
                # no injection-class tested field -> rule 1
            },
        ),
        (
            ("10.0.0.5", 8080),
            {"http_title": "Admin"},  # http service, never discovered -> rule 2
        ),
        (
            ("10.0.0.5", 22),
            {"banner": "OpenSSH"},  # not http -> no suggestion
        ),
        (
            ("app.local", 443),
            {
                "http_title": "App",
                "params_discovered": "url",
                "ssrf_tested": True,  # followed through -> no suggestion
            },
        ),
    ]


def test_suggestions_rule1_open_injection_thread():
    actions = suggest_next_actions(_records())
    hits = [(a["tool_id"], a["target"]) for a in actions]
    assert ("ghauri", "10.0.0.5:80") in hits


def test_suggestions_rule2_undiscovered_http():
    actions = suggest_next_actions(_records())
    hits = [(a["tool_id"], a["target"]) for a in actions]
    assert ("arjun", "10.0.0.5:8080") in hits


def test_suggestions_skip_followed_through_and_non_http():
    actions = suggest_next_actions(_records())
    targets = [a["target"] for a in actions]
    assert "app.local:443" not in targets
    assert "10.0.0.5:22" not in targets


def test_suggestions_empty_state_explicit():
    text = render_suggestions([])
    assert "none" in text


def test_suggestions_render_contains_reason():
    text = render_suggestions(suggest_next_actions(_records()))
    assert "ghauri" in text and "10.0.0.5:80" in text


def _tiny_tool(name, description="Pings a target host for liveness."):
    from types import SimpleNamespace
    tool = SimpleNamespace()
    tool.tool_id = name
    tool.spec = SimpleNamespace(
        name=name, description=description, parameters={"type": "object", "properties": {}}
    )
    return tool


def test_dynamic_menu_threshold():
    assert dynamic_menu_enabled(200) is True
    assert dynamic_menu_enabled(10) is False
    import os
    os.environ["TRADECRAFT_DYNAMIC_MENU"] = "0"
    try:
        assert dynamic_menu_enabled(200) is False
    finally:
        del os.environ["TRADECRAFT_DYNAMIC_MENU"]


def test_build_tool_menu_first_sentence_only():
    tool = _tiny_tool("ping_host", "Pings a target host. Long explanation follows. More text.")
    menu = build_tool_menu({"ping_host": tool})
    assert menu == "- ping_host: Pings a target host."


def test_load_tool_activates_and_returns_schema():
    ping = _tiny_tool("ping_host")
    loadder = _tiny_tool("nmap_scan", "Runs an nmap port scan against a target.")
    tool_map = {"ping_host": ping, "nmap_scan": loadder}
    active: set = set()
    lt = LoadTool(tool_map, active)
    result = lt.run(tool_name="nmap_scan")
    assert result["loaded"] == "nmap_scan"
    assert "schema" in result
    assert active == {"nmap_scan"}


def test_load_tool_unknown_is_error_not_crash():
    tool_map = {"ping_host": _tiny_tool("ping_host")}
    lt = LoadTool(tool_map, set())
    result = lt.run(tool_name="nope")
    assert "error" in result
    assert "ping_host" in result["error"]


def test_schemas_for_active_plus_always_on():
    ping = _tiny_tool("ping_host")
    note = _tiny_tool("log_note")
    scan = _tiny_tool("nmap_scan")
    tool_map = {"ping_host": ping, "log_note": note, "nmap_scan": scan}
    # Nothing activated: only always-on tools present in the map.
    schemas = schemas_for(tool_map, set())
    names = {s["function"]["name"] for s in schemas}
    assert names == {"log_note"}
    # After activation:
    schemas = schemas_for(tool_map, {"nmap_scan", "ghost"})
    names = {s["function"]["name"] for s in schemas}
    assert names == {"log_note", "nmap_scan"}
    # Always-on set itself is never accidentally polluted by activation:
    assert "nmap_scan" not in ALWAYS_ON_TOOLS
