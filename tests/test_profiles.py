"""
Unit and regression tests for engagement-shape profiles (Phase 4).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tradecraft.tools.profiles import _PROFILES_DIR, ProfileError, list_profiles, load_profile
from tradecraft.tools.registry import ALL_TOOLS


def test_every_profile_tool_id_exists_in_all_tools():
    """Catches a renamed/removed tool left stale in a profile file --
    the exact failure mode an explicit list (vs. a wildcard) is for."""
    registered = {t.tool_id for t in ALL_TOOLS}
    for profile_file in _PROFILES_DIR.glob("*.yaml"):
        name = profile_file.stem
        tool_ids = load_profile(name)
        assert len(tool_ids) > 0, f"{name}.yaml loaded an empty tool list"
        for tid in tool_ids:
            assert tid in registered, f"{name}.yaml lists unknown tool_id {tid!r}"


def test_full_profile_is_every_registered_tool():
    assert set(load_profile("full")) == {t.tool_id for t in ALL_TOOLS}


def test_unknown_profile_raises():
    with pytest.raises(ProfileError, match="no config/profiles/not_a_real_profile.yaml found"):
        load_profile("not_a_real_profile")


def test_list_profiles():
    profiles = list_profiles()
    assert "web" in profiles
    assert "ad-network" in profiles
    assert "kubernetes" in profiles
    assert "cloud" in profiles
    assert "full" in profiles


def test_empty_tool_ids_in_profile_raises(tmp_path, monkeypatch):
    dummy_yaml = tmp_path / "empty_profile.yaml"
    dummy_yaml.write_text("profile_id: empty\ntool_ids: []\n")
    monkeypatch.setattr("tradecraft.tools.profiles._PROFILES_DIR", tmp_path)

    with pytest.raises(ProfileError, match="declares no tool_ids"):
        load_profile("empty_profile")


def test_cli_profile_resolution():
    import argparse
    from tradecraft import cli

    # 1. Explicit --tools overrides --profile
    test_args = ["example.com", "--tools", "nmap_scan,subfinder", "--profile", "ad-network", "--no-persist"]
    with patch("tradecraft.cli.run_engagement") as mock_run:
        cli.main(test_args)
        assert mock_run.called
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["tool_ids"] == ["nmap_scan", "subfinder"]

    test_args_profile = ["example.com", "--profile", "ad-network", "--no-persist"]
    with patch("tradecraft.cli.run_engagement") as mock_run:
        cli.main(test_args_profile)
        assert mock_run.called
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["tool_ids"] == load_profile("ad-network")

    # 3. Default resolution loads 'web' profile
    test_args_default = ["example.com", "--no-persist"]
    with patch("tradecraft.cli.run_engagement") as mock_run:
        cli.main(test_args_default)
        assert mock_run.called
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["tool_ids"] == load_profile("web")


def test_loop_system_prompt_only_includes_actually_available_tools(monkeypatch):
    """Regression test: confirm system prompt's allowed_tools restriction
    only lists tools actually in tool_map, excluding any unavailable or
    destructive-blocked tools."""
    from tradecraft.execution.loop import run_engagement

    # Patch litellm complete to exit immediately
    mock_resp = MagicMock()
    mock_resp.choices = [
        MagicMock(
            message=MagicMock(
                content="Assessment finished.",
                tool_calls=[],
                reasoning_content=None,
            ),
            finish_reason="stop",
        )
    ]
    mock_resp.usage = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}

    captured_prompts: list[str] = []

    def mock_complete(*args, **kwargs):
        messages = kwargs.get("messages", [])
        if messages and messages[0].get("role") == "system":
            captured_prompts.append(messages[0]["content"])
        return mock_resp

    monkeypatch.setattr("tradecraft.execution.loop.litellm.completion", mock_complete)

    # Request both nmap_scan (available) and auth_bootstrap (destructive: true)
    # with allow_destructive=False. auth_bootstrap must be excluded from tool_map
    # and therefore excluded from the rendered prompt's allowed tools list!
    run_engagement(
        target="127.0.0.1",
        tool_ids=["nmap_scan", "auth_bootstrap"],
        allow_destructive=False,
        max_turns=1,
    )

    assert len(captured_prompts) > 0
    prompt = captured_prompts[0]

    assert "restricted by operator policy to:" in prompt
    restricted_tools_section = prompt.split("restricted by operator policy to:")[1].split(".")[0]
    assert "nmap_scan" in restricted_tools_section
    assert "auth_bootstrap" not in restricted_tools_section
