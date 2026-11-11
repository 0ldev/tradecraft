"""
Tests for the final review nudge mechanisms (tradecraft/execution/loop.py):
when the model voluntarily stops while FACTS still contains discovered
parameters without any injection tests recorded, or while the most
recent interactsh payload generated has no matching poll call,
Tradecraft nudges the model with one extra turn before allowing
finalization.
"""
from types import SimpleNamespace
from unittest.mock import patch

from tradecraft.execution.loop import (
    EngagementResult,
    _has_open_injection_thread,
    _has_open_interactsh_thread,
    run_engagement,
)
from tradecraft.memory.facts import FactStore


def _response(finish_reason: str = "stop", content: str | None = "Report", tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(finish_reason=finish_reason, message=message)
    return SimpleNamespace(choices=[choice], usage=None)


def test_has_open_injection_thread_unit_cases():
    # 1. Empty store -> False
    facts = FactStore()
    assert _has_open_injection_thread(facts) is False

    # 2. Record with no discovered parameters -> False
    facts.merge_port("example.com", 80, {"service": "http"})
    assert _has_open_injection_thread(facts) is False

    # 3. Record with arjun_params_discovered and no tested fields -> True
    facts.merge_port("example.com", 443, {"arjun_params_discovered": 3})
    assert _has_open_injection_thread(facts) is True

    # 4. Tested with sqli_tested -> False
    facts.merge_port("example.com", 443, {"sqli_tested": True})
    assert _has_open_injection_thread(facts) is False

    # 5. Record with params_discovered (e.g. from katana) -> True
    facts2 = FactStore()
    facts2.merge_port("target.com", 8080, {"params_discovered": 4})
    assert _has_open_injection_thread(facts2) is True

    # 6. Tested with xss_tested -> False
    facts2.merge_port("target.com", 8080, {"xss_tested": True})
    assert _has_open_injection_thread(facts2) is False

    # 7. Tested with cmdi_tested -> False
    facts3 = FactStore()
    facts3.merge_port("target.com", 8080, {"params_discovered": 1, "cmdi_tested": True})
    assert _has_open_injection_thread(facts3) is False

    # 8. Tested with sqli_injectable -> False
    facts4 = FactStore()
    facts4.merge_port("target.com", 8080, {"arjun_params_discovered": 2, "sqli_injectable": True})
    assert _has_open_injection_thread(facts4) is False

    # 9. Tested with open_redirect_tested -> False
    facts5 = FactStore()
    facts5.merge_port("target.com", 8080, {"params_discovered": 2, "open_redirect_tested": True})
    assert _has_open_injection_thread(facts5) is False

    # 10. Tested with ssrf_tested -> False
    facts6 = FactStore()
    facts6.merge_port("target.com", 8080, {"arjun_params_discovered": 3, "ssrf_tested": True})
    assert _has_open_injection_thread(facts6) is False


@patch("tradecraft.execution.loop._complete_with_retry")
def test_voluntary_stop_with_open_thread_gets_nudged_once_then_finalizes(mock_complete):
    """Facts pre-seeded with arjun_params_discovered and no tested fields.
    Mock two voluntary stops: first triggers the nudge, second finalizes."""
    resp1 = _response(content="I am done with the assessment.")
    resp2 = _response(content="Final report after checking open parameters.")
    mock_complete.side_effect = [resp1, resp2]

    seeded_facts = FactStore()
    seeded_facts.merge_port("example.com", 443, {"arjun_params_discovered": 5})

    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 2
    assert result.report == "Final report after checking open parameters."
    assert any("Before finalizing: FACTS shows" in msg.get("content", "") for msg in result.transcript)


@patch("tradecraft.execution.loop._complete_with_retry")
def test_voluntary_stop_with_no_open_thread_finalizes_immediately(mock_complete):
    """Empty facts -> first voluntary stop finalizes immediately without nudge."""
    resp = _response(content="Final report immediately.")
    mock_complete.side_effect = [resp]

    seeded_facts = FactStore()
    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 1
    assert result.report == "Final report immediately."
    assert not any("Before finalizing: FACTS shows" in msg.get("content", "") for msg in result.transcript)


@patch("tradecraft.execution.loop._complete_with_retry")
def test_nudge_never_fires_on_the_last_available_turn(mock_complete):
    """max_turns=1, facts show open thread, model stops voluntarily on turn 1.
    Must NOT nudge (turn budget exhausted) and must finalize directly."""
    resp = _response(content="Voluntary stop on turn 1.")
    mock_complete.side_effect = [resp]

    seeded_facts = FactStore()
    seeded_facts.merge_port("example.com", 443, {"arjun_params_discovered": 3})

    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=1)

    assert mock_complete.call_count == 1
    assert result.report == "Voluntary stop on turn 1."
    assert not any("Before finalizing: FACTS shows" in msg.get("content", "") for msg in result.transcript)


@patch("tradecraft.execution.loop._complete_with_retry")
def test_tool_calling_response_never_triggers_the_nudge(mock_complete):
    """A response with tool_calls must proceed to tool execution, not the nudge branch."""
    fake_tool_call = SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name="log_note", arguments='{"entry": "test note"}'),
    )
    resp1 = _response(content="", tool_calls=[fake_tool_call])
    resp2 = _response(content="I am done now.")
    resp3 = _response(content="Final report.")
    mock_complete.side_effect = [resp1, resp2, resp3]

    seeded_facts = FactStore()
    seeded_facts.merge_port("example.com", 443, {"arjun_params_discovered": 2})

    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=5)

    # Call 1: tool call
    # Call 2: voluntary stop -> nudge fires
    # Call 3: voluntary stop after nudge -> finalizes
    assert mock_complete.call_count == 3
    assert result.report == "Final report."


@patch("tradecraft.execution.loop._complete_with_retry")
def test_truncated_empty_response_bypasses_the_nudge_entirely(mock_complete):
    """An empty truncated response is an execution error, not a voluntary stop.
    It returns early with failure report without nudging."""
    truncated_resp = _response(finish_reason="length", content="", tool_calls=None)
    mock_complete.return_value = truncated_resp

    seeded_facts = FactStore()
    seeded_facts.merge_port("example.com", 443, {"arjun_params_discovered": 5})

    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 1
    assert "engagement ended early: the model's response was truncated" in result.report
    assert not any("Before finalizing: FACTS shows" in msg.get("content", "") for msg in result.transcript)


def _interactsh_tool_call(call_id: str, action: str):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name="interactsh", arguments=f'{{"action": "{action}"}}'),
    )


def test_has_open_interactsh_thread_unit_cases():
    # 1. No interactsh calls at all -> False
    assert _has_open_interactsh_thread([]) is False

    # 2. generate with no poll after it -> True
    convo = [{"role": "assistant", "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "interactsh", "arguments": '{"action": "generate"}'}},
    ]}]
    assert _has_open_interactsh_thread(convo) is True

    # 3. generate followed by poll -> False
    convo2 = convo + [{"role": "assistant", "tool_calls": [
        {"id": "2", "type": "function", "function": {"name": "interactsh", "arguments": '{"action": "poll"}'}},
    ]}]
    assert _has_open_interactsh_thread(convo2) is False

    # 4. generate, poll, then a second generate with no poll after it -> True
    convo3 = convo2 + [{"role": "assistant", "tool_calls": [
        {"id": "3", "type": "function", "function": {"name": "interactsh", "arguments": '{"action": "generate"}'}},
    ]}]
    assert _has_open_interactsh_thread(convo3) is True

    # 5. Unrelated tool calls don't interfere
    convo4 = [{"role": "assistant", "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "log_note", "arguments": '{"text": "x"}'}},
    ]}]
    assert _has_open_interactsh_thread(convo4) is False


@patch("tradecraft.tools.interactsh.run_interactsh")
@patch("tradecraft.execution.loop._complete_with_retry")
def test_voluntary_stop_with_open_interactsh_thread_gets_nudged_once_then_finalizes(
    mock_complete, mock_run_interactsh
):
    """A generate call with no following poll gets one nudge before finalization."""
    mock_run_interactsh.return_value = {
        "action": "generate",
        "active": True,
        "payload_domain": "abc123xyz.oast.me",
        "payload_url": "http://abc123xyz.oast.me",
    }
    resp1 = _response(content="", tool_calls=[_interactsh_tool_call("call_1", "generate")])
    resp2 = _response(content="I'm done.")
    resp3 = _response(content="Final report after checking interactsh.")
    mock_complete.side_effect = [resp1, resp2, resp3]

    result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 3
    assert result.report == "Final report after checking interactsh."
    assert any("most recent interactsh payload" in msg.get("content", "") for msg in result.transcript)


@patch("tradecraft.tools.interactsh.run_interactsh")
@patch("tradecraft.execution.loop._complete_with_retry")
def test_voluntary_stop_with_polled_interactsh_finalizes_immediately(
    mock_complete, mock_run_interactsh
):
    """A generate call followed by a poll call must not be nudged."""
    mock_run_interactsh.side_effect = [
        {
            "action": "generate",
            "active": True,
            "payload_domain": "abc123xyz.oast.me",
            "payload_url": "http://abc123xyz.oast.me",
        },
        {
            "action": "poll",
            "active": True,
            "payload_domain": "abc123xyz.oast.me",
            "total_interactions": 0,
            "interactions": [],
        },
    ]
    resp1 = _response(content="", tool_calls=[_interactsh_tool_call("call_1", "generate")])
    resp2 = _response(content="", tool_calls=[_interactsh_tool_call("call_2", "poll")])
    resp3 = _response(content="Final report, already polled.")
    mock_complete.side_effect = [resp1, resp2, resp3]

    result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 3
    assert result.report == "Final report, already polled."
    assert not any("most recent interactsh payload" in msg.get("content", "") for msg in result.transcript)
