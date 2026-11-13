"""
Regression tests for the truncation-retry fix: a reasoning model can
spend its whole max_tokens budget on hidden reasoning and come back with
finish_reason="length", empty content, and no tool_calls -- that must
never be read as "the model decided it's done."
"""
from types import SimpleNamespace
from unittest.mock import patch

from litellm.exceptions import InternalServerError

from tradecraft.execution.loop import (
    MAX_TRUNCATION_RETRIES,
    _complete_with_retry,
    _has_truncated_tool_calls,
    _is_tool_call_truncation_error,
    _is_truncated_empty,
    _is_truncated_response,
)
from tradecraft.execution.trace import EngagementTrace


def _response(finish_reason: str, content: str | None, tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(finish_reason=finish_reason, message=message)
    return SimpleNamespace(choices=[choice], usage=None)


def _call_with_retry(**overrides):
    kwargs = dict(
        model="m", base_url=None, api_key=None, messages=[], timeout=10, max_tokens=100,
        trace=EngagementTrace(), turn=1, call_kind="turn",
    )
    kwargs.update(overrides)
    return _complete_with_retry(**kwargs)


def test_truncated_empty_response_is_detected():
    assert _is_truncated_empty(_response("length", None, None)) is True
    assert _is_truncated_empty(_response("length", "", None)) is True
    assert _is_truncated_empty(_response("length", "   ", None)) is True


def test_truncated_with_content_is_not_flagged():
    assert _is_truncated_empty(_response("length", "partial but real text", None)) is False


def test_length_finish_with_tool_calls_is_not_flagged():
    fake_call = SimpleNamespace(id="c1", function=SimpleNamespace(name="nmap_scan", arguments="{}"))
    assert _is_truncated_empty(_response("length", None, [fake_call])) is False


def test_normal_stop_is_not_flagged():
    assert _is_truncated_empty(_response("stop", "all done", None)) is False


def test_retries_with_larger_budget_until_success():
    truncated = _response("length", None, None)
    success = _response("stop", "final answer", None)

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, truncated, success]) as mock_completion:
        result = _call_with_retry()

    assert result is success
    assert mock_completion.call_count == 3
    token_budgets = [call.kwargs["max_tokens"] for call in mock_completion.call_args_list]
    assert token_budgets == [100, 200, 400]  # doubles each retry


def test_gives_up_after_max_retries_and_returns_last_truncated_response():
    truncated = _response("length", None, None)

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated] * (MAX_TRUNCATION_RETRIES + 1)) as mock_completion:
        result = _call_with_retry()

    assert result is truncated
    assert mock_completion.call_count == MAX_TRUNCATION_RETRIES + 1


def test_succeeds_immediately_without_retrying():
    success = _response("stop", "done", None)
    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[success]) as mock_completion:
        result = _call_with_retry()
    assert result is success
    assert mock_completion.call_count == 1


def test_emits_an_event_per_retry():
    truncated = _response("length", None, None)
    success = _response("stop", "done", None)
    events = []

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, success]):
        _call_with_retry(emit=lambda kind, payload: events.append((kind, payload)))

    assert len(events) == 1
    assert events[0][0] == "truncation_retry"


def test_trace_records_one_call_per_attempt():
    truncated = _response("length", None, None)
    success = _response("stop", "done", None)
    trace = EngagementTrace()

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, success]):
        _call_with_retry(trace=trace)

    assert len(trace.calls) == 2
    assert trace.calls[0].truncation_attempt == 0
    assert trace.calls[1].truncation_attempt == 1


def test_truncated_tool_call_arguments_are_detected():
    bad_call = SimpleNamespace(id="c1", function=SimpleNamespace(name="http_request", arguments='{"url": "http://target.local/api'))
    good_call = SimpleNamespace(id="c2", function=SimpleNamespace(name="http_request", arguments='{"url": "http://target.local/api"}'))

    assert _has_truncated_tool_calls(_response("length", None, [bad_call])) is True
    assert _is_truncated_response(_response("length", None, [bad_call])) is True

    # Valid arguments with length finish is not considered truncated arguments
    assert _has_truncated_tool_calls(_response("length", None, [good_call])) is False

    # Stop finish reason is never considered truncated even if malformed
    assert _has_truncated_tool_calls(_response("stop", None, [bad_call])) is False


def test_tool_call_truncation_error_detection():
    exc1 = InternalServerError("Failed to parse tool call arguments as JSON: [json.exception.parse_error.101]", "openai", "m")
    exc2 = InternalServerError("syntax error while parsing object key - unexpected end of input", "openai", "m")
    exc3 = InternalServerError("database server went away", "openai", "m")

    assert _is_tool_call_truncation_error(exc1) is True
    assert _is_tool_call_truncation_error(exc2) is True
    assert _is_tool_call_truncation_error(exc3) is False


def test_server_tool_call_parse_error_triggers_truncation_retry_with_doubled_budget():
    parse_err = InternalServerError("Failed to parse tool call arguments as JSON: [json.exception.parse_error.101]", "openai", "m")
    success = _response("stop", "recovered", None)
    events = []

    # Attempt 0 runs up to MAX_NETWORK_RETRIES+1 (3 calls), fails with parse_err,
    # then triggers truncation_retry with doubled tokens (200) on attempt 1.
    with patch("tradecraft.execution.loop.MAX_NETWORK_RETRIES", 2), \
         patch("tradecraft.execution.loop.litellm.completion", side_effect=[parse_err, parse_err, parse_err, success]) as mock_completion:
        result = _call_with_retry(emit=lambda k, p: events.append((k, p)))

    assert result is success
    assert mock_completion.call_count == 4
    token_budgets = [call.kwargs["max_tokens"] for call in mock_completion.call_args_list]
    assert token_budgets == [100, 100, 100, 200]
    assert any(k == "truncation_retry" for k, _ in events)


def test_truncated_tool_call_triggers_truncation_retry_with_doubled_budget():
    bad_call = SimpleNamespace(id="c1", function=SimpleNamespace(name="http_request", arguments='{"url": "incomplete'))
    good_call = SimpleNamespace(id="c1", function=SimpleNamespace(name="http_request", arguments='{"url": "http://target.local"}'))

    truncated = _response("length", None, [bad_call])
    success = _response("stop", None, [good_call])

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, success]) as mock_completion:
        result = _call_with_retry()

    assert result is success
    assert mock_completion.call_count == 2
    token_budgets = [call.kwargs["max_tokens"] for call in mock_completion.call_args_list]
    assert token_budgets == [100, 200]


def test_retry_appends_system_nudge_and_disables_thinking():
    import os
    from tradecraft.execution.loop import TRUNCATION_RETRY_SYSTEM_NUDGE

    truncated = _response("length", None, None)
    success = _response("stop", "done", None)

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, success]) as mock_completion:
        result = _call_with_retry(messages=[{"role": "user", "content": "original"}])

    assert result is success
    assert mock_completion.call_count == 2
    # Attempt 0: original messages, no extra_body
    attempt0_msgs = mock_completion.call_args_list[0].kwargs["messages"]
    assert len(attempt0_msgs) == 1
    assert attempt0_msgs[0]["content"] == "original"
    assert "extra_body" not in mock_completion.call_args_list[0].kwargs

    # Attempt 1: original messages + system nudge, thinking disabled
    attempt1_msgs = mock_completion.call_args_list[1].kwargs["messages"]
    assert len(attempt1_msgs) == 2
    assert attempt1_msgs[0]["content"] == "original"
    assert attempt1_msgs[1]["content"] == TRUNCATION_RETRY_SYSTEM_NUDGE
    assert mock_completion.call_args_list[1].kwargs["extra_body"]["chat_template_kwargs"]["enable_thinking"] is False


def test_reasoning_effort_propagation_and_downgrade_on_retry(monkeypatch):
    monkeypatch.setenv("LLM_REASONING_EFFORT", "medium")

    truncated = _response("length", None, None)
    success = _response("stop", "done", None)

    with patch("tradecraft.execution.loop.litellm.completion", side_effect=[truncated, success]) as mock_completion:
        result = _call_with_retry()

    assert result is success
    assert mock_completion.call_count == 2
    assert mock_completion.call_args_list[0].kwargs["reasoning_effort"] == "medium"
    assert mock_completion.call_args_list[1].kwargs["reasoning_effort"] == "low"

