"""
Regression tests for the second real-run failure: a request timeout
(or other transient network error) from litellm must be retried a
bounded number of times, and must never escape run_engagement as an
unhandled crash -- it has to come back as an honest EngagementResult,
same posture as the truncation-retry handling.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from litellm.exceptions import InternalServerError, Timeout as LiteLLMTimeout

from tradecraft.execution.loop import MAX_NETWORK_RETRIES, _complete_with_network_retry
from tradecraft.execution.trace import EngagementTrace


def _timeout_exc():
    return LiteLLMTimeout(message="Request timed out.", model="m", llm_provider="openai")


def _server_error_exc():
    # Real shape seen from the local llama.cpp server: a 500 because the
    # model's own generated tool-call JSON came out malformed/truncated.
    return InternalServerError(
        message="Failed to parse tool call arguments as JSON: unterminated string",
        model="m", llm_provider="openai",
    )


def _success_response():
    message = SimpleNamespace(content="done", tool_calls=None)
    choice = SimpleNamespace(finish_reason="stop", message=message)
    return SimpleNamespace(choices=[choice], usage=None)


def _call(**overrides):
    kwargs = dict(
        kwargs={"model": "m"}, trace=EngagementTrace(), turn=1, call_kind="turn", truncation_attempt=0,
    )
    kwargs.update(overrides)
    return _complete_with_network_retry(**kwargs)


def test_retries_on_timeout_until_success():
    success = _success_response()
    with patch("tradecraft.execution.loop.MAX_NETWORK_RETRIES", 2), \
         patch("tradecraft.execution.loop.litellm.completion", side_effect=[_timeout_exc(), _timeout_exc(), success]) as mock_completion:
        result = _call()

    assert result is success
    assert mock_completion.call_count == 3


def test_raises_after_exhausting_network_retries():
    with patch(
        "tradecraft.execution.loop.litellm.completion",
        side_effect=[_timeout_exc()] * (MAX_NETWORK_RETRIES + 1),
    ) as mock_completion:
        with pytest.raises(LiteLLMTimeout):
            _call()

    assert mock_completion.call_count == MAX_NETWORK_RETRIES + 1


def test_emits_an_event_per_network_retry():
    success = _success_response()
    events = []
    with patch("tradecraft.execution.loop.MAX_NETWORK_RETRIES", 2), \
         patch("tradecraft.execution.loop.litellm.completion", side_effect=[_timeout_exc(), success]):
        _call(emit=lambda kind, payload: events.append((kind, payload)))

    assert len(events) == 1
    assert events[0][0] == "network_retry"


def test_retries_on_server_side_malformed_tool_call_json():
    success = _success_response()
    with patch("tradecraft.execution.loop.MAX_NETWORK_RETRIES", 2), \
         patch("tradecraft.execution.loop.litellm.completion", side_effect=[_server_error_exc(), success]) as mock_completion:
        result = _call()
    assert result is success
    assert mock_completion.call_count == 2


def test_does_not_retry_on_non_network_errors():
    with patch("tradecraft.execution.loop.litellm.completion", side_effect=ValueError("not a network error")) as mock_completion:
        with pytest.raises(ValueError):
            _call()
    assert mock_completion.call_count == 1


def test_trace_records_failed_attempts_and_the_success():
    success = _success_response()
    trace = EngagementTrace()
    with patch("tradecraft.execution.loop.MAX_NETWORK_RETRIES", 2), \
         patch("tradecraft.execution.loop.litellm.completion", side_effect=[_timeout_exc(), success]):
        _call(trace=trace)

    assert len(trace.calls) == 2
    assert trace.calls[0].error is not None
    assert trace.calls[0].network_attempt == 0
    assert trace.calls[1].error is None
    assert trace.calls[1].network_attempt == 1
