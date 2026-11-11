import json
from types import SimpleNamespace

import pytest

from tradecraft.execution.trace import EngagementTrace, redact_request


def _message(content=None, reasoning_content=None, tool_calls=None):
    return SimpleNamespace(content=content, reasoning_content=reasoning_content, tool_calls=tool_calls)


def _response(message, finish_reason="stop", usage=None):
    choice = SimpleNamespace(finish_reason=finish_reason, message=message)
    return SimpleNamespace(choices=[choice], usage=usage)


def _usage(prompt=10, completion=20, total=30):
    return SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion, total_tokens=total)


def test_redact_request_strips_api_key_only():
    kwargs = {"model": "m", "api_key": "secret", "messages": []}
    redacted = redact_request(kwargs)
    assert "api_key" not in redacted
    assert redacted["model"] == "m"
    assert redacted["messages"] == []


def test_successful_call_records_content_and_usage():
    trace = EngagementTrace()
    response = _response(_message(content="done"), usage=_usage())

    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={"model": "m"}) as handle:
        handle.set_response(response)

    assert len(trace.calls) == 1
    record = trace.calls[0]
    assert record.content == "done"
    assert record.error is None
    assert record.usage["total_tokens"] == 30


def test_records_reasoning_content_and_tool_call_names():
    tool_call = SimpleNamespace(
        id="c1",
        type="function",
        function=SimpleNamespace(name="nmap_scan", arguments='{"target": "example.com"}'),
    )
    response = _response(_message(content="", reasoning_content="thinking...", tool_calls=[tool_call]))

    trace = EngagementTrace()
    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={}) as handle:
        handle.set_response(response)

    record = trace.calls[0]
    assert record.reasoning_content == "thinking..."
    assert record.tool_call_names == ["nmap_scan"]
    assert record.tool_calls == [
        {
            "id": "c1",
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "arguments": '{"target": "example.com"}',
            },
        }
    ]


def test_exception_is_recorded_and_reraised():
    trace = EngagementTrace()
    with pytest.raises(ValueError):
        with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=1, request={}):
            raise ValueError("boom")

    assert len(trace.calls) == 1
    assert "boom" in trace.calls[0].error
    assert trace.calls[0].content is None


def test_summary_counts_calls_and_retries_and_tokens():
    trace = EngagementTrace()

    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={}) as handle:
        handle.set_response(_response(_message(content="a"), usage=_usage(10, 20, 30)))

    with trace.call(turn=2, call_kind="turn", truncation_attempt=1, network_attempt=0, request={}) as handle:
        handle.set_response(_response(_message(content="b"), usage=_usage(5, 5, 10)))

    with pytest.raises(RuntimeError):
        with trace.call(turn=2, call_kind="turn", truncation_attempt=1, network_attempt=1, request={}):
            raise RuntimeError("transient")

    summary = trace.summary()
    assert summary["total_llm_calls"] == 3
    assert summary["successful_calls"] == 2
    assert summary["failed_calls"] == 1
    assert summary["truncation_retries"] == 2  # both calls on turn 2 have truncation_attempt=1
    assert summary["network_retries"] == 1
    assert summary["total_prompt_tokens"] == 15
    assert summary["total_completion_tokens"] == 25
    assert summary["total_tokens"] == 40


def test_every_call_gets_a_wall_clock_timestamp():
    trace = EngagementTrace()
    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={}) as handle:
        handle.set_response(_response(_message(content="a"), usage=_usage()))

    record = trace.calls[0]
    assert isinstance(record.timestamp, str) and record.timestamp
    # Must be a real, parseable UTC ISO8601 timestamp.
    from datetime import datetime
    datetime.fromisoformat(record.timestamp)


def test_token_breakdown_is_recorded_when_given():
    trace = EngagementTrace()
    breakdown = {"facts": 10, "history": 5, "system_prompt_total": 100, "tool_schemas": 50, "conversation": 20,
                 "estimated_prompt_total": 170}
    with trace.call(
        turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={}, token_breakdown=breakdown,
    ) as handle:
        handle.set_response(_response(_message(content="a"), usage=_usage()))

    assert trace.calls[0].token_breakdown == breakdown


def test_token_breakdown_defaults_to_none():
    trace = EngagementTrace()
    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={}) as handle:
        handle.set_response(_response(_message(content="a"), usage=_usage()))

    assert trace.calls[0].token_breakdown is None



def test_persists_one_json_line_per_call(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = EngagementTrace(persist_path=str(path))

    with trace.call(turn=1, call_kind="turn", truncation_attempt=0, network_attempt=0, request={"model": "m"}) as handle:
        handle.set_response(_response(_message(content="a")))
    with trace.call(turn=2, call_kind="turn", truncation_attempt=0, network_attempt=0, request={"model": "m"}) as handle:
        handle.set_response(_response(_message(content="b")))

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["content"] == "a"
    assert json.loads(lines[1])["content"] == "b"


def test_empty_trace_summary():
    summary = EngagementTrace().summary()
    assert summary["total_llm_calls"] == 0
    assert summary["total_tokens"] == 0
