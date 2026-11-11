"""
Cache-friendly message layout (tradecraft/execution/loop.py): across turns the
system message must stay byte-identical, and the per-turn engagement state
must sit as the final message, after the conversation, never inside the
system message and never persisted into the conversation.
"""
from types import SimpleNamespace
from unittest.mock import patch

from tradecraft.execution.loop import run_engagement
from tradecraft.memory.facts import FactStore


def _response(content: str = "Final report"):
    message = SimpleNamespace(content=content, tool_calls=None)
    choice = SimpleNamespace(finish_reason="stop", message=message)
    return SimpleNamespace(choices=[choice], usage=None)


@patch("tradecraft.execution.loop._complete_with_retry")
def test_system_message_is_static_and_state_is_last(mock_complete):
    # First voluntary stop with an open injection thread triggers one nudge
    # turn, so the loop makes two model calls we can compare.
    mock_complete.side_effect = [_response("done for now"), _response("Final report")]

    seeded_facts = FactStore()
    seeded_facts.merge_port("example.com", 443, {"arjun_params_discovered": 5})

    with patch("tradecraft.execution.loop.FactStore", return_value=seeded_facts):
        result = run_engagement("example.com", model="test-model", max_turns=5)

    assert mock_complete.call_count == 2
    first_messages = mock_complete.call_args_list[0].kwargs["messages"]
    second_messages = mock_complete.call_args_list[1].kwargs["messages"]

    # 1. The system message is identical on every call -- the cacheable prefix.
    assert first_messages[0]["role"] == "system"
    assert first_messages[0] == second_messages[0]

    # 2. The engagement state is not inside the system message.
    assert "## Engagement Log So Far" not in first_messages[0]["content"]
    assert "## Engagement Budget" not in first_messages[0]["content"]

    # 3. Each call ends with the state message, after the conversation.
    for messages in (first_messages, second_messages):
        assert messages[-1]["role"] == "user"
        assert "## Engagement Budget" in messages[-1]["content"]
        assert "## Engagement Log So Far" in messages[-1]["content"]

    # 4. The state message is not persisted into the conversation transcript.
    assert not any(
        "[Engagement state" in str(msg.get("content", "")) for msg in result.transcript
    )
    # The conversation is the prefix the second call extends.
    assert second_messages[1:-1][: len(first_messages) - 2] == first_messages[1:-1]
