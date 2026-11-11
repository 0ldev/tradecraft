"""
Uses a deterministic word-count counter instead of litellm's real
tokenizer so budgets in these tests are exact and easy to reason about.
"""
from unittest.mock import patch

import pytest

from tradecraft.execution.budget import (
    FALLBACK_CONTEXT_WINDOW,
    render_within_budget,
    resolve_context_window,
    total_context_budget,
    trim_conversation,
    trim_facts,
    trim_history,
)
from tradecraft.memory.log import EngagementMemory


def word_counter(model, messages):
    return sum(len((m.get("content") or "").split()) for m in messages)


# -- resolve_context_window --------------------------------------------------


@pytest.fixture
def no_context_window_env(monkeypatch):
    monkeypatch.delenv("LLM_CONTEXT_WINDOW", raising=False)


def test_env_var_takes_priority_over_litellm(no_context_window_env, monkeypatch):
    monkeypatch.setenv("LLM_CONTEXT_WINDOW", "262144")
    with patch("tradecraft.execution.budget.litellm.get_model_info", return_value={"max_input_tokens": 128000}) as mock_info:
        assert resolve_context_window("openai/qwen3.8-27b") == 262144
    mock_info.assert_not_called()  # env var short-circuits the lookup entirely


def test_falls_back_to_litellm_when_env_unset(no_context_window_env):
    with patch("tradecraft.execution.budget.litellm.get_model_info", return_value={"max_input_tokens": 128000}):
        assert resolve_context_window("gpt-4o") == 128000


def test_falls_back_to_128k_when_litellm_does_not_know_the_model(no_context_window_env):
    with patch("tradecraft.execution.budget.litellm.get_model_info", side_effect=Exception("ModelNotMappedError")):
        assert resolve_context_window("openai/qwen3.8-27b") == FALLBACK_CONTEXT_WINDOW


def test_falls_back_to_128k_when_litellm_returns_no_window_field(no_context_window_env):
    with patch("tradecraft.execution.budget.litellm.get_model_info", return_value={}):
        assert resolve_context_window("some-model") == FALLBACK_CONTEXT_WINDOW


# -- total_context_budget ---------------------------------------------------


def test_total_context_budget_subtracts_output_and_margin():
    assert total_context_budget(context_window=10000, max_output_tokens=2000) == 10000 - 2000 - 512


def test_total_context_budget_never_negative():
    assert total_context_budget(context_window=100, max_output_tokens=1000) == 0


# -- trim_history ------------------------------------------------------------


def test_trim_history_keeps_everything_when_it_fits():
    memory = EngagementMemory()
    memory.note("one two three")
    memory.finding("four five six")

    rendered = trim_history(memory.entries, budget_tokens=100, model="m", counter=word_counter)
    assert "note: one two three" in rendered
    assert "FINDING #1 [unverified: no evidence_id]: four five six" in rendered
    assert "omitted" not in rendered


def test_trim_history_drops_oldest_first_and_marks_it():
    memory = EngagementMemory()
    memory.note("aaaa bbbb cccc")  # oldest -- 3 words
    memory.note("dddd eeee ffff")  # newest -- 3 words, "note: " + 3 words = 4 words each line

    # budget fits only the newest line ("note: dddd eeee ffff" = 4 words)
    rendered = trim_history(memory.entries, budget_tokens=4, model="m", counter=word_counter)
    assert "dddd eeee ffff" in rendered
    assert "aaaa bbbb cccc" not in rendered
    assert "1 earlier log entry omitted" in rendered


def test_trim_history_empty_entries():
    assert trim_history([], budget_tokens=100, model="m", counter=word_counter) == "(empty -- nothing logged yet)"


def test_trim_history_findings_unaffected_by_trim():
    """memory.findings() reads .entries directly -- trimming the render
    for the prompt must never affect what the final report draws from."""
    memory = EngagementMemory()
    memory.finding("old finding that will get dropped from the window")
    memory.note("newer note")

    trim_history(memory.entries, budget_tokens=2, model="m", counter=word_counter)
    assert memory.findings() == ["old finding that will get dropped from the window [unverified: no evidence_id]"]


# -- trim_facts ---------------------------------------------------------


def test_trim_facts_keeps_everything_when_it_fits():
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    rendered = trim_facts(records, budget_tokens=100, model="m", counter=word_counter)
    assert "h:22" in rendered
    assert "omitted" not in rendered


def test_trim_facts_drops_oldest_first():
    records = [
        (("h", 22), {"host": "h", "port": 22, "service": "ssh"}),
        (("h", 80), {"host": "h", "port": 80, "service": "http"}),
    ]
    # budget fits roughly one record ("h:80 -- service=http" = 3 words)
    rendered = trim_facts(records, budget_tokens=3, model="m", counter=word_counter)
    assert "h:22" in rendered
    assert "h:80" not in rendered
    assert "omitted" in rendered


def test_trim_facts_empty():
    assert trim_facts([], budget_tokens=100, model="m", counter=word_counter) == "(no facts recorded yet)"


# -- trim_conversation --------------------------------------------------


def _turn(call_id, call_text, result_text):
    return [
        {"role": "assistant", "content": call_text, "tool_calls": [{"id": call_id}]},
        {"role": "tool", "tool_call_id": call_id, "content": result_text},
    ]


def test_trim_conversation_keeps_everything_when_it_fits():
    conv = [{"role": "user", "content": "begin"}, *_turn("c1", "a b", "x y")]
    result, omitted = trim_conversation(conv, static_tokens=0, total_budget=100, model="m", counter=word_counter)
    assert result == conv
    assert omitted == 0


def test_trim_conversation_drops_oldest_whole_turn_not_half_of_one():
    conv = [
        {"role": "user", "content": "begin"},
        *_turn("c1", "aaaa bbbb", "cccc dddd"),  # oldest turn: 4 words
        *_turn("c2", "eeee ffff", "gggg hhhh"),  # newest turn: 4 words
    ]
    # budget only large enough for "begin" (1 word) + one turn (4 words) = 5
    result, omitted = trim_conversation(conv, static_tokens=0, total_budget=5, model="m", counter=word_counter)

    assert omitted == 1
    assert result[0] == {"role": "user", "content": "begin"}
    assert result[1]["role"] == "user" and "omitted" in result[1]["content"]
    # the surviving turn is the newest one, and it's intact (assistant + its tool result)
    remaining_roles = [m["role"] for m in result[2:]]
    assert remaining_roles == ["assistant", "tool"]
    assert result[2]["tool_calls"][0]["id"] == "c2"


def test_trim_conversation_never_drops_the_first_message():
    conv = [{"role": "user", "content": "begin"}, *_turn("c1", "a", "b")]
    result, _omitted = trim_conversation(conv, static_tokens=0, total_budget=0, model="m", counter=word_counter)
    assert result[0] == {"role": "user", "content": "begin"}


def test_trim_conversation_empty_is_noop():
    assert trim_conversation([], static_tokens=0, total_budget=100, model="m", counter=word_counter) == ([], 0)


def test_trim_conversation_elastic_when_budget_zero_or_negative():
    conv = [
        {"role": "user", "content": "begin"},
        *_turn("c1", "a b", "c d"),
    ]
    # max_conversation_tokens <= 0 behaves elastically under total_budget
    assert trim_conversation(conv, static_tokens=0, total_budget=100, model="m", counter=word_counter, max_conversation_tokens=0) == (conv, 0)
    assert trim_conversation(conv, static_tokens=0, total_budget=100, model="m", counter=word_counter, max_conversation_tokens=-1) == (conv, 0)


def test_trim_conversation_respects_explicit_conversation_budget():
    conv = [
        {"role": "user", "content": "begin"},
        *_turn("c1", "aaaa bbbb", "cccc dddd"),  # oldest turn: 4 words
        *_turn("c2", "eeee ffff", "gggg hhhh"),  # newest turn: 4 words
    ]
    # total_budget is huge (1000), but max_conversation_tokens=5 fits "begin" (1 word) + 1 turn (4 words)
    result, omitted = trim_conversation(
        conv, static_tokens=0, total_budget=1000, model="m", counter=word_counter, max_conversation_tokens=5
    )
    assert omitted == 1
    assert result[0] == {"role": "user", "content": "begin"}
    assert "omitted" in result[1]["content"]
    assert result[2]["tool_calls"][0]["id"] == "c2"


def test_conversation_token_budget_env_var(monkeypatch):
    monkeypatch.setenv("TRADECRAFT_CONVERSATION_TOKEN_BUDGET", "25000")
    import importlib
    import tradecraft.execution.budget
    importlib.reload(tradecraft.execution.budget)
    assert tradecraft.execution.budget.DEFAULT_CONVERSATION_TOKEN_BUDGET == 25000
    monkeypatch.delenv("TRADECRAFT_CONVERSATION_TOKEN_BUDGET", raising=False)
    importlib.reload(tradecraft.execution.budget)
    assert tradecraft.execution.budget.DEFAULT_CONVERSATION_TOKEN_BUDGET == 0


# -- render_within_budget -----------------------------------------------


def _prompt(history_r, facts_r):
    # "SYS"/"MID"/"END" are 3 fixed literal words -- keeps hand-computed
    # word-count arithmetic in these tests simple and exact.
    return f"SYS {history_r} MID {facts_r} END"


def test_render_within_budget_noop_when_everything_fits():
    memory = EngagementMemory()
    memory.note("one two three")
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    conv = [{"role": "user", "content": "begin"}, *_turn("c1", "a b", "x y")]

    history_r, facts_r, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=1000, model="m", counter=word_counter,
    )
    assert "one two three" in history_r
    assert "h:22" in facts_r
    assert out_conv == conv
    assert omitted == 0


def test_render_within_budget_shrinks_conversation_first():
    memory = EngagementMemory()
    memory.note("a note")
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    conv = [
        {"role": "user", "content": "begin"},
        *_turn("c1", "zzz " * 20, "yyy " * 20),  # oldest turn, heavy (40 words)
        *_turn("c2", "p p p p", "q q q q"),  # newest turn, light (8 words)
    ]
    # Full prompt (history+facts, 9 words) + full conversation (49 words)
    # = 58, over budget; dropping the oldest turn alone (down to 1 head +
    # 10-word marker + 8-word newest turn = 19) brings it under 30 without
    # touching HISTORY or FACTS at all.
    history_r, facts_r, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=30, model="m", counter=word_counter,
    )
    assert "a note" in history_r  # HISTORY untouched
    assert "h:22" in facts_r  # FACTS untouched
    assert any("omitted" in (m.get("content") or "") for m in out_conv)  # CONVERSATION shrank
    assert not any("zzz" in (m.get("content") or "") for m in out_conv)  # oldest (heavy) turn gone
    assert omitted == 1


def test_render_within_budget_shrinks_history_next_once_conversation_is_minimal():
    memory = EngagementMemory()
    memory.note("aaaa bbbb cccc")  # oldest
    memory.note("dddd eeee ffff")  # newest
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    conv = [{"role": "user", "content": "begin"}, *_turn("c1", "a b", "x y")]

    # Budget tight enough that even dropping the lone conversation turn
    # isn't enough -- HISTORY has to give up its oldest entry next, while
    # FACTS (not yet exhausted as an option) stays untouched.
    history_r, facts_r, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=13, model="m", counter=word_counter,
    )
    assert "dddd eeee ffff" in history_r  # kept the newest
    assert "aaaa bbbb cccc" not in history_r  # oldest dropped
    assert "h:22" in facts_r  # FACTS still untouched


def test_render_within_budget_shrinks_facts_last_as_true_last_resort():
    memory = EngagementMemory()
    memory.note("a note")
    records = [
        (("h", 22), {"host": "h", "port": 22, "service": "ssh"}),
        (("h", 80), {"host": "h", "port": 80, "service": "http"}),
    ]
    conv = [{"role": "user", "content": "begin"}]

    # Budget too small for everything even with history/conversation
    # minimized -- FACTS (the last resort) has to give up a record too.
    history_r, facts_r, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=6, model="m", counter=word_counter,
    )
    assert "h:22" in facts_r
    assert "h:80" not in facts_r
    assert "omitted" in facts_r


def test_render_within_budget_enforces_conversation_cap_even_when_total_fits():
    # Regression: the early-return path ignored max_conversation_tokens, so a
    # cap (TRADECRAFT_CONVERSATION_TOKEN_BUDGET) only bit once the *total* budget
    # overflowed. Here the total budget is huge, so only the cap can trim.
    memory = EngagementMemory()
    memory.note("a note")
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    conv = [
        {"role": "user", "content": "begin"},
        *_turn("c1", "zzz " * 40, "yyy " * 40),  # oldest, heavy (80 words)
        *_turn("c2", "p p p p", "q q q q"),  # newest, light (8 words)
    ]
    history_r, facts_r, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=100000, model="m", counter=word_counter,
        max_conversation_tokens=30,
    )
    assert omitted == 1
    assert not any("zzz" in (m.get("content") or "") for m in out_conv)
    assert word_counter("m", out_conv) <= 30 + 10  # cap, allowing for the omission marker
    assert "a note" in history_r
    assert "h:22" in facts_r


def test_render_within_budget_cap_zero_stays_elastic():
    memory = EngagementMemory()
    records = [(("h", 22), {"host": "h", "port": 22, "service": "ssh"})]
    conv = [{"role": "user", "content": "begin"}, *_turn("c1", "zzz " * 40, "yyy " * 40)]
    _, _, out_conv, omitted = render_within_budget(
        memory.entries, records, conv, _prompt, tool_schemas_tokens=0,
        total_budget=100000, model="m", counter=word_counter,
        max_conversation_tokens=0,
    )
    assert out_conv == conv
    assert omitted == 0
