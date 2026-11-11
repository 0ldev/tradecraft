"""
Tests for _engagement_budget_text (tradecraft/execution/loop.py): the exact,
never-estimated turn/trim status line surfaced in the system prompt each
turn.
"""
from tradecraft.execution.loop import _engagement_budget_text


def test_unlimited_turns_and_no_trimming():
    text = _engagement_budget_text(turn=5, max_turns=0, conversation_turns_omitted=0)
    assert "No turn limit for this engagement" in text
    assert "No conversation trimming has happened yet." in text


def test_unlimited_turns_with_trimming():
    text = _engagement_budget_text(turn=29, max_turns=0, conversation_turns_omitted=28)
    assert "No turn limit for this engagement" in text
    assert "28 earlier tool-call turn(s) are currently trimmed" in text
    assert "never a reason to narrow investigation scope" in text


def test_finite_turns_remaining_count_is_exact():
    text = _engagement_budget_text(turn=3, max_turns=10, conversation_turns_omitted=0)
    assert "Turn 3 of 10 (7 remaining)." in text
    assert "No conversation trimming has happened yet." in text


def test_finite_turns_with_trimming():
    text = _engagement_budget_text(turn=8, max_turns=10, conversation_turns_omitted=2)
    assert "Turn 8 of 10 (2 remaining)." in text
    assert "2 earlier tool-call turn(s) are currently trimmed" in text


def test_last_available_turn_shows_zero_remaining():
    text = _engagement_budget_text(turn=10, max_turns=10, conversation_turns_omitted=0)
    assert "Turn 10 of 10 (0 remaining)." in text
