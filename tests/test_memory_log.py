import re

from tradecraft.memory.log import EngagementMemory


def test_render_has_no_timestamp():
    memory = EngagementMemory()
    memory.note("checked port 80")
    memory.finding("port 80 open, nginx 1.24.0")

    rendered = memory.render()
    assert "note: checked port 80" in rendered
    assert "FINDING #1 [unverified: no evidence_id]: port 80 open, nginx 1.24.0" in rendered
    # no ISO-8601-ish timestamp bracket anywhere
    assert not re.search(r"\[\d{4}-\d{2}-\d{2}T", rendered)


def test_empty_memory_renders_placeholder():
    assert EngagementMemory().render() == "(empty -- nothing logged yet)"


def test_findings_only_returns_finding_entries():
    memory = EngagementMemory()
    memory.note("just a note")
    memory.finding("a real finding")
    assert memory.findings() == ["a real finding [unverified: no evidence_id]"]


def test_finding_returns_a_stable_incrementing_id():
    memory = EngagementMemory()
    first_id = memory.finding("first")
    second_id = memory.finding("second")
    assert first_id == 1
    assert second_id == 2


def test_retract_removes_finding_from_findings_but_keeps_it_in_render():
    memory = EngagementMemory()
    finding_id = memory.finding("a finding that turns out to be wrong")
    ok = memory.retract(finding_id, "contradicted by a later check")
    assert ok is True
    assert memory.findings() == []  # excluded from the report-facing list
    rendered = memory.render()
    assert "FINDING #1 [RETRACTED] [unverified: no evidence_id]: a finding that turns out to be wrong" in rendered
    assert "Finding #1 retracted: contradicted by a later check" in rendered


def test_retract_unknown_id_returns_false_and_changes_nothing():
    memory = EngagementMemory()
    memory.finding("a real finding")
    ok = memory.retract(999, "doesn't exist")
    assert ok is False
    assert memory.findings() == ["a real finding [unverified: no evidence_id]"]


def test_retract_does_not_affect_other_findings():
    memory = EngagementMemory()
    memory.finding("stays")
    second_id = memory.finding("goes")
    memory.retract(second_id, "wrong")
    assert memory.findings() == ["stays [unverified: no evidence_id]"]
