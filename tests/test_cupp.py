from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pexpect

from tradecraft.adapters.cupp import execute as cupp_execute
from tradecraft.adapters.cupp import parse as cupp_parse
from tradecraft.tools.cupp import Cupp

FAKE_CUPP = str(Path(__file__).resolve().parent / "fixtures" / "fake_cupp.py")
_REAL_SPAWN = pexpect.spawn


def _spawn_fake(binary, args, **kwargs):
    return _REAL_SPAWN(sys.executable, [FAKE_CUPP], **kwargs)


def test_execute_requires_name():
    assert cupp_execute.execute(name="").error == "name is required"


def test_execute_binary_not_found():
    with patch.object(cupp_execute, "find_binary", return_value=None):
        res = cupp_execute.execute(name="John")
        assert res.error == "cupp executable not found on PATH"


def test_prompt_matching_is_order_independent():
    """fake_cupp.py asks company/surname/name/pet/keywords/leet in that
    order -- different from tradecraft's own prompt table order -- to prove
    answers land on the right field by keyword, not by position. Also
    exercises the real two-step keywords flow (a Y/[N] gate, then a
    separate prompt for the actual words) confirmed against a live
    cupp.py run -- a single "keyword"-matching field would silently
    never send the keywords_value answer at all."""
    with patch.object(cupp_execute, "find_binary", return_value=FAKE_CUPP):
        with patch("pexpect.spawn", side_effect=_spawn_fake):
            res = cupp_execute.execute(
                name="John",
                surname="Smith",
                company="Acme",
                pet_name="Rex",
                keywords="widget,gadget",
                leet_mode=True,
            )

    assert res.error is None
    assert "Acme" in res.words
    assert "Smith" in res.words
    assert "John" in res.words
    assert "Rex" in res.words
    assert "widget,gadget" in res.words
    assert "y" in res.words  # leet_mode answered "y"
    assert "JohnSmith" in res.words
    assert res.prompts_answered == 8  # company, surname, name, pet, keywords gate+value, leet, hyperspeed


def test_blank_fields_send_blank_answers():
    with patch.object(cupp_execute, "find_binary", return_value=FAKE_CUPP):
        with patch("pexpect.spawn", side_effect=_spawn_fake):
            res = cupp_execute.execute(name="Jane")

    assert res.error is None
    assert "Jane" in res.words
    # No pet/company/surname given -- fake_cupp only writes non-empty answers.
    assert "Acme" not in res.words


def test_max_words_bounds_output():
    with patch.object(cupp_execute, "find_binary", return_value=FAKE_CUPP):
        with patch("pexpect.spawn", side_effect=_spawn_fake):
            res = cupp_execute.execute(name="John", surname="Smith", max_words=2)

    assert len(res.words) == 2


def test_parse_cupp_result_success():
    raw = cupp_execute.RawCuppResult(words=["acme", "john"])
    assert cupp_parse.parse_cupp_result(raw) == {"words": ["acme", "john"], "total_words": 2}


def test_parse_cupp_result_error():
    raw = cupp_execute.RawCuppResult(error="name is required")
    parsed = cupp_parse.parse_cupp_result(raw)
    assert parsed["error"] == "name is required"
    assert parsed["words"] == []


def test_tool_run_wires_through():
    with patch.object(cupp_execute, "find_binary", return_value=FAKE_CUPP):
        with patch("pexpect.spawn", side_effect=_spawn_fake):
            result = Cupp().run(name="John", surname="Smith")

    assert "error" not in result
    assert "John" in result["words"]
