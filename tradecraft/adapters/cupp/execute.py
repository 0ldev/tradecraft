"""
Subprocess execution for cupp: drives Mebus/cupp's interactive `-i`
profiling Q&A via pexpect to generate a personalized candidate password
list from OSINT details about a target person (name, birthdate, partner,
pet, company -- the kind of thing social media/company-site recon turns
up). Entirely local text generation; no network calls, not destructive.

Verified against a real `Mebus/cupp` checkout (run inside a disposable
container, 2026-11-11) with every field populated end to end, confirming
the full prompt sequence and exact wording -- including two real
surprises a documented-field-set guess would have missed: cupp's
"keywords" step is actually two separate prompts (a Y/[N] gate, "Do you
want to add some key words about the victim?", then -- only if
answered y -- a second prompt asking for the actual comma-separated
words), and there's a final "Hyperspeed Print? (Y/n)" prompt after leet
mode that isn't part of the documented field set at all -- and despite
its name, answering y there is the SLOW path: it echoes every one of
tens of thousands of generated candidates to the terminal with no
further prompt to detect completion by, which blew straight through a
30s timeout in testing. Answering n is what finishes in under a second.
Matched by keyword in the prompt text rather than by a fixed question order (cupp
itself has at least one typo in its own prompt text, "Partners) name"
instead of "Partner's name" -- substring matching shrugs this off,
position-based matching wouldn't). If a prompt doesn't match anything
in the table, this sends a blank line (cupp's own skip-this-field
behavior) rather than guessing, so an upstream wording change in some
other version degrades to "field skipped," not a wrong answer reaching
the wrong question.

Runs inside a disposable tempdir (cwd) so the generated wordlist file
--cupp writes <name>.txt to its working directory, not a path you choose
-- can be found afterward without colliding with anything.

Invoked as `sys.executable <cupp.py path> -i`, not by executing
cupp.py directly -- also confirmed the hard way in that same verification
container: cupp.py's own shebang is `#!/usr/bin/python3`, which doesn't
exist in a plain `python:3.12-slim-bookworm` image (python3 there lives
at /usr/local/bin/python3), so direct execution fails with ENOENT
despite the file being executable and `python3` itself being on PATH.
Running it through the interpreter already running this process sidesteps
that entirely, regardless of where cupp.py is installed or what its
shebang says.
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import pexpect

CUPP_BIN = "cupp.py"
CUPP_BIN_FALLBACK = "cupp"
TIMEOUT_SECONDS = 30
MAX_PROMPT_ROUNDS = 40
MAX_WORDS = 500

# Checked in order, first match wins. Keys are regexes matched
# case-insensitively against the prompt text since the last answer.
_PROMPT_FIELD_ORDER = [
    "partner_nickname",
    "partner_birthdate",
    "partner_name",
    "child_nickname",
    "child_birthdate",
    "child_name",
    "pet_name",
    "company",
    "surname",
    "nickname",
    "birthdate",
    "keywords_value",
    "keywords_gate",
    "add_special_chars",
    "add_random_numbers",
    "leet_mode",
    "hyperspeed",
    "name",
]

_PROMPT_PATTERNS: Dict[str, str] = {
    "partner_nickname": r"partner.{0,25}nickname",
    "partner_birthdate": r"partner.{0,25}birth",
    "partner_name": r"partner",
    "child_nickname": r"child.{0,25}nickname",
    "child_birthdate": r"child.{0,25}birth",
    "child_name": r"child",
    "pet_name": r"pet",
    "company": r"compan",
    "surname": r"surname",
    "nickname": r"nickname",
    "birthdate": r"birth",
    # cupp asks these as two separate prompts: a Y/[N] gate ("Do you want
    # to add some key words about the victim?"), then -- only if answered
    # y -- a second prompt asking for the actual comma-separated words
    # ("Please enter the words, separated by comma"). Confirmed against
    # a real cupp.py -i run; "keyword" (no space) never matches the real
    # prompt text, which says "key words".
    "keywords_value": r"separated by comma",
    "keywords_gate": r"key\s*words?",
    "add_special_chars": r"special char",
    "add_random_numbers": r"random numbers?",
    "leet_mode": r"leet",
    "hyperspeed": r"hyperspeed",
    "name": r"\bname\b",
}


@dataclass
class RawCuppResult:
    words: List[str] = field(default_factory=list)
    prompts_answered: int = 0
    error: Optional[str] = None


def find_binary() -> Optional[str]:
    return shutil.which(CUPP_BIN) or shutil.which(CUPP_BIN_FALLBACK)


def is_available() -> bool:
    return find_binary() is not None


def _answer_for_prompt(prompt_text: str, answers: Dict[str, str]) -> str:
    lowered = prompt_text.lower()
    for field_name in _PROMPT_FIELD_ORDER:
        if re.search(_PROMPT_PATTERNS[field_name], lowered):
            return answers.get(field_name, "")
    return ""


def execute(
    name: str = "",
    surname: str = "",
    nickname: str = "",
    birthdate: str = "",
    partner_name: str = "",
    partner_nickname: str = "",
    partner_birthdate: str = "",
    child_name: str = "",
    child_nickname: str = "",
    child_birthdate: str = "",
    pet_name: str = "",
    company: str = "",
    keywords: str = "",
    add_special_chars: bool = False,
    add_random_numbers: bool = False,
    leet_mode: bool = False,
    max_words: int = MAX_WORDS,
    timeout: int = TIMEOUT_SECONDS,
) -> RawCuppResult:
    if not name.strip():
        return RawCuppResult(error="name is required")

    binary = find_binary()
    if not binary:
        return RawCuppResult(error="cupp executable not found on PATH")

    answers = {
        "name": name.strip(),
        "surname": surname.strip(),
        "nickname": nickname.strip(),
        "birthdate": birthdate.strip(),
        "partner_name": partner_name.strip(),
        "partner_nickname": partner_nickname.strip(),
        "partner_birthdate": partner_birthdate.strip(),
        "child_name": child_name.strip(),
        "child_nickname": child_nickname.strip(),
        "child_birthdate": child_birthdate.strip(),
        "pet_name": pet_name.strip(),
        "company": company.strip(),
        "keywords_gate": "y" if keywords.strip() else "n",
        "keywords_value": keywords.strip(),
        "add_special_chars": "y" if add_special_chars else "n",
        "add_random_numbers": "y" if add_random_numbers else "n",
        "leet_mode": "y" if leet_mode else "n",
        # "Hyperspeed Print?" means "echo every generated word to the
        # terminal as it goes" (confirmed live: answering y here made
        # cupp spend minutes scrolling tens of thousands of candidate
        # words with no further prompt to detect completion by) --
        # answering n is what finishes quickly and cleanly. The name is
        # misleading; this isn't a performance switch, it's a verbosity
        # one.
        "hyperspeed": "n",
    }

    bounded_max_words = max(1, min(max_words, MAX_WORDS))

    with tempfile.TemporaryDirectory() as tmp:
        try:
            child = pexpect.spawn(sys.executable, [binary, "-i"], cwd=tmp, timeout=timeout, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            return RawCuppResult(error=f"cupp failed to start: {exc}")

        rounds = 0
        try:
            while rounds < MAX_PROMPT_ROUNDS:
                index = child.expect([r"[:?]\s*$", pexpect.EOF, pexpect.TIMEOUT])
                if index != 0:
                    break
                answer = _answer_for_prompt(child.before or "", answers)
                child.sendline(answer)
                rounds += 1
            else:
                child.close(force=True)
                return RawCuppResult(
                    prompts_answered=rounds,
                    error=f"cupp exceeded {MAX_PROMPT_ROUNDS} prompt rounds without finishing",
                )
            child.expect(pexpect.EOF, timeout=timeout)
        except pexpect.exceptions.TIMEOUT:
            child.close(force=True)
            return RawCuppResult(prompts_answered=rounds, error=f"cupp timed out after {timeout}s waiting for a prompt")
        except Exception as exc:  # noqa: BLE001
            child.close(force=True)
            return RawCuppResult(prompts_answered=rounds, error=f"cupp execution failed: {exc}")
        finally:
            if child.isalive():
                child.close(force=True)

        generated = sorted(Path(tmp).glob("*.txt"))
        if not generated:
            return RawCuppResult(prompts_answered=rounds, error="cupp produced no wordlist file")

        lines = [l.strip() for l in generated[0].read_text(errors="replace").splitlines() if l.strip()]
        return RawCuppResult(words=lines[:bounded_max_words], prompts_answered=rounds)
