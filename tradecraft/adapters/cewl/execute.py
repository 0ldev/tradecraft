"""
Subprocess execution for cewl: crawls one target site and extracts the
words it uses into a candidate wordlist (for password/username guessing
elsewhere -- hydra, kerbrute_spray, sqli_login -- not for submitting
anything itself; this adapter makes read-only GET requests only).

Writes the word list to a disposable tempdir via cewl's own -w flag
rather than parsing stdout, since cewl's stdout interleaves a banner
and progress lines with the actual words and that shape isn't worth
depending on. -d/-m match cewl's own --depth/--min_word_length flags.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

CEWL_BIN = "cewl"
TIMEOUT_SECONDS = 120
MIN_DEPTH = 1
MAX_DEPTH = 3
MAX_WORDS = 200


@dataclass
class RawCewlResult:
    words: List[str] = field(default_factory=list)
    error: Optional[str] = None


def is_available() -> bool:
    return shutil.which(CEWL_BIN) is not None


def build_argv(url: str, depth: int, min_word_length: int, output_file: str, binary: str = CEWL_BIN) -> List[str]:
    return [binary, "-d", str(depth), "-m", str(min_word_length), "-w", output_file, url]


def execute(
    target: str,
    depth: int = 2,
    min_word_length: int = 3,
    max_words: int = MAX_WORDS,
    timeout: int = TIMEOUT_SECONDS,
) -> RawCewlResult:
    url = target.strip()
    if not url:
        return RawCewlResult(error="empty target")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    binary = shutil.which(CEWL_BIN)
    if not binary:
        return RawCewlResult(error="cewl executable not found on PATH")

    bounded_depth = max(MIN_DEPTH, min(depth, MAX_DEPTH))
    bounded_min_len = max(1, min_word_length)
    bounded_max_words = max(1, min(max_words, MAX_WORDS))

    with tempfile.TemporaryDirectory() as tmp:
        output_path = str(Path(tmp) / "cewl_words.txt")
        argv = build_argv(url, bounded_depth, bounded_min_len, output_path, binary=binary)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return RawCewlResult(error=f"cewl timed out after {timeout}s")
        except Exception as exc:  # noqa: BLE001
            return RawCewlResult(error=f"cewl execution failed: {exc}")

        if not Path(output_path).is_file():
            stderr = (proc.stderr or "").strip()
            return RawCewlResult(error=f"cewl produced no output file (exit {proc.returncode}): {stderr}")

        lines = [l.strip() for l in Path(output_path).read_text(errors="replace").splitlines() if l.strip()]
        return RawCewlResult(words=lines[:bounded_max_words])
