# Post-engagement investigation console (`docs/post-engagement.md`)

`tradecraft chat` is a read-only console over a finished (or interrupted)
engagement run's persisted artifacts — `log.txt`, `trace.jsonl`,
`evidence/`, `facts.json` (`tradecraft/reporting/console.py`). It answers
questions about a run by citing the actual turn or evidence file a
claim traces back to, rather than re-deriving an answer from scratch.

## Usage

```bash
tradecraft chat --target 10.0.0.5 --ask "what did nmap find on port 443?"
tradecraft chat --run-dir /path/to/run_dir
```

`--target` resolves the latest run for that target (or a specific one
via `--run <run_id>`); `--run-dir` points at one run directory
directly. `--ask` answers a single question and exits; without it,
`tradecraft chat` opens an interactive REPL for follow-up questions
against the same run. `--model` picks the model used to answer
questions (default: same as the engagement itself).

## What it's for

Reviewing a run after the fact — "why did the model stop testing that
endpoint," "what evidence backs finding #3," "did it ever check for
X" — without manually grepping `log.txt`/`trace.jsonl`/`evidence/`
yourself.
