# Report generation (`docs/report.md`)

Tradecraft turns a persisted engagement run into a structured security
assessment report: findings, facts, and closing notes rendered
deterministically from the run's data, plus an LLM-synthesized
Executive Summary (`tradecraft/reporting/generator.py`).

## Two ways to generate one

**Inline, at the end of a live engagement:**

```bash
tradecraft 10.0.0.5 --report --report-format md,html
```

`--report` (no path) writes `report.<ext>` inside that run's directory;
an explicit path overrides the default. `--report-format` accepts any
comma-separated combination of `md`, `html`, `json`, `sarif`, or `all`.
`--report-model` picks a different model for the summary synthesis call
than the engagement itself used.

**Standalone, over any already-finished or interrupted run:**

```bash
tradecraft report --target 10.0.0.5 --format md,html,json,sarif
tradecraft report --run-dir /path/to/run_dir --output ./out/ --no-llm
```

`tradecraft report` reads a run directory directly — no live engagement
needed. `--no-llm` skips the Executive Summary synthesis call entirely
and produces a strictly deterministic report (useful for offline/CI
use, or when no LLM endpoint is configured). `--run` picks a specific
run ID under `--target` (default: latest).

## Formats

- **`md`** / **`html`** — human-readable report: Executive Summary,
  findings (with evidence citations), facts, turn history.
- **`json`** — the same data as a structured machine-readable bundle.
- **`sarif`** — for ingestion into SIEM/CI tooling that consumes the
  [SARIF](https://sarifweb.azurewebsites.net/) static-analysis format.

If a run logged no findings and no facts, report generation is skipped
with a warning rather than producing an empty report.
