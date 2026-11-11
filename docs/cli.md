# CLI reference (`docs/cli.md`)

One console-script entrypoint, `tradecraft`, that dispatches on its first
argument: `chat`, `report`, `dataset`, or `memory` run that subsystem's
own command; anything else is treated as a target and runs an
engagement. Every subcommand below also has `-h`/`--help` for the
authoritative, always-current flag list — this doc is the map, not a
substitute for it.

All of the subcommands below that take `--run-dir`/`--target --run`
operate on the same persisted run layout under
`$TRADECRAFT_HOME` (default `~/.tradecraft`):

```
$TRADECRAFT_HOME/targets/<target>/runs/<run_id>/
    manifest.json   evidence/
    log.txt          <tool_id>.json per target
    trace.jsonl
    facts.json
    report.<ext>     (if --report was used)
```

## `tradecraft <target>` — run an engagement

```bash
tradecraft 10.0.0.5 --profile web --allow-destructive --report
```

| Flag | Purpose |
|---|---|
| `target` (positional) | Host/IP/domain to assess. |
| `--model` | litellm model string (default: `LLM_MODEL` from `.env`). |
| `--max-turns` | Hard cap on tool-call turns. `0` (default) = unlimited. |
| `--profile` | Named tool preset — see `docs/profiles.md`. Default `web`. |
| `--tools` | Explicit comma-separated tool id list; overrides `--profile`. |
| `--allow-destructive` | Make every `destructive: true` tool available regardless of category. Off by default — see `docs/policy.md`. |
| `--allow-destructive-categories` | Make only destructive tools whose declared blast-radius categories are all in this comma-separated list available. See `docs/policy.md`. |
| `--credential-budget` | Total credential-guessing attempts allowed per endpoint for the whole engagement, shared by `hydra`/`kerbrute_spray`. Must be `>= 1`. Defaults to 5. See `docs/policy.md`. |
| `--seed-from` | Prior `run_id` (or `latest`) against the same target to seed context from — the *entire* prior run's facts + log, verbatim. Sets `mode: complement` in the manifest. |
| `--guidance` | Free-text operator instruction/observation/focus for this engagement (see below). |
| `--no-persist` | Skip run-directory persistence; use temp/in-memory storage. |
| `--run-id` | Explicit run id instead of auto-generating one. |
| `--log` / `--trace` / `--evidence-dir` | Override where the log/trace/evidence persist (defaults live under the run directory). |
| `--report` [`PATH`] | Also write a report at the end of the run. |
| `--report-format` | Formats for `--report`: `md`, `html`, `json`, `sarif`, or `all`. |
| `--report-model` | Model for the report's executive summary (default: same as `--model`). |

### Automatic cross-engagement seeding

A second (or Nth) engagement against the same target — or even a
sibling subdomain under the same registrable root domain — doesn't
start blind. Every run, on completion, is auto-indexed into the
cross-engagement memory store (see `tradecraft memory` below) with no
extra flag needed. Then, at the *start* of a new run, if `--seed-from`
wasn't passed, the loop queries that store for prior verified findings
and service facts matching the target or its root domain and injects
a curated summary as a one-time Turn-0 seed context, before Turn 1 —
the system prompt stays static for the rest of the run. `mode` stays
`fresh` in the manifest in this case (`--seed-from` is what flips it
to `complement`); this auto-seed is a lighter-weight, best-effort
nudge, not a guarantee the model acts on it. It's silently skipped if
the store can't be reached or has nothing for that root domain.

### Operator guidance (`--guidance`)

A free-text instruction, observation, or focus for the engagement —
"focus on the GraphQL endpoint," "avoid the admin panel, another team
owns it this week," "the login form rate-limits oddly." Rendered as
its own `## Operator Guidance` section in the static system prompt
(right after `## Target`, before any seed context), stored in
`manifest.json`, and surfaced in `tradecraft report` output and the
`checklist` dataset format.

It's deliberately a single free-text field rather than separate
focus/exclusion/observation flags — real instructions mix all three,
and the model is told to treat it as *priority, not an exclusive
boundary*: it will still log a significant finding outside the stated
guidance rather than suppress it. This is advisory only, the same way
skills are — it is not a hard, code-enforced constraint. If you need
an actual hard boundary (a target path that must never be touched
regardless of what the model decides), that needs enforcing yourself
at the `--tools`/profile or policy layer; `--guidance` won't stop a
model that ignores it.

## `tradecraft chat` — post-run Q&A console

```bash
tradecraft chat --target 10.0.0.5 --ask "what did nmap find on port 443?"
```

Full writeup: [`docs/post-engagement.md`](post-engagement.md). Takes
`--run-dir` or `--target` (+ optional `--run`), `--ask` for one-shot
mode (otherwise opens a REPL), and `--model`.

## `tradecraft report` — standalone report generator

```bash
tradecraft report --target 10.0.0.5 --format md,html,json,sarif
```

Full writeup: [`docs/report.md`](report.md). Takes `--run-dir` or
`--target` (+ optional `--run`), `--format`, `--output`/`-o`, `--model`,
and `--no-llm` to skip the executive-summary synthesis call entirely.

## `tradecraft dataset` — SFT/DPO/checklist extraction

```bash
tradecraft dataset --all --format sft,dpo --scrub --min-score 4 --deduplicate
```

Full writeup, output formats, and curation recipes:
[`docs/finetune.md`](finetune.md). Takes `--run-dir`, `--target`
(+ `--run`), or `--all`; `--format`; `--behavior`; `--profile`;
`--min-score`; `--min-checklist-score`; `--deduplicate`; `--scrub`
(anonymizes the target domain, discovered subdomains, and IPv4
addresses); `--include-unfiltered`; `--require-reasoning`.

## `tradecraft memory` — cross-engagement memory store

Hybrid FTS5 BM25 + vector search over findings/facts/notes across
every indexed run (`tradecraft/memory/cross_engagement.py`), keyed by
target/root-domain. Four actions:

```bash
tradecraft memory index --target 10.0.0.5          # backfill from disk
tradecraft memory search "GraphQL introspection"    # query
tradecraft memory stats                             # summary counts
tradecraft memory clear --target 10.0.0.5           # remove entries
```

| Action | Key flags |
|---|---|
| `index` | `--run-dir` (one run) or `--target` (all runs for that target); `--db` to override the store path. |
| `search` | positional `query`; `--target`, `--kind` (`finding`/`fact`/`note`), `--limit` (default 10), `--json`. |
| `stats` | `--json`. |
| `clear` | `--target` to scope the removal (omit to clear everything); asks for nothing else, so double-check the scope first. |

All four take `--db` to point at a `memory.db` other than
`$TRADECRAFT_HOME/memory.db`.
