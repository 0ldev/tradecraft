# Tradecraft 2.0 Platform

The v2 work turns the single engagement loop into a platform in five
pillars. Everything here is additive: pre-2.0 behavior (all schemas,
full FACTS/HISTORY renders, the two hardcoded nudges) remains the
default for small toolsets, and each v2 mechanism can be switched off.

## Phase 0 — Coverage Matrix

`tradecraft/coverage/matrix.py` — one deterministic projection of the
FactStore answering "which target was checked for which vulnerability
class, and what came of it?".

- Statuses per (target, class): `vulnerable` / `clean` / `partial`
  (params discovered but this class untested) / `untested`.
- Class scan is generic: any `<class>_tested` / `<class>_vulnerable` /
  `<class>_injectable` field a tool reports shows up automatically.
- Three consumers: the model (compact table in the state message), the
  Studio UI (`to_dict()`), the report generator.

## Phase 1 — Efficient engine

- **Deterministic suggestions** (`tradecraft/execution/suggestions.py`):
  generalizes the hardcoded injection/interactsh nudges into rules over
  facts, rendered every turn as advisory "Suggested Next Actions" with
  the reason each fired. The model acts on them or dismisses them.
- **Dynamic tool menu** (`tradecraft/execution/tool_menu.py`): past a
  tool-count threshold (default 40), only always-on + activated tools
  get full schemas in `tools=`; the rest appear as one-line menu entries
  the model activates with the `load_tool` meta-tool. On small profiles
  the old send-everything behavior is kept.
  - Override: `TRADECRAFT_DYNAMIC_MENU=0|1`.

## Phase 2 — Finding verification

`tradecraft/policy/verify.py` — deterministic statuses over existing
evidence pointers: `verified` (cited evidence resolves and is non-empty),
`unverified` (no evidence cited), `missing_evidence` (cited id doesn't
resolve). The `verify_finding` tool hands the model the actual stored
evidence for a finding mid-engagement, so claims get confirmed or
retracted before the report, not discovered broken in it. The summary
renders in every state message; the report generator shows the same
classification.

## Phase 3 — Craft Studio

`tradecraft/studio/` — read-only live web dashboard over persisted runs.

```bash
pip install "tradecraft[studio]"
tradecraft studio                     # scans the whole TRADECRAFT_HOME
tradecraft studio --run-dir <path>    # one run tree
```

Shows: coverage matrix heatmap, findings + verification tags, log
notes, trace tail. Auto-refreshes every 5s. Vanilla HTML/JS, no build
step. `studio/data.py` is the pure data layer (unit-tested without a
server).

## Phase 4 — Knowledge graph + fan-out

- `tradecraft/memory/graph.py` — typed target graph (host → service →
  finding → evidence) persisted as `graph.json` next to each run.
  `render_seed()` produces the compact seed context for the next
  engagement on the same target; `diff_against()` yields new-services /
  new-findings between runs.
- `tradecraft/execution/fanout.py` — splits an engagement into per-host
  focused sub-runs (bounded thread pool, default 2 workers) planned
  from the coverage matrix, each with its own context, deterministically
  merged into one result with findings tagged by origin.

## Phase 5 — Ecosystem

- **Plugin SDK**: `tradecraft new-tool <tool_id>` scaffolds the YAML
  contract, adapter (execute/parse), tool glue, and a self-contained
  starter test; prints the exact registry lines to add.
- **Report factory**: the report now includes a deterministic
  "Coverage & ATT&CK Mapping" appendix (`reporting/attack_map.py`) —
  finding → ATT&CK technique + *estimated* CVSS, keyword-mapped, no LLM
  involved and clearly labeled as heuristic.
- **Bench harness**: `bench/` — lab targets with expected-finding
  keyword groups, scored automatically (`python -m bench.run_bench
  bench/labs/example.yaml`). Metrics: recall, turns-per-recall-point,
  findings-per-turn. Every optimization claim should move these numbers,
  and nothing else.

## Testing

All v2 modules are unit-tested; loop integration tests exercise the
menu gate, load_tool activation, and the state-message sections with a
mocked completion call.
