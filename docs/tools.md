# Tools & adapters

A **tool** is one action the model can call during an engagement. Every
tool is declared in two halves, kept deliberately separate:

- `config/tools/<tool_id>.yaml` — the **contract** the model sees: a
  narrow, factual `description` (what it does, what inputs it needs),
  the parameter schema, which binary it needs (`required_binary`, if
  any), which parameter carries its network target (`scope_param`, if
  any), and whether it's `destructive`.
- `tradecraft/tools/<tool_id>.py` — a thin `Tool` subclass. Just `tool_id`
  plus a `run()` that calls its adapter and shapes the result into the
  dict returned to the model. No subprocess or parsing logic lives here.

A capability only exists if its `Tool` is registered in
`tradecraft/tools/registry.py`'s `ALL_TOOLS` **and** has a matching YAML
contract — one without the other is a hard failure, not a silent skip.
A test (`tests/test_tool_schema_completeness.py`) enforces that every
parameter `run()` accepts is declared in the YAML with a non-empty
description, and vice versa.

## Adapters

`tradecraft/adapters/<tool>/` holds the actual execution logic, split into
two pure layers:

- `execute.py` — builds the subprocess argv, runs it, returns a raw
  result (or an `error`, for a missing binary/timeout/crash).
- `parse.py` — pure functions, no I/O, no subprocess. Turns raw output
  into clean, structured data.

The `Tool.run()` glues `execute()` → `parse()` → the dict shape the
model sees. This split is what lets adapters be tested by mocking only
the subprocess call and verifying argv construction and parsing
independently, against real captured tool output rather than
hand-typed fixtures.

Want to add a new tool? See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Destructive tools

A tool that can mutate target state in a way that doesn't undo itself
— account lockouts from credential brute-forcing, a planted webshell,
data deletion — is **destructive**, regardless of whether it looks like
"recon" or "exploitation." Its contract declares `destructive: true`
plus a `destructive_categories:` list. See [`docs/policy.md`](policy.md)
for the full mechanics: the two opt-in flags, the six blast-radius
categories, and the `account_lockout_risk` budget shared by `hydra` and
`kerbrute_spray`.

## Engagement-shape profiles

`config/profiles/<profile_id>.yaml` curate which tools apply to an
engagement shape — an external web app, an internal AD network, a
Kubernetes cluster — selected with `--profile` (default: `web`).
See [`docs/profiles.md`](profiles.md) for the full picture: how
profiles overlap on purpose, how to classify a tool into one, and how
to add a new one.

## Skills vs. tool descriptions

A tool's YAML `description` only ever says what that one tool does.
Knowledge about *when* to reach for it relative to other tools —
sequencing, prioritization, tradecraft — belongs in a skill instead.
See [`docs/skills.md`](skills.md).
