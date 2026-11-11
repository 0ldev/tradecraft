# Skills

A **skill** is a markdown file in `tradecraft/skills/*.md` holding advisory
tradecraft knowledge: facts the model can weigh when deciding what to
do next, never an enforced phase, gate, or prescribed pipeline. Tradecraft
is a single continuous tool-calling loop — the model decides what to
run next — and skills exist to make that decision better-informed
without turning the loop into a staged planner.

## What goes in a skill vs. a tool description

A tool's own `description` in `config/tools/<id>.yaml` is narrow and
factual: what that one tool does, what inputs it needs. Anything about
*sequencing or prioritizing it relative to other tools* — "prefer a
non-destructive check before reaching for this one," "this tool's
output feeds that one's input," a class of finding that tends to need
several tools chained together — belongs in a skill instead, stated as
a fact the model can weigh, not an instruction it must follow.

Skills are also not a place for generic pentesting advice. A skill
should close a concrete, tool-specific knowledge gap — not restate
"recon before exploitation" or similar workflow truisms a capable model
already knows.

## How skills are rendered

`tradecraft/skills/loader.py`'s `render_skills()` concatenates every
`*.md` file in that directory into the system prompt, **in full, on
every turn**. There's no manifest, no trigger/applicability matching,
and no tiering — every skill is always visible, regardless of what the
engagement is actually doing. This keeps the system prompt
byte-identical across turns (good for prompt-caching) and avoids
building a second, skill-shaped planning layer on top of the tool loop.

## Current skills

Each file's name is its own description. As of this writing:

`cloud_asset_enumeration`, `cors_misconfiguration_testing`,
`credential_wordlist_generation`, `destructive_tool_sequencing`,
`endpoint_and_parameter_fuzzing`, `evidence_retrieval`,
`graphql_schema_recovery`, `js_endpoint_extraction`, `parameter_triage`,
`post_exploitation_cve_triage`, `second_order_injection_testing`,
`single_shot_tool_confirmation`, `spa_dynamic_crawling`,
`ssrf_open_redirect_discovery`, `version_exploit_lookup`,
`vulnerability_scanning_tradecraft`, `waf_tradecraft`.

## Adding a skill

Add one only when a specific tool's value depends on *when* to use it
relative to other tools — not because the tool exists, and not to
encode a general methodology. If in doubt, it probably doesn't need a
skill yet.
