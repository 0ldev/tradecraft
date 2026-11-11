# Engagement-shape profiles (`docs/profiles.md`)

A **profile** is a named, curated list of tool ids for one kind of
engagement — an external web app, an internal AD network, a cloud
account, a Kubernetes cluster. It's selected at launch with
`--profile <name>` (default: `web`); `--tools` passed explicitly
always overrides it. The built-in `full` profile isn't a file at all —
it loads every tool in `tradecraft/tools/registry.py`'s `ALL_TOOLS`
directly.

This is a static, pre-run, operator-made decision — the same one-way
shape as `--tools` itself. It's about *scope* (which tools make sense
for this kind of target), which is orthogonal to the destructive-tools
axis in [`docs/policy.md`](policy.md), which is about *risk* (which
tools are safe to hand the model by default).

## Profiles overlap — on purpose

A tool can and should appear in more than one profile. Profiles are
**not a partition** of the tool registry — they're presets, and
plenty of tools are relevant to several engagement shapes at once.
Concretely, every pair of the five current profiles shares tools; e.g.
`nmap_scan`/`http_request`/`httpx_probe` show up in all five, and
`cloud` and `web` share 27 tools outright (cloud-asset tools that are
just as relevant probing a web app's infrastructure as a pure cloud
engagement).

Don't treat "which profile does this tool already belong to" as a
reason to leave it out of another profile it's genuinely relevant to.

## How to classify a tool into a profile

Ask what's actually true about the *target*, not the tool's own label.
A tool belongs in a profile if it can produce a meaningful result
against that engagement shape's kind of target — regardless of whether
the tool "sounds like" recon, exploitation, cloud, or web. Some
starting questions:

- Does this tool need a target that's reachable over the network the
  way this profile's targets are (e.g. an AD domain controller vs. a
  public web app vs. a cloud API endpoint)?
- Does it need a precondition this engagement shape typically has
  (e.g. `post-exploitation`'s tools assume an already-established
  foothold; most others don't)?
- Is it a generic, stack-agnostic check (HTTP probing, TCP probing,
  generic secret scanning) that's relevant almost everywhere? Those
  tend to end up in most or all profiles.

When in doubt, prefer including a tool in a profile it's plausibly
relevant to over leaving it out — a profile that's too narrow costs an
engagement real coverage; a tool that turns out irrelevant for a given
target just returns nothing, at the cost of one wasted call.

## Current profiles

| Profile | Shape |
|---|---|
| `web` | External web application and network-perimeter pentesting (default) |
| `cloud` | Cloud infrastructure assessment (AWS/GCP/Azure) |
| `ad-network` | Internal Active Directory / Windows network pentesting |
| `kubernetes` | Kubernetes cluster and containerized infrastructure |
| `post-exploitation` | Local privesc/auditing from an already-established foothold |
| `full` | Every registered tool (built-in, no YAML file) |

## Tools intentionally outside every profile

Every registered tool should normally end up in at least one profile —
see "How to classify a tool into a profile" above. A tool only belongs
in this section if there is a deliberate reason it should not be
auto-included in *any* profile by default. Such a tool is still callable
explicitly via `--tools`.

Each exclusion is a `### <tool_id>` heading followed by a one- or
two-sentence reason. `tests/test_profile_coverage.py` enforces this: every
registered tool must appear in a profile or here, and every id listed here
must be a registered tool.

There are currently no such tools.

## Adding a profile

See "Adding a profile" in [`CONTRIBUTING.md`](../CONTRIBUTING.md) for
the how-to.
