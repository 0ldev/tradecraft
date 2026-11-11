# Contributing

## Adding a tool

A tool in Tradecraft is five small pieces glued together: an adapter that
shells out and parses output, a YAML contract the model sees, a thin
`Tool` subclass, a registry entry, and tests. There is no plugin system
and no separate packaging step — everything lives in-tree so one test
(`tests/test_tool_schema_completeness.py`) can enforce that every tool's
contract is complete. Follow the steps below in order; each one builds
on the last.

We'll use `cero` (Certificate Transparency subdomain discovery) as the
running example — it's one of the simplest tools in the repo and a good
template to copy from. Or skip the copying: `scripts/new_adapter.py
<tool_id>` generates all five pieces below, pre-filled in the safe
shapes this doc describes.

### 1. Adapter — `tradecraft/adapters/<tool>/`

Two files, strictly separated:

- **`execute.py`** — builds the subprocess argv, runs it, returns a raw
  result. No parsing logic here beyond stripping/splitting raw output
  into lines or similar. Handle `FileNotFoundError` (binary missing) and
  `subprocess.TimeoutExpired` explicitly and return them as an `error`
  field rather than raising — exceptions from `run()` are only for truly
  unexpected failures.
- **`parse.py`** — pure functions, no I/O. Takes the raw output and
  returns clean, deduplicated, structured data. Must be independently
  testable against captured real output, not just hand-typed fixtures.

```python
# tradecraft/adapters/cero/execute.py
@dataclass
class RawCeroResult:
    domains: List[str] = field(default_factory=list)
    error: Optional[str] = None

def execute(target: str, timeout: int = 120) -> RawCeroResult:
    ...  # subprocess.run(["cero", clean_target], ...), catch errors, return raw lines

# tradecraft/adapters/cero/parse.py
def parse_domains(raw_domains: List[str], target: str) -> List[str]:
    ...  # normalize, dedupe, sort — pure function, no subprocess calls
```

If your tool mutates target state irreversibly (creates accounts,
writes files to the target, locks out credentials, etc.), its adapter
must hard-cap its own worst case — bounded attempts, wordlist size,
output size, runtime — regardless of the `destructive` flag below. The
flag controls whether the model can see the tool at all; it is never a
substitute for the adapter containing its own blast radius.

If your tool talks to a cloud-provider metadata/IMDS endpoint
(`169.254.169.254`, `metadata.google.internal`, etc.) or any other
address that resolves differently depending on which machine asks,
never issue that request directly from wherever Tradecraft itself runs —
it leaks the operator's own credentials, not the target's. The only
legitimate path is relaying through something inside the target's own
environment (an SSRF sink, `kubectl exec`, etc.) — see
`tradecraft/adapters/cloud_metadata_credential_probe/execute.py`'s module
docstring. `tests/test_adapter_conventions.py` checks for a direct call
to one of these hosts and fails the build if it finds one.

### 2. Contract — `config/tools/<tool_id>.yaml`

This is the model-facing description — the only place `tool_id`,
`required_binary`, `scope_param`, `description`, and the parameter
schema are declared. Write the `description` as narrow and factual:
what the tool does, what inputs it needs. Don't put sequencing advice
("run this before X") in it — that belongs in a skill
(`tradecraft/skills/*.md`), and only add one if there's a genuine
tool-specific knowledge gap, not generic workflow advice.

```yaml
tool_id: cero
required_binary: cero
scope_param: target

description: >
  Discover subdomains by querying public Certificate Transparency logs
  for certificates ever issued to the target domain. Finds a different
  set of names than subfinder (DNS/passive-source aggregation) --
  catches short-lived, decommissioned, or otherwise undocumented
  subdomains. Purely passive -- never sends a request to the target
  itself.

parameters:
  type: object
  properties:
    target:
      type: string
      description: >
        Apex domain to query Certificate Transparency logs for, e.g.
        'example.com'.
  required: ["target"]
```

Every parameter your `run()` accepts must appear here with a
non-empty `description`, and vice versa —
`test_tool_schema_completeness.py` checks both directions and fails
the build if they drift.

If the tool is destructive (see [`docs/policy.md`](docs/policy.md)),
add `destructive: true` here, plus a
non-empty `destructive_categories:` list naming one or more of the six
fixed blast-radius categories that doc describes (`account_lockout_risk`,
`state_mutation`, `code_execution`, `credential_or_secret_exposure`,
`persistent_artifact`, `availability_risk`) — `tests/test_destructive_categories.py` enforces
that every destructive contract declares at least one known category,
and `tradecraft/tools/spec_loader.py` raises at runtime if it's missing.
Pick every category that genuinely applies, not just the most obvious
one — e.g. a tool whose cleanup is only best-effort (a write-then-delete
probe where the delete can fail) needs `persistent_artifact` alongside
`state_mutation`, not instead of it. Otherwise this is the only thing
that changes: the tool stays fully registered and contract-complete
like any other, it's just excluded from the model-facing tool set
unless the operator passes `--allow-destructive` (every destructive
tool) or `--allow-destructive-categories` (only tools whose categories
are all covered) at launch.

### 3. Tool glue — `tradecraft/tools/<tool>.py`

A thin `Tool` subclass. `tool_id` plus `run()`, which calls the
adapter's `execute()` then `parse()` and returns a plain dict. No
subprocess or parsing logic belongs here — if you find yourself writing
either, it belongs in step 1 instead.

Import the function straight from its submodule, as below — never
`from tradecraft.adapters.<tool> import execute` and never `import
tradecraft.adapters.<tool>.execute as x`. Every adapter's `__init__.py`
re-exports `execute` (and sometimes `parse`) under the same name as its
submodule, which rebinds that name from the submodule to the function —
either of the two forms above then silently hands back the function
where you may have wanted the module, and `tests/
test_adapter_conventions.py` fails the build if it happens.

```python
from tradecraft.adapters.cero.execute import execute as cero_execute
from tradecraft.adapters.cero.parse import parse_domains as cero_parse_domains
from tradecraft.tools.base import Tool

class Cero(Tool):
    tool_id = "cero"

    def run(self, target: str) -> Dict[str, Any]:
        raw = cero_execute(target)
        if raw.error:
            return {"target": target, "domains": [], "error": raw.error}
        domains = cero_parse_domains(raw.domains, target)
        return {"target": target, "domains_found": len(domains), "domains": domains}
```

Override `extract_evidence()` / `extract_facts()` (see
`tradecraft/tools/base.py`) only if the default behavior doesn't fit.

#### Facts — `extract_facts()`

Default is `[]`. Override it when your tool reports something about a
specific `(host, port)` that later tool calls (yours or another tool's)
should be able to see without re-reading the whole transcript — the
`FactStore` (`tradecraft/memory/facts.py`) is deduplicated, last-write-wins
per field, keyed on `(host, port)`. Each dict you return needs `"host"`
and `"port"`; every other key is a field merged onto that record.

```python
# tradecraft/tools/nmap_scan.py
def extract_facts(self, params, result) -> List[Dict[str, Any]]:
    host, _ = nmap_execute.parse_host_port(params.get("target", ""))
    ev_id = result.get("evidence_id")
    facts = []
    for p in result.get("ports", []):
        f = {"host": host, "port": p["port"], "state": p.get("state"),
             "service": p.get("service"), "version": p.get("version")}
        if ev_id:
            f["evidence"] = ev_id
        facts.append(f)
    return facts
```

If a fact is itself a finding-grade observation (e.g. a confirmed
vulnerable misconfiguration), it's still just a fact — don't try to
call `log_finding` from inside the tool. Facts are mechanical,
written straight from parsed output; findings stay something only the
model asserts, citing a fact/evidence id as backing.

#### Evidence — `extract_evidence()`

The base class already handles the common case: if a successful result
dict has a target/url/host/domain/ip param, it offloads the whole
result dict under that target in `EvidenceStore`
(`tradecraft/memory/evidence.py`) and you don't need to override anything.

Override it when the data worth keeping isn't the result dict you
already return to the model — e.g. the full raw output is too large or
differently shaped to put in the conversation, so you stash it under a
private key and strip it before returning:

```python
# tradecraft/tools/dns_axfr.py
def run(self, target: str) -> Dict[str, Any]:
    ...
    res["_full_evidence"] = {"target": target, "raw": {ns: r.stdout for ns, r in raw.items()}}
    return res

def extract_evidence(self, params, result) -> Tuple[str, Any] | None:
    target = params.get("target", "")
    full = result.pop("_full_evidence", None)  # pop so it never reaches the model
    return (target, full) if (target and full is not None) else None
```

Return `None` when there's nothing worth persisting (e.g. memory tools
like `log_note`/`log_finding` already opt out this way in the base
class — don't persist a tool's own bookkeping as if it were target
evidence).

Evidence and fact extraction are independent — a tool can override
either, both, or neither, and fact extraction can still read
`result["evidence_id"]` (set by the loop after `extract_evidence()`
runs) to attach an evidence pointer to a fact, as both examples above
do.

### 4. Register — `tradecraft/tools/registry.py`

Add an import and an entry in `ALL_TOOLS`. A tool only exists as a
capability if it's registered here *and* has a matching YAML contract —
neither one alone is enough.

A newly registered tool must also end up in at least one profile it is
genuinely relevant to — see the classification guide in
[`docs/profiles.md`](docs/profiles.md). If no profile fits, it needs a
documented exclusion in the "Tools intentionally outside every profile"
section of `docs/profiles.md` instead. `tests/test_profile_coverage.py`
enforces this automatically.

Regenerate `docs/tool-list.md` (`.venv/bin/python scripts/gen_tool_list.py`)
so the reference table picks up the new tool — `tests/test_tool_list_coverage.py`
enforces that it doesn't drift from `ALL_TOOLS`.

If the tool declares a `required_binary`, it must also be installed in
the `Dockerfile` (the `slim`/`web`/`full` stage matching the profile(s)
it's in — see `docs/setup.md`), or it will silently report
`is_available() == False` in every container build and never actually
be offered to the model in the documented way to run Tradecraft. Nothing
catches this outside a real container build —
`tests/test_container_tools.py::test_web_profile_tools_available`
checks it, but only when actually run inside one (`TRADECRAFT_CONTAINER_TEST=1`
or `/.dockerenv` present), which is easy to skip by accident. This
exact gap went unnoticed for `hydra` for its entire existence.

### 5. Tests

Mock the subprocess call in the adapter test; test argv construction
and parsing against real captured tool output, not hand-typed
fixtures. If the tool is destructive, its tests must exercise the
adapter/tool directly (the runtime gate doesn't apply at the unit-test
layer), and any CLI/integration test asserting its availability must
pass `--allow-destructive` explicitly.

### 6. Verify

```bash
.venv/bin/python -m pytest -v
```

Confirm `test_tool_schema_completeness.py` passes — it's the thing
standing in for a plugin registry's "manifest validation," and it's
non-negotiable. `test_adapter_conventions.py` is the same kind of
non-negotiable check, for the import-shadowing and metadata-hazard
rules noted above — if it fails, fix the import shape or remove the
direct-query mode, don't silence the test.

## Adding a profile

See [`docs/profiles.md`](docs/profiles.md) for what a profile is, why
they're allowed to overlap, and how to decide which tools belong in
one. The mechanics:

1. Create `config/profiles/<profile_id>.yaml`:

   ```yaml
   profile_id: <profile_id>
   description: >
     One or two sentences: what engagement shape this is for.
   tool_ids:
     - some_tool
     - another_tool
   ```

2. That's it — profiles are auto-discovered by `tradecraft/tools/
   profiles.py`'s `list_profiles()`/`load_profile()` globbing
   `config/profiles/*.yaml`. There's no central registry file to
   update (unlike a tool's `ALL_TOOLS` entry).
3. Every `tool_id` listed must already be registered in
   `tradecraft/tools/registry.py`'s `ALL_TOOLS` —
   `tests/test_profiles.py::test_every_profile_tool_id_exists_in_all_tools`
   enforces this and will catch a typo or a stale id left behind after
   a tool is renamed/removed.
4. Don't worry about duplicating tool ids already listed in another
   profile — that's expected, not a smell.

## Adding a wordlist

`config/wordlists/` holds the bundled lists `tradecraft/adapters/wordlists.py`'s
`resolve_wordlist()` resolves by name (with or without extension) for any
adapter that needs one (`ffuf`, `ffuf_vhost`, `kiterunner`, `kerbrute`,
`kerbrute_spray`).

1. Add the file to `config/wordlists/`.
2. Wire it into the relevant tool's `wordlist`/`user_wordlist` parameter
   in `config/tools/<tool_id>.yaml`: add its name (without extension) to
   that parameter's `enum:` list, and extend the `description` with a
   one-line note on what it's for and when to prefer it over the
   existing options — not just that it exists. A bare name with no
   use-case guidance leaves the model no way to choose between options
   it can already see.
3. `tests/test_wordlist_consistency.py` enforces both directions: every
   enum value must resolve to a real file here, and every file here
   must be referenced by some adapter's source or a tool contract's
   `enum:` — an unreferenced file is exactly as much a bug as a typo'd
   enum value, since nothing else will ever catch either one.
4. If the content comes from an external source rather than being
   original to this project, add a row to
   [`config/wordlists/ATTRIBUTION.md`](config/wordlists/ATTRIBUTION.md)
   naming the source and its license, and confirm that license actually
   permits redistribution before bundling anything.

### Before opening the PR

1. Run `pytest` and include the output.
2. Review your own diff against this document's architecture layering.
3. If a test fails and you can't fix it, or the task is ambiguous, say
   so rather than opening the PR anyway.
