# Policy

`tradecraft/policy/` holds the small, pure modules that decide what the
model is *allowed* to do, as opposed to what a tool's adapter knows how
to do. Both of today's modules are static, pre-run decisions, never a
mid-run prompt — that's deliberate, not an accident of how they happen
to be implemented.

## Destructive tools

A tool that can mutate target state in a way that doesn't undo itself
— account lockouts from credential brute-forcing, a planted webshell,
data deletion — is **destructive**, regardless of whether it looks like
"recon" or "exploitation." Its contract declares `destructive: true`.

Destructive tools stay fully registered with a complete contract like
any other tool. What changes is runtime availability: they're excluded
from the model-facing tool set by default, and only become available
when the operator opts in before the engagement starts
(`tradecraft/policy/destructive.py`).

That opt-in controls *availability*, not a destructive tool's internal
blast radius. Every adapter — destructive or not — still hard-caps its
own worst case (attempts, wordlist size, output size, runtime)
regardless of whether it's available.

### Two ways to opt in

**`--allow-destructive`** is the original, coarse switch: every
destructive tool becomes available, regardless of what kind of risk it
carries.

**`--allow-destructive-categories cat1,cat2`** is the finer-grained
alternative, for an operator who wants (for example) RCE-confirmation
tools available but not credential-dumping ones. Every destructive
tool's contract declares a non-empty `destructive_categories:` list —
one or more of six fixed blast-radius categories:

- **`account_lockout_risk`** — repeated credential guesses where volume
  against one account/endpoint matters (e.g. `kerbrute_spray`).
- **`state_mutation`** — a real write/delete/update to application or
  cloud data that *is* the point of the check (e.g. `csrf_probe`,
  `price_manipulation_probe`). Distinct from `persistent_artifact`
  below: this is one auditable, expected mutation, not something extra
  left behind by accident.
- **`code_execution`** — confirmed or attempted remote code execution
  on the target (e.g. `deserialization_probe`, `redis_rce_exploit`).
- **`credential_or_secret_exposure`** — the tool obtains or exfiltrates
  real secret or credential-equivalent material (hashes, tokens,
  certs, temporary cloud credentials), or bypasses auth to access
  another identity's protected data (e.g. `secretsdump`,
  `identity_auth_bypass`).
- **`persistent_artifact`** — the tool leaves something behind on the
  live target that isn't guaranteed to be cleaned up and may need
  manual removal (e.g. `webshell_upload`'s planted shell;
  `bucket_permission_exploit`'s and `kubectl_exploit`'s write-probe
  cleanup, which is attempted but can fail, leaving an orphaned object
  or ConfigMap behind).
- **`availability_risk`** — the tool risks crashing, hanging, or
  otherwise destabilizing the target as a side effect of exploitation,
  not as the point of the check (e.g. `kernel_privesc_exploit`).
  Distinct from `state_mutation`: that category covers an intended,
  auditable mutation, while this risk is unintended and can't be
  verified or cleaned up after the fact.

A tool declaring more than one category needs **every one of them**
opted into before it's available — opting into just one category a
multi-category tool happens to have is not enough. For example
`netexec_exploit` declares both `code_execution` and
`credential_or_secret_exposure`: `--allow-destructive-categories
code_execution` alone does not unlock it.

If `--allow-destructive` is passed, `--allow-destructive-categories` is
irrelevant — the coarse flag already allows everything. The two flags
are otherwise independent and both static, pre-run choices; neither is
ever a mid-run prompt.

`ticketer` is a genuine edge case worth calling out: it forges a
Kerberos golden ticket entirely offline from an already-captured
krbtgt hash, with zero live contact with the target. None of the six
categories describe risk from *running* the tool — but its *output* is
domain-admin-equivalent forged credential material, so it's still
classified `credential_or_secret_exposure`.

### The account_lockout_risk budget

`account_lockout_risk` is backed by a real enforcement mechanism, not
just a label: `tradecraft/policy/credential_budget.py`'s `CredentialLedger`
gives every guessable surface (a login endpoint for `hydra`, a domain
for `kerbrute_spray`) a fixed total attempt budget for the whole
engagement — not just its first call. `hydra` and `kerbrute_spray`
share one `CredentialLedger` instance per engagement — one shared
instance, not one shared budget: each tool's own endpoint-key shape (a
4-tuple for `hydra`, a bare domain string for `kerbrute_spray`) means
their budgets don't actually collide today, but any future credential-
submitting tool gets the same protection for free just by sharing this
ledger too. Once an endpoint's budget is spent, further calls against
it run zero attempts regardless of what the model asks for; each
result's `budget` field reports what remains.

The total itself (`TOTAL_BUDGET_PER_ENDPOINT`, default 5) is an
operator-level choice, not a tool parameter: `--credential-budget N`
sets it once before the engagement starts, same static pre-run shape
as `--allow-destructive`. It is deliberately not exposed to the model
— the model already controls `max_attempts` per call, and that alone
was not enough to prevent a real lockout (see below), so the backstop
has to live somewhere the model can't also configure its way past it.

This budget applies to *every* candidate submitted through `hydra`/
`kerbrute_spray`, regardless of where the candidate came from —
`cewl`/`cupp` (see `tradecraft/skills/credential_wordlist_generation.md`)
generate smarter candidates than the bundled defaults, but generating
them costs nothing against this budget; only submitting one through
`hydra`/`kerbrute_spray` does.

Two limitations are still real, even with the budget enforced:

- It tracks per *endpoint* (host/port/service/form for `hydra`, domain
  for `kerbrute_spray`), not per *account*. Guessing against several
  different usernames at the same login form shares one budget, which
  is conservative for any one account but doesn't isolate them from
  each other.
- Detecting an actual lock still depends on the model reading each
  tool's response — neither tool's output reliably distinguishes a
  lock from an ordinary failed guess. A real engagement run against
  `hydra` hit exactly this: a login form returned a disabled-account
  message that nothing in hydra's own output surfaced as a lock.
