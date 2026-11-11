# Destructive-tool sequencing

Prefer the cheapest signal before the costliest action, within whatever
tool set is active. Running a destructive tool (an exploit
attempt, anything the model can tell mutates target state from its own
contract's description) before confirming the thing it targets actually
exists wastes the one shot a lockout-prone or loud action usually gets.

- If a non-destructive tool already answers "is this worth trying" --
  sqlmap/dalfox confirming an injectable parameter before an exploit
  chain targets it, cloudenum/whatweb confirming real cloud infra
  before form_fuzzer's SSRF-to-metadata probe -- run that first.
- Before calling `auth_bootstrap` to register a throwaway account, confirm
  that the application exposes public user registration (e.g. check URLs
  discovered by `katana`/`subjs`/`linkfinder` or inspect page content via
  `http_request` for registration forms/links). If custom endpoints were
  discovered, supply `register_path` and `login_path` explicitly to guide
  the registration attempt instead of relying solely on generic guesses.
  After a successful call, its `session_token` is NOT merged into Known
  Facts (it's a credential, not a (host, port) fact) -- carry it forward
  yourself: pass it as a `Cookie`/`Authorization` header via
  `http_request`'s or `corsy`'s `headers` parameter wherever an
  authenticated request is needed, and `log_note` the token/email so it
  survives context trimming instead of only existing in this turn's
  result.
- Before calling `netexec_exploit` for SMB execution/credential dumping,
  confirm via `netexec_enum` first that the supplied credentials actually
  authenticate and that a reachable share/host exists -- same
  enum-before-exploit shape as `kerbrute`/`powerview`: confirm the target
  first, then spend the destructive attempt.
  `netexec_exploit` against credentials or a host `netexec_enum` hasn't
  already confirmed is spending the destructive attempt on an unverified
  guess.
- Before submitting credentials to a login endpoint, verify that the endpoint
  is reachable and has no blocking CAPTCHA or lockout controls (via
  `httpx_probe` or a single `http_request` check). Prefer explicitly
  enumerated usernames (such as administrative emails discovered in leaked
  endpoints, or Active Directory accounts enumerated non-destructively via
  `kerbrute` or `powerview`) over generic dictionaries, and keep the number
  of attempts small.
- Any login submission counts toward lockout, whichever tool sends it. A
  manual `http_request` POST to a login form is as lockout-prone as any
  automated guessing, and each one spends the same account's failure budget. If a login
  response says the account is locked, disabled, or temporarily suspended
  (for example "sua conta está desativada temporariamente" or "account
  locked"), stop submitting credentials to that login endpoint for this
  engagement, `log_finding` the lockout as observed, and do not retry the
  same account from another tool or with different passwords. Likewise, a
  CAPTCHA appearing on the login form means stop automated guessing there.
  Without a lock message, keep the number of attempts small, and make any
  further attempt against the same account only for a specific reason tied
  to evidence (for example a username found in a leaked file), `log_note`ing
  the running attempt count for that account.
  A credential that a tool reports as a hit is not a confirmed login: verify
  it with a single request that shows an authenticated-only response before
  treating it as valid.
- Before calling `fastcgi_exploit`, verify via `nmap_scan` or `tcp_probe` that
  a FastCGI service (typically TCP port 9000) is open and reachable on the host.
  Do not run `fastcgi_exploit` against general HTTP/HTTPS web ports (80/443);
  it speaks raw FastCGI binary framing directly to exposed PHP-FPM daemons.
- Before calling `phpggc`, confirm the parameter or cookie you intend to send
  is one the target actually passes to `unserialize()` (a value that decodes to
  a PHP serialized `O:`/`a:` structure, or a framework endpoint known to
  deserialize it), and pick the chain matching the confirmed framework/version
  (`framework`, or an exact chain name). A chain for the wrong library fails
  silently -- the response looks clean even though the sink is real. Where
  `php_lfi` can read the PHP source behind a suspected endpoint
  non-destructively, that is often the cheapest way to confirm `unserialize()`
  is called on the input before spending the gated attempt.
- Before calling `laravel_exploit`, confirm the target is actually Laravel
  (`laravel_session` or `XSRF-TOKEN` cookies, `/vendor/laravel` paths,
  Ignition debug output) and that the APP_KEY in hand is the target's real
  key (from a leaked `.env`, backup, debug page, or JS config). A wrong key
  is simply rejected by Laravel -- it looks exactly like a non-vulnerable
  app -- so a guessed key only spends the gated attempt. This tool is the
  APP_KEY-specific path; `phpggc` already covers a directly reachable
  `unserialize()` sink without needing the key.
- Before calling `sqli_login` to attempt an authentication bypass, confirm via
  `httpx_probe` or `katana` that an interactive login form exists on the endpoint.
  If specific input field names were discovered in the form HTML (e.g. `user`, `email`),
  pass `username_field` explicitly. If `sqlmap` has already tested the login form and
  reported it clean, avoid re-running tautology bypasses on the same form unless a
  different parameter or injection point is being evaluated.
- Before calling `mass_assignment_probe`, confirm the endpoint's normal
  baseline request/response shape with a plain `http_request` first (or
  reuse a request you've already seen succeed). Each candidate field
  not already in your baseline body spends one of the gated writes; a
  guess at the wrong body shape wastes the attempt on a request the
  endpoint would have rejected anyway regardless of mass assignment.
- Before calling `csrf_probe`, confirm you already have one request that
  succeeds with a valid token for that endpoint (via `http_request` or
  prior recon). Without that baseline, a "vulnerable" result from the
  two gated attempts (token removed, token replaced) can't be told apart
  from the endpoint simply rejecting malformed requests in general.
- Before calling `price_manipulation_probe`, confirm with a normal
  request (e.g. via `http_request`) that the unmodified baseline body
  actually succeeds against the checkout/cart/order endpoint first. A
  "vulnerable" result from a tampered variant is only meaningful once
  you know the endpoint accepts the untampered request at all --
  otherwise a rejected tamper attempt could just be a broken endpoint,
  not a validated finding.
- Before calling `email_header_injection_probe`, confirm the contact
  form's normal baseline submission actually succeeds first. Delivery
  of the injected Bcc is never confirmed by this tool itself -- treat
  an "accepted" result as "the header was not rejected," and check the
  marker mailbox separately (e.g. with `mail_access_probe`, if you
  control it) before reporting the Bcc as a confirmed exfiltration path.
- Before calling `redis_rce_exploit`, confirm with the non-destructive
  `unauth_datastore_probe` (service 'redis') that the server is reachable
  and actually unauthenticated: a NOAUTH/NOPERM server is rejected by the
  exploit's PING anyway, so skipping the probe just spends a connection
  without learning anything. Then pick the least invasive method that
  proves code execution in this engagement's context (`module_load` when
  a module is already present, otherwise `cron`/`ssh_key`), and supply
  `write_dir`/`filename` when recon has already established the target's
  OS layout instead of letting the default candidates guess.
- Before calling `workflow_step_bypass_probe`, confirm the workflow's
  normal shape first: walk the legitimate steps (or replay a known-good
  request via `http_request`) so you have the exact later-step URL,
  method, body, and a real success marker from a completed run. Every
  call is one real write against live state, so a guessed body shape
  spends the only attempt on a request the endpoint would reject
  regardless of whether the step gate exists. Treat
  `accepted_unconfirmed` as a lead to verify with a follow-up read, not
  as a confirmed bypass.
- This is a preference, not a requirement: a destructive tool with
  strong standalone signal (a confirmed CVE with a known-exploitable
  version match) doesn't need an artificial non-destructive step first
  just to satisfy this ordering. Judge each case; don't treat this as a
  checklist to tick through regardless of context.
