# SSRF and open-redirect parameter discovery

No Tradecraft tool flags which query parameters look like redirect or fetch
targets. `gau`, `katana`, and `linkfinder` surface crawled or historical
URLs, but they do not classify parameter names such as `redirect=`,
`url=`, `next=`, `dest=`, `return=`, `callback=`, or `src=`. `interactsh`
confirms an out-of-band callback only once a candidate URL and parameter
already exist to fire it at.

- When `gau`, `katana`, or `linkfinder` output contains a URL whose
  parameter name or value looks like a redirect or fetch target, the fit
  is `http_request` with that parameter's value replaced by an
  `interactsh`-generated callback URL, followed by an `interactsh` poll
  for a hit.
- Only an interaction that arrives in direct response to the request just
  sent counts as a hit. Match the poll result's source and timing to that
  request before treating it as evidence the parameter is fetched or
  redirected server-side. `interactsh`'s own `poll` result computes this
  timing check for you on each interaction (`after_domain_generated`) --
  an interaction with `after_domain_generated: false` predates the
  payload domain's own creation and cannot have been caused by anything
  sent during this engagement, full stop, regardless of how close the
  timestamps might otherwise look. Trust that computed field over manual
  timestamp arithmetic.
- A parameter that looks like a target but is only reflected in the
  response body, with no callback, is not an SSRF or open-redirect
  finding by itself.
- **Direct Cloud Metadata SSRF Confirmation (`form_fuzzer`):**
  When candidate URL fetch parameters or HTML forms are discovered on targets operating on cloud infrastructure (e.g. AWS EC2/ECS, Azure App Service/VM, GCP Cloud Run/Compute), sequence `form_fuzzer` with `target` (and optionally `internal_url` or `target_param`). `form_fuzzer` probes form inputs and query parameters against instance metadata services (`http://169.254.169.254/latest/meta-data/`) to confirm whether the server fetches and reflects internal cloud instance identity, tokens, or configuration. Where practicable, verify SSRF callback responsiveness via `interactsh` first.
