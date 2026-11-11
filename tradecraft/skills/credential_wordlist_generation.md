- **Prefer a profiled/scraped wordlist over the generic defaults when a
  target person or organization is known:** `cewl` (scrapes a target
  site's own text into organization-specific words) and `cupp`
  (profiles a specific person's OSINT details into tailored password
  candidates) exist specifically because `hydra`/`kerbrute_spray`'s own
  bundled defaults are generic top-1000-style lists. If a target
  organization's own jargon, product names, or a specific person's
  name/birthdate/company is already known (from a company "about us"
  page, an email signature, a social media profile, or similar), run
  `cewl` and/or `cupp` first and feed a handful of their most promising
  output words into `hydra`'s `password_list`/`username` or
  `kerbrute_spray`'s `password` parameter as a literal comma-separated
  list, rather than reaching straight for the bundled defaults.
- **Neither `cewl` nor `cupp` is destructive or budget-limited** --
  they only generate candidates locally (`cupp`) or make read-only GET
  requests (`cewl`). The account-lockout-risk budget
  (`docs/policy.md`) only applies once a candidate is actually
  submitted via `hydra`/`kerbrute_spray`/`sqli_login`, so generating a
  large candidate list costs nothing against that budget -- only
  picking a handful of the best ones to actually submit does.
