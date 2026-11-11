When tools collect voluminous output (such as `testssl`, `httpx_probe`, or `gau`), high-level summaries
are returned in the conversation turn, while complete records are saved to the run's evidence store.
A durable pointer is attached to KNOWN FACTS (e.g. `evidence=testssl:<target>` or `evidence=httpx_probe:<target>`).

- Use `read_evidence(target, tool_id)` ONLY for single-asset deep dives where the data is naturally bounded
  (e.g., viewing complete TLS ciphers from `testssl`, raw HTTP response headers/cookies from `httpx_probe`, or full CMS findings from `wpscan`).
  Do NOT use `read_evidence` to dump bulk multi-thousand-line discovery outputs (such as `gau`, `katana`, or `subfinder`), as doing so floods the context window with raw URLs and degrades reasoning speed.
- **Hydration Discipline & Avoiding Redundant Reads:**
  When `read_evidence(target, tool_id)` or `search_evidence(query, target)` returns relevant findings, record a concise finding via `log_finding` or summarize key details in a `log_note`. Do NOT repeatedly call `read_evidence` for the exact same target and tool across subsequent turns unless paging through distinct offsets; re-reading already-hydrated evidence wastes turn budget and produces redundant loops.
- Use `search_evidence(query, target)` to query specific strings, paths, file extensions (e.g. `.php`, `.json`, `api`, `admin`, `login`), HTTP headers (e.g. `Set-Cookie`, `Server`, `Location`), or parameter names across all saved evidence without re-scanning or flooding context.
- `search_evidence` matches up to 50 results and truncates lines over 200 characters; specify `target`
  or a more specific query if matches are omitted.
- Subdomain evidence lookups: `read_evidence` and `search_evidence` automatically normalize target keys
  across subdomain relationships. Querying a subdomain (e.g. `mail.target.com`) for bulk recon tools
  (`httpx_probe`, `dnsx`, `subfinder`, `subzy`) automatically resolves and extracts matching records
  from parent evidence (e.g. `target.com/httpx_probe.json`), eliminating "no evidence found" lookup misses.
- `http_request`'s own result carries `body_truncated: true` whenever a fetched body (e.g. a large minified
  JS bundle or a verbose REST API index) got cut off in the conversation. When that flag is set and the full body actually matters:
  - If searching for routes, keys, or patterns across saved responses, use `read_evidence`/`search_evidence` against that same `evidence_id` to get the untruncated content without re-requesting the host.
  - For sequential streaming of bulky responses, pass `body_offset=<next_body_offset>` into subsequent `http_request` calls.
- **Bulky REST Indexes & API Schemas (`http_request`, `search_evidence`):**
  When discovering large REST root catalogs (e.g. WordPress `/wp-json/`, Swagger/OpenAPI JSON, or GraphQL schemas) where the initial index is truncated, do not guess obscure routes blindly or drown context dumping the full raw JSON. Use `search_evidence(query="/wp/v2/", target=...)` or search for specific namespaces (e.g. `users`, `routes`, `schema`, `v1`, `v2`, `admin`) to extract candidate endpoints from the saved evidence, then probe the targeted sub-resource endpoint directly (e.g. `/wp-json/wp/v2/users`) via `http_request`.
- **Route & Parameter Hydration (`katana`, `linkfinder`, `arjun`):**
  When `katana` or `linkfinder` reports discovered API routes or parameters with omitted items (`omitted_endpoints` or `omitted_parameters`), do not guess endpoints in the dark. Call `search_evidence` (querying for `/api/`, `/v1/`, `json`, or specific controller paths) or call `read_evidence` once for focused single-host crawls to inspect the full route list. When parameter miners (like `arjun` or `katana`) identify hidden or reflection parameters, hydrate the parameter names via `read_evidence` before deciding injection payloads (`sqlmap`, `dalfox`, `tplmap`, `commix`). Candidate endpoints with parameters are prime targets for `arjun` parameter discovery, `corsy`, and injection testing.
- **Email Spoofing Posture & Mail Probing (`email_auth_posture`, `smtp_probe`, `mail_access_probe`):**
  `email_auth_posture` (SPF/DMARC/DKIM policy scoring, pure DNS), `smtp_probe` (live SMTP banner/STARTTLS/VRFY on ports 25/587), and `mail_access_probe` (IMAP/POP3 capabilities and cleartext auth audit on ports 143/993/110/995) inspect different layers of email infrastructure. Run `smtp_probe` for mail routing/MTA ports and `mail_access_probe` whenever mail retrieval ports are open; neither supersedes the other.
- **GitHub Dork Secret Verification (`gitdorker`, `trufflehog`):**
  A `gitdorker` "secret"-type finding is a matched dork pattern on a URL, never retrieved file content -- fetch the URL (`http_request`) or, if the match is on a full repository, run `trufflehog(target=<repo_url>, scan_git_history=true)` directly to walk its complete commit history before treating it as a confirmed leak, the same discipline `linkfinder`'s candidates require.
- **Cross-Engagement Historical Recall (`recall_memory`):**
  While `read_evidence` and `search_evidence` inspect raw tool output from the *current* run, `recall_memory(query, target, kind)` searches across *all historical engagements* for verified findings, service facts, and notes. After fingerprinting a target's tech stack, CMS, framework, or WAF (via `httpx_probe`, `whatweb`, `webanalyze`, or `wafw00f`), call `recall_memory` with the detected product/version or technology pattern to see what vulnerabilities, misconfigurations, or bypasses succeeded on prior assessments.
