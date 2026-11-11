# Parameter Triage & Sink Categorization

Crawling and archive tools (`katana`, `gau`, `linkfinder`) frequently surface dozens of query parameters across HTML source, scripts, and anchor tags. Treating every parameter as an equal target for heavy injection scanners wastes turn and token budget on non-sinks. Tradecraft operators and models prioritize candidate parameters by separating client-side and third-party artifacts from true server-side application sinks.

## 1. Recognizing Non-Sinks & Third-Party Artifacts

Many parameters extracted from page footers, embeds, and third-party widgets are not processed by the target server:

- **Third-Party Social & Chat Links:** Parameters embedded in off-site URLs (e.g. `api.whatsapp.com/send?phone=...&text=...` or `youtube.com/c/.../?sub_confirmation=1`) are delivered to external third-party servers. Probing them on the target application root produces false negatives or 404s.
- **CDN & Edge Diagnostic Artifacts:** Parameters like `ray=`, `cf_ray=`, or `s_fid=` are ephemeral CDN edge trace identifiers, not application input handlers.
- **Client-Side Analytics & Tag Manager Artifacts:** Parameters like `gtm.js?id=...` or static script version hashes (`v=`, `ver=`) are read solely by client-side browser scripts or serve cache-busting purposes.
- **Static Asset Queries:** Query parameters appended to images (`.png?w=200`), CSS (`.css?v=1.2`), or compiled bundles (`.min.js?hash=...`) do not route to dynamic server endpoints.

Do not route heavy SQLi, command injection, or SSRF probes to client-side or third-party artifacts. If all discovered parameters on a host fall into these categories, note the triage explicitly rather than spending turns fuzzing them.

## 2. Categorizing True Server-Side Sinks

When interactive parameters are discovered on target-owned application endpoints, match the parameter's semantic purpose to the corresponding tool:

1. **Database & Search Queries (`q=`, `query=`, `search=`, `keyword=`, `id=`, `cat=`, `filter=`):**
   - Candidate for SQL injection and Cross-Site Scripting (XSS).
   - Sequence `sqlmap(target=..., parameter=...)` and `dalfox(target=..., parameter=...)`.
2. **Navigation & Redirection Sinks (`redirect=`, `url=`, `next=`, `return=`, `return_to=`, `dest=`, `r=`):**
   - Candidate for Open Redirect and SSRF.
   - Sequence `open_redirect_probe(target=..., param=...)` or `http_request(url=..., follow_redirects=false)`.
   - Check if the HTTP response emits a 301/302/307/308 status code reflecting the untrusted destination in the `Location` header.
3. **Remote Resource Fetching & Webhooks (`src=`, `link=`, `feed=`, `callback=`, `domain=`, `host=`):**
   - Candidate for Server-Side Request Forgery (SSRF).
   - Sequence `ssrf_probe` or replace the value with an `interactsh`-generated callback domain, followed by `interactsh(action="poll")`.
4. **File System & Template Loading (`page=`, `file=`, `template=`, `view=`, `doc=`, `path=`):**
   - Candidate for Local/Remote File Inclusion (LFI/RFI) and path traversal.
   - Sequence `php_lfi(target=..., parameter=...)` or `path_traversal_probe`.

## 3. Fact Preservation & Thread Resolution

- When parameters are discovered by `katana` or `arjun`, the harness records `params_discovered` and `params_sample` in `Known Facts`.
- Testing a parameter with any matching probe tool (`sqlmap`, `dalfox`, `open_redirect_probe`, `ssrf_probe`, `nosql_injection_probe`) records durable tested status onto that host's record in `Known Facts`.
- Completing a cheap check against candidate parameters early ensures the testing record survives conversation context trimming on long engagements, preventing redundant re-probes or pre-finalization nudges later in the run.
