When `wafw00f` reports a WAF/CDN positive for a target, that fact is
merged into Known Facts (`waf=<name>`) and stays there for the rest of
the engagement -- treat it as binding context for every other tool's
results against that target, not just a one-off note at the moment it
was detected.

- A 403/406/503, dropped connection, or odd response from `httpx_probe`
  or `whatweb` against a WAF-fronted host is probably the edge talking,
  not the origin app. Don't conclude the endpoint is absent or broken
  from that alone, and don't retry the same probe expecting a different
  answer -- the edge, not the app, decided that response.
- `testssl` against a WAF-fronted target usually negotiates TLS with the
  edge, not the origin. Note whose certificate/cipher data you're
  actually looking at before drawing conclusions about the real server.
- Prefer finding and testing an un-fronted origin over spending further
  effort against the edge itself: check `subfinder` output and other
  resolved hosts for the same organization for a sibling target that
  resolves direct, with no WAF/CDN reported. Once an un-fronted origin
  IP or URL is discovered (e.g. via CSP headers, CNAME chains, or cloud
  service hostnames), immediately redirect web application scanners
  (`wpscan`, `nuclei`, `sqlmap`, `dalfox`) to target that origin directly
  instead of continuing to scan the CDN/WAF-fronted hostname.
- When a target is fronted by a WAF/CDN, `favicon_correlator` computes its
  favicon MurmurHash3 and queries Shodan's index to uncover un-fronted origin
  IPs and related infrastructure sharing the same favicon deployment -- try
  it when header-based leak techniques (such as CSP frame-ancestors) have
  not surfaced a direct IP yet.
- A broad `nmap_scan` sweep against a WAF-fronted host is more likely to
  trip edge rate-limiting than to reveal the origin's real port/service
  surface -- breadth there is lower-value than breadth against a direct
  target.
