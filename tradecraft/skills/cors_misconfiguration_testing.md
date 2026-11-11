# CORS misconfiguration testing

`corsy` tests one URL at a time for CORS misconfiguration -- it does not
discover endpoints itself, and running it against every URL `ffuf`,
`katana`, or `gau` ever surfaced would be unbounded, noisy fan-out
against a real production host, not useful coverage.

- Run `corsy` only against endpoints that already look like they handle
  authenticated or sensitive cross-origin data -- API routes
  (`/api/...`), endpoints that `httpx_probe`/`katana` show returning
  JSON, or anything that already required a session cookie/auth header
  to reach. A static asset or a public marketing page has nothing a CORS
  misconfiguration would expose.
- If an endpoint needs a session to be meaningful to test (e.g. a
  logged-in API route), pass the session cookie via corsy's `headers`
  parameter rather than testing it unauthenticated and concluding
  nothing is wrong.
