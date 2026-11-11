# Second-order (stored) injection testing

No Tradecraft tool revisits a different rendering context after planting a
payload. `dalfox`, `commix`, `xxe_probe`, and `phpggc` each test for
injection in the same response the payload-carrying request produces --
none of them check whether a payload that gets no hit there still
renders unescaped somewhere else later (an admin/moderation panel, an
exported report, a notification view, a different user's dashboard).
That gap is a sequencing fact, not a missing capability: the planting
tool and the revisit are both already covered individually.

- `dalfox` only tests reflected contexts in the same response it sends --
  a payload that gets no hit there may still fire somewhere else. After
  planting a marker payload via a profile-bio, contact-form, or similar
  stored-input field (with `http_request`, `form_fuzzer`, or `dalfox`
  itself against the planting endpoint), revisit any admin/moderation
  panel, export, or notification view discovered via `katana`, `gau`, or
  `gowitness` with `playwright_engine` or `spa_crawl` to check whether
  the marker renders unescaped there instead.
- A filename, uploaded via `webshell_upload`-adjacent form flows or any
  endpoint that accepts a file name as user input, is a plant point too
  -- the filename itself (not just the file's content) can carry a
  payload that only renders when a later admin-facing file listing
  displays it.
- An HTTP header value accepted by the target (tested via
  `http_request`, `crlf_injection_probe`, or similar) can be a plant
  point: a `User-Agent` or `Referer` string stored in an access log is a
  classic second-order XSS vector once a log-viewing admin panel renders
  it without escaping.
- A payload with no hit anywhere after a reasonable revisit is a
  negative result, not evidence the input is unreachable -- there may be
  a rendering context this engagement hasn't discovered yet. Don't treat
  a single revisit location as exhaustive.
