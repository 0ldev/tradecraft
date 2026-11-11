Both `playwright_engine` and `spa_crawl` drive a real headless browser,
at real time cost -- don't run either against a page with nothing
dynamic to find (a static marketing page, a server-rendered page with
no client-side routing).

- `spa_crawl` is cheap and automatic: it fills every visible text input
  it finds and submits it, with no per-input judgment. Good for a quick
  first pass on an SPA to see what request shapes come out. It WILL
  trigger real side effects if a visible text input happens to belong to
  something consequential (a contact form, a newsletter signup, a
  password-reset email field) -- it has no way to know the difference.
  Don't run it against a page you've already identified as having a
  sensitive form you don't want to trigger; use `playwright_engine`'s
  explicit `actions` list there instead, where you choose exactly what
  gets filled and clicked.
- `playwright_engine` costs one more round of reasoning (you write the
  actions) but gives you that precision -- use it once you already know
  roughly what's on the page (from `spa_crawl`'s first pass, or from
  looking at a `gowitness` screenshot) and want to interact with a
  specific control deliberately, or confirm DOM-XSS on a specific input
  rather than every input on the page at once.
