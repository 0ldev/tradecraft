# Single-shot tools' first positive deserves one re-confirmation

Several tools in this project are deliberately single-shot by design
-- no internal retries, no loop, exactly one (or a small fixed number
of) request(s) per call. That property exists to bound each call's
blast radius against a real target, not to express confidence about
any individual result. A tool's own description says so explicitly
when it applies (e.g. "single-shot," "no retries," "exactly N requests
per call") -- treat that phrasing as the trigger for this skill,
whichever tool it's on, including ones that don't exist yet.

- The first time, in a given engagement, that a single-shot tool
  returns a positive/concerning result against a specific target, run
  it again -- a second, independent call against the same target --
  before writing that result into `log_finding` or the final report.
  Confidence here comes from a second observation, not from retrying
  inside the tool (which the tool's own design deliberately doesn't do).
- This applies once per tool per engagement, not to every call: once a
  given single-shot tool's behavior against this target class has
  already been confirmed once this engagement, a second positive from
  the same tool doesn't need re-confirming again.
- This is a preference weighed against cost, not an unconditional
  rule: if the second call would meaningfully add further load to a
  target already showing signs of strain (rate-limited, slow to
  respond, or already flagged elsewhere in FACTS/HISTORY as fragile),
  it's reasonable to report the single observation as-is and say
  explicitly in the finding that it's unconfirmed by a second call and
  why -- an honest "unconfirmed, re-run skipped due to target load" is
  better than either silently skipping confirmation or confirming at
  real cost to a fragile target.
