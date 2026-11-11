"""Per-engagement budget for credential submissions against one
guessable surface.

This exists for one tool risk: repeated failed logins can lock a real
account, and a lock cannot be undone from the harness. The model can't
know in advance how many attempts a given application or domain
allows before it locks, so every endpoint gets a fixed TOTAL_BUDGET
across the *whole engagement*, not just its first call -- several
individually-small calls adding up to an unbounded total against one
account is exactly the risk a first-call-only cap misses: a real
engagement run against hydra showed a per-call cap alone did not stop
a real account lockout.

An endpoint is any hashable key the caller chooses to represent one
guessable surface: (host, port, service, form path) for a web login
(hydra), or a domain for a Kerberos password spray (kerbrute_spray,
where every call sends exactly one guess per account in its wordlist
-- the call itself, not a per-username count, is the unit this budget
caps). Two different login forms on the same host are tracked
separately; so are two different tools' calls against the same
endpoint, since the ledger instance is shared across every credential-
submitting tool for one engagement (see tradecraft/execution/loop.py).

When wired in, the ledger is created once per engagement, so its state
is run-scoped.
"""
from __future__ import annotations

from typing import Dict, Hashable, Tuple

TOTAL_BUDGET_PER_ENDPOINT = 5


class CredentialLedger:
    def __init__(self, total_budget: int = TOTAL_BUDGET_PER_ENDPOINT) -> None:
        self._cap = total_budget
        # endpoint -> attempts actually sent so far against it, across
        # every call and every tool sharing this ledger.
        self._sent: Dict[Hashable, int] = {}

    @property
    def total_budget(self) -> int:
        return self._cap

    def remaining(self, endpoint: Hashable) -> int:
        return max(0, self._cap - self._sent.get(endpoint, 0))

    def allow(self, endpoint: Hashable, requested: int) -> Tuple[int, bool]:
        """Return (attempts_to_run, capped): requested, clamped to what
        remains of this endpoint's total engagement budget. A fully
        spent endpoint returns (0, True) for every later call."""
        remaining = self.remaining(endpoint)
        if requested > remaining:
            return remaining, True
        return requested, False

    def record(self, endpoint: Hashable, attempts: int) -> None:
        """Count attempts that were actually sent. Zero (e.g. the binary
        rejected its own arguments before sending anything) doesn't
        consume budget."""
        if attempts > 0:
            self._sent[endpoint] = self._sent.get(endpoint, 0) + attempts
