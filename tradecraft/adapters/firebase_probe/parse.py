"""
Pure parsing for firebase_probe: turns the raw per-project checks into the
dict the model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.firebase_probe.execute import RawFirebaseResult


def parse_firebase_result(raw: RawFirebaseResult) -> Dict[str, Any]:
    if raw.error:
        return {"error": raw.error}

    exposed = [c for c in raw.checks if c.rtdb_readable or c.firestore_readable]
    if not exposed:
        return {
            "reason": "no candidate project has a publicly readable Realtime Database or Firestore",
            "checked_count": len(raw.checks),
        }
    return {
        "exposed_projects": [
            {
                "project_id": c.project_id,
                "rtdb_readable": c.rtdb_readable,
                "rtdb_status": c.rtdb_status,
                "rtdb_body_snippet": c.rtdb_body_snippet,
                "firestore_readable": c.firestore_readable,
                "firestore_status": c.firestore_status,
            }
            for c in exposed
        ]
    }
