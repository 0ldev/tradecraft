"""Bench runner: engagements against lab targets, scored automatically.

Config format (bench/labs/<name>.yaml):

    labs:
      - name: juice-shop-basic
        target: http://localhost:3000
        profile: web
        expected_findings:
          - id: sqli_login
            keywords: ["sql", "login"]
          - id: xss_search
            keywords: ["xss"]

Run:  python -m bench.run_bench bench/labs/mybench.yaml

Writes bench/results/<timestamp>.json (full) and .md (summary). The
harness never runs destructive tools and never overrides the operator's
--allow-destructive choices: labs run with the same defaults as a
normal engagement.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

from bench.scoring import efficiency, render_summary, score_findings

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def load_config(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"bench config not found: {p}")
    config = yaml.safe_load(p.read_text(encoding="utf-8"))
    labs = config.get("labs")
    if not labs:
        raise ValueError(f"no labs defined in {path}")
    for lab in labs:
        if "target" not in lab:
            raise ValueError(f"lab '{lab.get('name', '?')}' has no target")
    return config


def run_lab(lab: Dict[str, Any], *, model: str, max_turns: int, no_persist: bool = True) -> Dict[str, Any]:
    from tradecraft.execution.loop import run_engagement
    from tradecraft.tools.profiles import load_profile

    tool_ids = load_profile(lab.get("profile", "web"))
    result = run_engagement(
        target=lab["target"],
        model=model,
        max_turns=max_turns,
        tool_ids=tool_ids,
        run_dir=None if no_persist else None,
    )
    scoring = score_findings(result.findings, lab.get("expected_findings", []))
    eff = efficiency(scoring["recall"], result.turns_used, len(result.findings))
    return {
        "lab": lab.get("name", lab["target"]),
        "target": lab["target"],
        "recall": scoring["recall"],
        "matched": scoring["matched"],
        "missed": scoring["missed"],
        "total_expected": scoring["total_expected"],
        "turns_used": result.turns_used,
        "findings_count": len(result.findings),
        "efficiency": eff,
        "findings": result.findings,
    }


def main(argv: List[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m bench.run_bench <config.yaml> [--model MODEL] [--max-turns N]", file=sys.stderr)
        return 2
    config_path = argv[0]
    model = ""
    max_turns = 40
    for i, arg in enumerate(argv):
        if arg == "--model" and i + 1 < len(argv):
            model = argv[i + 1]
        if arg == "--max-turns" and i + 1 < len(argv):
            max_turns = int(argv[i + 1])
    if not model:
        import os
        model = os.environ.get("LLM_MODEL", "")
    if not model:
        print("no model: pass --model or set LLM_MODEL", file=sys.stderr)
        return 2

    config = load_config(config_path)
    results = []
    for lab in config["labs"]:
        print(f"[bench] running lab: {lab.get('name', lab['target'])}")
        results.append(run_lab(lab, model=model, max_turns=max_turns))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = RESULTS_DIR / f"bench-{stamp}.json"
    json_path.write_text(json.dumps(
        {"config": str(config_path), "model": model, "results": results},
        default=str, indent=2,
    ), encoding="utf-8")
    md_path = RESULTS_DIR / f"bench-{stamp}.md"
    md_path.write_text(render_summary(results) + "\n", encoding="utf-8")
    print(f"[bench] wrote {json_path} and {md_path}")
    print(render_summary(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
