"""
CLI entry point for `tradecraft memory` (`index`, `search`, `stats`, `clear`).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from tradecraft.memory.cross_engagement import CrossEngagementMemory


def memory_main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="tradecraft memory",
        description="Cross-engagement hybrid vector + FTS5 memory store management and search.",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    index_p = subparsers.add_parser(
        "index",
        help="Backfill cross-engagement memory from persisted run directories on disk.",
    )
    index_p.add_argument(
        "--run-dir",
        default=None,
        help="Index a single explicit run directory path.",
    )
    index_p.add_argument(
        "--target",
        default=None,
        help="Index all runs for a specific target under $TRADECRAFT_HOME/targets/.",
    )
    index_p.add_argument(
        "--db",
        default=None,
        help="Optional explicit path to memory.db (default: $TRADECRAFT_HOME/memory.db).",
    )

    search_p = subparsers.add_parser(
        "search",
        help="Query cross-engagement memory using hybrid FTS5 BM25 + vector similarity.",
    )
    search_p.add_argument("query", help="Search query string (tech stack, CVE, symptom, domain).")
    search_p.add_argument("--target", default=None, help="Filter by target or root domain.")
    search_p.add_argument(
        "--kind",
        choices=["finding", "fact", "note"],
        default=None,
        help="Filter by entry kind.",
    )
    search_p.add_argument("--limit", type=int, default=10, help="Max results to return (default: 10).")
    search_p.add_argument("--json", action="store_true", default=False, help="Output results as JSON.")
    search_p.add_argument(
        "--db",
        default=None,
        help="Optional explicit path to memory.db (default: $TRADECRAFT_HOME/memory.db).",
    )

    stats_p = subparsers.add_parser(
        "stats",
        help="Show summary statistics of the cross-engagement memory store.",
    )
    stats_p.add_argument("--json", action="store_true", default=False, help="Output stats as JSON.")
    stats_p.add_argument(
        "--db",
        default=None,
        help="Optional explicit path to memory.db (default: $TRADECRAFT_HOME/memory.db).",
    )

    clear_p = subparsers.add_parser(
        "clear",
        help="Remove entries from the cross-engagement memory store.",
    )
    clear_p.add_argument(
        "--target",
        default=None,
        help="Only clear entries matching this target or root domain.",
    )
    clear_p.add_argument(
        "--db",
        default=None,
        help="Optional explicit path to memory.db (default: $TRADECRAFT_HOME/memory.db).",
    )

    args = parser.parse_args(argv)
    store = CrossEngagementMemory(db_path=args.db)

    if args.action == "index":
        if args.run_dir:
            rdir = Path(args.run_dir).expanduser().resolve()
            if not rdir.is_dir():
                print(f"error: run directory does not exist: {rdir}", file=sys.stderr)
                sys.exit(1)
            inserted = store.index_run_dir(rdir)
            print(f"indexed 1 run directory ({inserted} new memory entries added to {store.db_path})")
        else:
            runs_count, inserted = store.backfill_all(target_filter=args.target)
            print(f"indexed {runs_count} run(s) ({inserted} new memory entries added to {store.db_path})")

    elif args.action == "search":
        results = store.search(
            query=args.query,
            target=args.target,
            kind=args.kind,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
            return
        if not results:
            print("no matching memory entries found")
            return
        for idx, rec in enumerate(results, 1):
            ev = f" [evidence: {rec.evidence_id}]" if rec.evidence_id else ""
            tags = f" (tags: {rec.tags})" if rec.tags else ""
            print(
                f"{idx}. [{rec.kind.upper()}] {rec.target} (run {rec.run_id}, score={rec.score:.4f}){tags}\n"
                f"   {rec.text}{ev}"
            )

    elif args.action == "stats":
        st = store.stats()
        if args.json:
            print(json.dumps(st, indent=2))
            return
        print(f"Database: {st['db_path']}")
        print(f"Total entries: {st['total_entries']}")
        print(f"Indexed runs: {st['indexed_runs']}")
        print(f"Distinct targets: {st['distinct_targets']} ({st['distinct_root_domains']} root domains)")
        by_k = st.get("by_kind") or {}
        print(
            f"By kind: findings={by_k.get('finding', 0)}, "
            f"facts={by_k.get('fact', 0)}, "
            f"notes={by_k.get('note', 0)}"
        )
        print(f"Neural embedded entries: {st['neural_embedded_entries']}")

    elif args.action == "clear":
        removed = store.clear(target=args.target)
        scope = f" for target '{args.target}'" if args.target else ""
        print(f"removed {removed} memory entries{scope}")
