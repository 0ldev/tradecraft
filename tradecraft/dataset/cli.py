"""
Standalone CLI entry point for `tradecraft dataset` and `python -m tradecraft.dataset`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from tradecraft.dataset.builder import (
    SUPPORTED_BEHAVIORS,
    build_datasets_from_sources,
    normalize_behaviors,
    normalize_dataset_formats,
    write_datasets,
)
from tradecraft.dataset.loader import (
    load_run_dataset_source,
    resolve_dataset_run_dirs,
)


def dataset_main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="tradecraft dataset",
        description="Standalone offline dataset extractor and checklist evaluator over persisted engagement runs.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-dir", default=None, help="Direct path to one run directory.")
    group.add_argument("--target", default=None, help="Target domain/host to extract runs from.")
    group.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Extract across all targets and runs under $TRADECRAFT_HOME/targets/.",
    )
    parser.add_argument(
        "--run",
        default=None,
        help="Run ID, 'latest' (default), or 'all' under --target.",
    )
    parser.add_argument(
        "--format",
        default="sft",
        help="Comma-separated format(s): 'sft', 'dpo', 'checklist', or 'all' (default: sft).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path or directory (default: dataset_<fmt>.jsonl in the run dir or current dir).",
    )
    parser.add_argument(
        "--behavior",
        default=None,
        help=f"Comma-separated behavior tag filter for SFT: {', '.join(SUPPORTED_BEHAVIORS)}.",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Comma-separated engagement profile filter (e.g. 'web,full') to exclude ad-hoc --tools runs.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="Minimum turn quality score threshold for SFT records.",
    )
    parser.add_argument(
        "--min-checklist-score",
        type=float,
        default=None,
        help="Minimum run-level checklist score (0.0 to 1.0) required to include a run.",
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        default=False,
        help="Deduplicate zero-delta turns with identical (tool_call_names, behaviors) signatures.",
    )
    parser.add_argument(
        "--scrub",
        action="store_true",
        default=False,
        help="Anonymize target domain, discovered subdomains, and IPv4 addresses into RFC placeholders.",
    )
    parser.add_argument(
        "--include-unfiltered",
        action="store_true",
        default=False,
        help="Disable SFT quality filtering (include turns with unverified/retracted findings or tool dispatch errors).",
    )
    parser.add_argument(
        "--require-reasoning",
        action="store_true",
        default=False,
        help="Only include SFT turns with non-empty reasoning_content.",
    )
    args = parser.parse_args(argv)

    if (args.run_dir or args.all) and args.run is not None:
        parser.error("--run can only be used with --target")

    try:
        normalize_dataset_formats(args.format)
        normalize_behaviors(args.behavior)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    all_for_target = args.all or (args.target is not None and args.run == "all")
    run_arg = None if args.run == "all" else args.run

    try:
        run_dirs = resolve_dataset_run_dirs(
            run_dir=args.run_dir,
            target=args.target,
            run=run_arg,
            all_runs=all_for_target,
        )
        sources = [load_run_dataset_source(rdir) for rdir in run_dirs]
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    datasets = build_datasets_from_sources(
        sources,
        formats=args.format,
        filter_quality=not args.include_unfiltered,
        require_reasoning=args.require_reasoning,
        scrub=args.scrub,
        behaviors=args.behavior,
        profiles=args.profile,
        min_score=args.min_score,
        min_checklist_score=args.min_checklist_score,
        deduplicate=args.deduplicate,
    )

    default_dir = run_dirs[0] if len(run_dirs) == 1 else Path.cwd()
    written = write_datasets(
        datasets,
        output_path=args.output,
        default_dir=default_dir,
    )
    for fmt, dest in written.items():
        count = len(datasets.get(fmt, []))
        print(f"wrote {count} {fmt} record(s) to {dest}")
