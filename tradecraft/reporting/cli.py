"""
CLI entry points for `tradecraft chat` (post-run investigation console) and
`tradecraft report` (standalone report generator).
"""
from __future__ import annotations

import argparse
import sys

from tradecraft.execution.loop import DEFAULT_MODEL
from tradecraft.reporting.console import InvestigationConsole, resolve_console_run_dir, run_repl
from tradecraft.reporting.generator import generate_reports_from_bundle, write_bundle_reports
from tradecraft.reporting.loader import load_run_bundle, resolve_report_run_dir


def chat_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tradecraft chat", description="Post-run investigation console.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-dir", default=None, help="Direct path to one run directory.")
    group.add_argument("--target", default=None, help="Target domain/host to inspect runs for.")
    parser.add_argument("--run", default=None, help="Run ID or 'latest' under --target (default: latest).")
    parser.add_argument("--ask", default=None, help="One-shot question to answer instead of opening interactive REPL.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="litellm model string for console (default: same as engagement).")
    args = parser.parse_args(argv)

    if args.run_dir and args.run is not None:
        parser.error("--run can only be used with --target")

    try:
        run_dir_path = resolve_console_run_dir(
            run_dir=args.run_dir,
            target=args.target,
            run=args.run,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        console = InvestigationConsole(run_dir_path, model=args.model)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.ask:
        answer = console.ask(args.ask)
        print(answer)
    else:
        run_repl(console)


def report_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="tradecraft report",
        description="Standalone multi-format report generator over any finished or interrupted engagement run.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-dir", default=None, help="Direct path to one run directory.")
    group.add_argument("--target", default=None, help="Target domain/host to generate report for.")
    parser.add_argument("--run", default=None, help="Run ID or 'latest' under --target (default: latest).")
    parser.add_argument(
        "--format",
        default="md,html",
        help="Comma-separated output format(s): 'md', 'html', 'json', 'sarif', or 'all' (default: md,html).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional output file path or directory (default: writes report.<ext> inside the run directory).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="litellm model string for Executive Summary synthesis (default: LLM_MODEL from .env).",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        default=False,
        help="Skip LLM executive summary synthesis and generate a strictly deterministic report offline.",
    )
    args = parser.parse_args(argv)

    if args.run_dir and args.run is not None:
        parser.error("--run can only be used with --target")

    try:
        run_dir_path = resolve_report_run_dir(
            run_dir=args.run_dir,
            target=args.target,
            run=args.run,
        )
        bundle = load_run_bundle(run_dir_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        outputs = generate_reports_from_bundle(
            bundle,
            formats=args.format,
            model=args.model,
            use_llm=not args.no_llm,
        )
    except Exception as exc:
        print(f"error generating report: {exc}", file=sys.stderr)
        sys.exit(1)

    if outputs is None:
        print(
            "warning: nothing to report -- no findings or facts logged, skipping report output",
            file=sys.stderr,
        )
        return

    written = write_bundle_reports(
        outputs,
        run_dir=bundle.run_dir,
        run_id=bundle.run_id,
        output_path=args.output,
    )
    for fmt, dest in written.items():
        print(f"wrote {fmt} report to {dest}")
