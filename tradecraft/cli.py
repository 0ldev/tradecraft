"""
Top-level entrypoint: dispatches `tradecraft chat`/`report`/`dataset`/`memory`
to their own subsystem's cli.py, and owns the main engagement-run command
itself (argv with no recognized subcommand prefix).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Must load .env before importing tradecraft.execution.loop: that module reads
# LLM_BASE_URL/LLM_MODEL/etc. from os.environ at import time to build its
# DEFAULT_* constants (used as argparse defaults below), so .env has to be
# in the environment before that import runs, not just before main() runs.
from dotenv import load_dotenv

load_dotenv()

from tradecraft.dataset.cli import dataset_main  # noqa: E402
from tradecraft.execution.loop import DEFAULT_MAX_TURNS, DEFAULT_MODEL, run_engagement  # noqa: E402
from tradecraft.execution.run_dir import create_run_dir, load_seed_context  # noqa: E402
from tradecraft.memory.cli import memory_main  # noqa: E402
from tradecraft.reporting.cli import chat_main, report_main  # noqa: E402
from tradecraft.reporting.generator import generate_report, generate_reports_from_bundle, write_bundle_reports  # noqa: E402
from tradecraft.reporting.loader import bundle_from_result  # noqa: E402
from tradecraft.tools.profiles import ProfileError, load_profile  # noqa: E402


_BANNER_CHEVRON = (
    "\\     ",
    " \\    ",
    "  \\   ",
    "  /   ",
    " /  __",
    "/     ",
)
_BANNER_WORDMARK = (
    "████████╗██████╗  █████╗ ██████╗ ███████╗ ██████╗██████╗  █████╗ ███████╗████████╗",
    "╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝",
    "   ██║   ██████╔╝███████║██║  ██║█████╗  ██║     ██████╔╝███████║█████╗     ██║   ",
    "   ██║   ██╔══██╗██╔══██║██║  ██║██╔══╝  ██║     ██╔══██╗██╔══██║██╔══╝     ██║   ",
    "   ██║   ██║  ██║██║  ██║██████╔╝███████╗╚██████╗██║  ██║██║  ██║██║        ██║   ",
    "   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝   ",
)
_BANNER_SUBTITLE = "blackbox pentesting"
_BANNER_SEP = " │ "


def _studio_main(argv: list[str]) -> None:
    """`tradecraft studio [--run-dir PATH] [--host H] [--port N]` --
    read-only live dashboard over persisted runs (Craft Studio, v2)."""
    import argparse

    parser = argparse.ArgumentParser(prog="tradecraft studio", description="Craft Studio: live engagement dashboard")
    parser.add_argument("--run-dir", default=None, help="Serve a specific run directory tree (default: scan the whole TRADECRAFT_HOME).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8480)
    args = parser.parse_args(argv)

    from tradecraft.studio.app import serve
    print(f"Craft Studio -> http://{args.host}:{args.port}")
    serve(runs_dir=args.run_dir, host=args.host, port=args.port)


def _new_tool_main(argv: list[str]) -> None:
    """`tradecraft new-tool <tool_id>` -- scaffold a new tool plugin."""
    import argparse

    parser = argparse.ArgumentParser(prog="tradecraft new-tool", description="Scaffold a new tool (YAML contract + adapter + glue + test)")
    parser.add_argument("tool_id", help="lowercase snake_case tool id, e.g. tls_expiry_probe")
    parser.add_argument("--root", default=".", help="Repo root to scaffold into (default: cwd).")
    args = parser.parse_args(argv)

    from tradecraft.newtool import registration_snippet, scaffold
    try:
        created = scaffold(args.tool_id, root=args.root)
    except (ValueError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    for path in created:
        print(f"  created {path}")
    print(registration_snippet(args.tool_id))


def _print_banner() -> None:
    prefix_width = len(_BANNER_CHEVRON[0]) + len(_BANNER_SEP)
    # Colors only when attached to a real terminal -- raw escape codes would
    # otherwise land in --log/--trace output and anything redirected to a file.
    if not sys.stdout.isatty():
        for chevron, wordmark in zip(_BANNER_CHEVRON, _BANNER_WORDMARK):
            print(chevron + _BANNER_SEP + wordmark)
        print(" " * prefix_width + _BANNER_SUBTITLE)
        print()
        return

    white, orange, gray, reset = "\033[1;97m", "\033[38;5;208m", "\033[90m", "\033[0m"
    for chevron, wordmark in zip(_BANNER_CHEVRON, _BANNER_WORDMARK):
        print(f"{white}{chevron}{reset}{orange} │ {reset}{white}{wordmark}{reset}")
    print(" " * prefix_width + f"{gray}{_BANNER_SUBTITLE}{reset}")
    print()


def _on_event(kind: str, payload) -> None:
    if kind == "text":
        print(f"\n[tradecraft] {payload}\n")
    elif kind == "tool_result":
        print(f"  -> {payload['name']}({payload['input']})")
        print(f"     {payload['result']}")
    elif kind == "truncation_retry":
        print(f"  [retry] truncated response (attempt {payload['attempt']}), "
              f"retrying with max_tokens={payload['next_max_tokens']}")
    elif kind == "network_retry":
        print(f"  [retry] network error (attempt {payload['attempt']}): {payload['error']}")


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "chat":
        chat_main(argv[1:])
        return
    if argv and argv[0] == "report":
        report_main(argv[1:])
        return
    if argv and argv[0] == "dataset":
        dataset_main(argv[1:])
        return
    if argv and argv[0] == "memory":
        memory_main(argv[1:])
        return
    if argv and argv[0] == "studio":
        _studio_main(argv[1:])
        return
    if argv and argv[0] == "new-tool":
        _new_tool_main(argv[1:])
        return

    parser = argparse.ArgumentParser(prog="tradecraft", description="LLM-driven security-testing agent (v0).")
    parser.add_argument("target", help="Host/IP to assess, e.g. 10.0.0.5 or target.local")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="litellm model string, e.g. 'openai/qwen3.8-27b'.")
    parser.add_argument(
        "--max-turns", type=int, default=DEFAULT_MAX_TURNS,
        help="Hard cap on tool-call turns. 0 (default) = unlimited; the model runs until it stops on its own.",
    )
    parser.add_argument("--log", default=None, help="Optional path to persist the raw engagement log to.")
    parser.add_argument(
        "--trace", default=None,
        help="Optional path to persist a full per-LLM-call trace (JSONL: exact request, "
             "response content/reasoning/tool_calls, finish_reason, token usage, duration).",
    )
    parser.add_argument(
        "--evidence-dir", default=None,
        help="Optional directory to persist raw tool evidence to (tradecraft/memory/evidence.py).",
    )
    parser.add_argument(
        "--tools", default=None,
        help="Comma-separated list of tool ids to make available this engagement "
             "(default: all registered tools), e.g. --tools nmap_scan,subfinder. "
             "log_note/log_finding are always available regardless.",
    )
    parser.add_argument(
        "--profile", default=None,
        help="Named engagement-shape tool preset (see config/profiles/), "
             "e.g. 'web' (default if neither this nor --tools is given), "
             "'ad-network', 'kubernetes', 'cloud', 'full' (every registered tool). "
             "Ignored if --tools is also given -- --tools is always authoritative.",
    )
    parser.add_argument(
        "--allow-destructive", action="store_true", default=False,
        help="Make destructive tools (destructive: true in their contract -- "
             "can mutate target state irreversibly) available this engagement. "
             "Off by default. Allows every destructive tool regardless of its "
             "blast-radius category -- see --allow-destructive-categories for a "
             "finer-grained alternative. See docs/policy.md.",
    )
    parser.add_argument(
        "--allow-destructive-categories", default=None,
        help="Comma-separated blast-radius categories to allow, instead of "
             "every destructive tool (account_lockout_risk, state_mutation, "
             "code_execution, credential_or_secret_exposure, persistent_artifact "
             "-- see docs/policy.md). A destructive "
             "tool runs only if ALL of its own declared categories are in this "
             "set. Ignored if --allow-destructive is also given, since that "
             "already allows everything.",
    )
    parser.add_argument(
        "--credential-budget", type=int, default=None,
        help="Total credential-guessing attempts allowed per endpoint for the "
             "whole engagement, shared by hydra and kerbrute_spray (see "
             "docs/policy.md). Must be >= 1. Defaults to "
             "tradecraft.policy.credential_budget.TOTAL_BUDGET_PER_ENDPOINT "
             "(currently 5) if not given. This is a static, pre-run operator "
             "choice -- it is not a tool parameter, so the model can never "
             "raise it mid-engagement.",
    )
    parser.add_argument(
        "--seed-from", default=None,
        help="Prior run_id (or 'latest') against the same target to seed context from (complement mode).",
    )
    parser.add_argument(
        "--guidance", default=None,
        help="Free-text operator instruction/observation/focus for this engagement "
             "(e.g. 'focus on the GraphQL endpoint', 'avoid the admin panel, another team "
             "owns it this week'). Rendered into the system prompt as advisory priority, "
             "never an enforced constraint -- the model may still log a significant finding "
             "outside it.",
    )
    parser.add_argument(
        "--no-persist", action="store_true", default=False,
        help="Opt out of run directory persistence ($TRADECRAFT_HOME/targets/<target>/runs/<run_id>) "
             "and revert to in-memory/temp-dir behavior.",
    )
    parser.add_argument(
        "--run-id", default=None,
        help="Explicit run_id to use instead of auto-generating one.",
    )
    parser.add_argument(
        "--report", nargs="?", const=True, default=None,
        help="Write the generated report. If given with no PATH, "
             "defaults to <run_dir>/report.<ext>. An explicit PATH overrides that default.",
    )
    parser.add_argument(
        "--report-format", default=None,
        help="Comma-separated report format(s) when --report is used: "
             "'md', 'html', 'json', 'sarif', or 'all' (default: md).",
    )
    parser.add_argument(
        "--report-model", default=None,
        help="litellm model string for the report generator's synthesis call "
             "(default: same as --model).",
    )
    args = parser.parse_args(argv)

    _print_banner()

    if args.credential_budget is not None and args.credential_budget < 1:
        print(f"error: --credential-budget must be >= 1, got {args.credential_budget}", file=sys.stderr)
        sys.exit(1)

    # effective_profile records which named profile (if any) actually
    # produced tool_ids, for manifest.json -- None when --tools overrode it
    # with an explicit id list, since that run isn't "running the <name>
    # profile" even if --profile was also passed (the CLI's own precedence
    # rule: --tools always wins).
    effective_profile: str | None = None
    if args.tools:
        tool_ids = [t.strip() for t in args.tools.split(",") if t.strip()]
    elif args.profile:
        try:
            tool_ids = load_profile(args.profile)
            effective_profile = args.profile
        except ProfileError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            tool_ids = load_profile("web")
            effective_profile = "web"
        except ProfileError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)

    run_dir = None
    run_id = args.run_id
    mode = "complement" if args.seed_from else "fresh"
    seed_from_val = None
    seed_context = ""

    if args.seed_from:
        try:
            seed_from_val, seed_context = load_seed_context(args.target, args.seed_from)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)

    if not args.no_persist:
        run_id, run_dir_path = create_run_dir(args.target, run_id=run_id)
        run_dir = run_dir_path
        persist_log_path = args.log if args.log is not None else str(run_dir_path / "log.txt")
        persist_trace_path = args.trace if args.trace is not None else str(run_dir_path / "trace.jsonl")
        persist_evidence_dir = args.evidence_dir if args.evidence_dir is not None else str(run_dir_path / "evidence")
    else:
        persist_log_path = args.log
        persist_trace_path = args.trace
        persist_evidence_dir = args.evidence_dir

    try:
        result = run_engagement(
            target=args.target,
            model=args.model,
            max_turns=args.max_turns,
            persist_log_path=persist_log_path,
            persist_trace_path=persist_trace_path,
            persist_evidence_dir=persist_evidence_dir,
            run_dir=run_dir,
            run_id=run_id,
            mode=mode,
            seed_from=seed_from_val,
            seed_context=seed_context,
            guidance=args.guidance or "",
            tool_ids=tool_ids,
            allow_destructive=args.allow_destructive,
            allow_destructive_categories=frozenset(
                c.strip() for c in args.allow_destructive_categories.split(",") if c.strip()
            ) if args.allow_destructive_categories else frozenset(),
            credential_budget=args.credential_budget,
            profile=effective_profile,
            on_event=_on_event,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 72)
    print(f"ENGAGEMENT COMPLETE ({result.turns_used} turns)")
    if result.run_id:
        print(f"Run ID: {result.run_id}")
    if result.run_dir:
        print(f"Run directory: {result.run_dir}")
    print("=" * 72)
    print(result.report)

    if result.findings:
        print("\n" + "-" * 72)
        print(f"{len(result.findings)} logged finding(s):")
        for f in result.findings:
            print(f" - {f}")

    stats = result.stats
    if stats:
        print("\n" + "-" * 72)
        print("Call stats:")
        print(f"  LLM calls: {stats['total_llm_calls']} "
              f"({stats['successful_calls']} ok, {stats['failed_calls']} failed, "
              f"{stats['truncation_retries']} truncation retries, {stats['network_retries']} network retries)")
        print(f"  Tokens: {stats['total_prompt_tokens']} prompt + "
              f"{stats['total_completion_tokens']} completion = {stats['total_tokens']} total")
        print(f"  Wall time in LLM calls: {stats['total_wall_seconds']}s")

    if args.report is not None or args.report_format is not None:
        report_model = args.report_model or args.model
        if args.report_format is not None:
            bundle = bundle_from_result(result, target=args.target)
            outputs = None
            report_error = False
            try:
                outputs = generate_reports_from_bundle(
                    bundle,
                    formats=args.report_format,
                    model=report_model,
                    use_llm=True,
                )
            except Exception as exc:
                print(f"error generating report: {exc}", file=sys.stderr)
                report_error = True

            if not report_error:
                if outputs is None:
                    print(
                        "warning: nothing to report -- no findings or facts logged, skipping --report output",
                        file=sys.stderr,
                    )
                else:
                    out_arg = None if args.report in (None, True) else args.report
                    written = write_bundle_reports(
                        outputs,
                        run_dir=result.run_dir,
                        run_id=result.run_id,
                        output_path=out_arg,
                    )
                    for _, dest in written.items():
                        print(f"wrote report to {dest}")
        else:
            report_content = None
            report_error = False
            try:
                report_content = generate_report(result, target=args.target, model=report_model)
            except Exception as exc:
                print(f"error generating report: {exc}", file=sys.stderr)
                report_error = True

            if not report_error:
                if report_content is None:
                    print(
                        "warning: nothing to report -- no findings or facts logged, skipping --report output",
                        file=sys.stderr,
                    )
                else:
                    if args.report is True:
                        if result.run_dir:
                            report_dest = Path(result.run_dir) / "report.md"
                        else:
                            report_dest = Path(f"report_{result.run_id or 'run'}.md")
                    else:
                        report_dest = Path(args.report)
                    report_dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(report_dest, "w", encoding="utf-8") as f:
                        f.write(report_content)
                    print(f"wrote report to {report_dest}")


if __name__ == "__main__":
    main()
