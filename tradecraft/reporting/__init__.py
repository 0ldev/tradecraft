"""
Reporting and investigation components for Tradecraft.
"""
from tradecraft.reporting.console import InvestigationConsole, resolve_console_run_dir
from tradecraft.reporting.exporters import (
    render_html_bundle,
    render_json_bundle,
    render_markdown_bundle,
    render_sarif_bundle,
)
from tradecraft.reporting.generator import (
    SUPPORTED_REPORT_FORMATS,
    generate_report,
    generate_reports_from_bundle,
    normalize_report_formats,
    write_bundle_reports,
)
from tradecraft.reporting.loader import (
    ParsedFinding,
    RunReportBundle,
    TurnHistoryEntry,
    TurnToolCall,
    bundle_from_result,
    load_run_bundle,
    resolve_report_run_dir,
)

__all__ = [
    "generate_report",
    "generate_reports_from_bundle",
    "normalize_report_formats",
    "write_bundle_reports",
    "SUPPORTED_REPORT_FORMATS",
    "InvestigationConsole",
    "resolve_console_run_dir",
    "RunReportBundle",
    "ParsedFinding",
    "TurnHistoryEntry",
    "TurnToolCall",
    "load_run_bundle",
    "bundle_from_result",
    "resolve_report_run_dir",
    "render_markdown_bundle",
    "render_html_bundle",
    "render_json_bundle",
    "render_sarif_bundle",
]
