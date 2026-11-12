"""
Post-engagement security assessment report generator.

Transforms an EngagementResult (facts, findings, closing notes, evidence index)
into a structured Markdown report with an LLM-synthesized Executive Summary.
All other sections are deterministically rendered from python data.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import litellm

from tradecraft.coverage.matrix import CoverageMatrix
from tradecraft.execution.loop import (
    DEFAULT_API_KEY,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    EngagementResult,
)
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.reporting.attack_map import render_attack_appendix
from tradecraft.reporting.exporters import (
    render_html_bundle,
    render_json_bundle,
    render_markdown_bundle,
    render_sarif_bundle,
)
from tradecraft.reporting.loader import RunReportBundle

SUPPORTED_REPORT_FORMATS = ("md", "html", "json", "sarif")
FORMAT_FILE_EXTENSIONS = {
    "md": ".md",
    "html": ".html",
    "json": ".json",
    "sarif": ".sarif.json",
}

EXEC_SUMMARY_INPUT_CHAR_LIMIT = 24_000

EXEC_SUMMARY_SYSTEM_PROMPT = """You are writing the Executive Summary section of a security assessment
report. You will be given the Attack Surface Inventory and Findings
sections exactly as they will appear in the final report, already
rendered below. Write 2-4 short paragraphs assessing overall exposure
and business impact.

Hard rules:
- Reference ONLY hosts, ports, and findings that appear verbatim in the
  text below. Do not introduce any host, port, CVE, CVSS score, or
  claim not already present in it.
- Do not invent a severity rating or numeric score for anything.
- If the inventory and findings below are both sparse, say so plainly
  rather than padding with generic security advice.
- Do not repeat a section heading (e.g. "Executive Summary") in your
  output. The report template already adds that heading -- write only
  the body paragraphs, starting directly with the first sentence.

--- Attack Surface Inventory ---
{facts_text}

--- Findings ---
{findings_text}"""

MAP_SYSTEM_PROMPT = """You are summarizing a batch of findings for an Executive Summary of a security assessment report. You will be given the Attack Surface Inventory and a batch of Findings. Write 2-3 bullet points assessing key exposures, following these hard rules:
- Reference ONLY hosts, ports, and findings that appear verbatim in the text below. Do not introduce any host, port, CVE, CVSS score, or claim not already present in it.
- Do not invent a severity rating or numeric score for anything.
- Write only the bullet points -- no section heading.

--- Attack Surface Inventory ---
{facts_text}

--- Findings (Batch) ---
{batch_findings_text}"""

REDUCE_SYSTEM_PROMPT = """You are writing the Executive Summary section of a security assessment report. You will be given the Attack Surface Inventory and summarized finding bullets from previous batches. Write 2-4 short paragraphs assessing overall exposure and business impact.

Hard rules:
- Reference ONLY hosts, ports, and findings that appear verbatim in the text below. Do not introduce any host, port, CVE, CVSS score, or claim not already present in it.
- Do not invent a severity rating or numeric score for anything.
- If the inventory and findings below are both sparse, say so plainly rather than padding with generic security advice.
- Do not repeat a section heading (e.g. "Executive Summary") in your output. The report template already adds that heading -- write only the body paragraphs, starting directly with the first sentence.

--- Attack Surface Inventory ---
{facts_text}

--- Findings Summary Bullets ---
{combined_bullets}"""


def render_attack_surface_inventory(facts: FactStore) -> str:
    """Renders the Attack Surface Inventory Markdown table or placeholder."""
    records = facts.sorted_records()
    if not records:
        return "_(no facts recorded for this engagement)_"
    lines = [
        "| Host | Port | Details |",
        "|---|---|---|",
    ]
    for (host, port), record in records:
        details = ", ".join(f"{k}={v}" for k, v in record.items() if k not in ("host", "port"))
        lines.append(f"| {host} | {port} | {details} |" if details else f"| {host} | {port} | |")
    return "\n".join(lines)


def render_findings(findings: List[str]) -> str:
    """Renders the Findings Markdown bullets or placeholder."""
    if not findings:
        return "_(no findings logged)_"
    return "\n".join(f"- {f}" for f in findings)


def render_closing_notes(report_text: str) -> str:
    """Renders the model's closing report text inside a blockquote."""
    if not report_text or not report_text.strip():
        return "> _(no closing notes)_"
    lines = [f"> {line}" if line.strip() else ">" for line in report_text.splitlines()]
    return "\n".join(lines)


def render_evidence_index(evidence: EvidenceStore) -> str:
    """Renders the Evidence Index list or placeholder."""
    keys = evidence.keys()
    if not keys:
        return "_(no evidence persisted for this run)_"
    return "\n".join(f"- `{k}`" for k in keys)


def _call_completion(
    model: str,
    system_prompt: str,
    user_prompt: str,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> str:
    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    if base_url:
        kwargs["api_base"] = base_url
    if api_key:
        kwargs["api_key"] = api_key

    response = litellm.completion(**kwargs)
    content = response.choices[0].message.content
    return content.strip() if content else ""


def generate_executive_summary(
    facts_text: str,
    findings: List[str],
    *,
    model: str,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> str:
    """Generates the Executive Summary, using map-reduce chunking if input exceeds character limit."""
    findings_text = render_findings(findings)

    if len(facts_text) + len(findings_text) <= EXEC_SUMMARY_INPUT_CHAR_LIMIT or len(findings) <= 20:
        system_prompt = EXEC_SUMMARY_SYSTEM_PROMPT.format(
            facts_text=facts_text,
            findings_text=findings_text,
        )
        summary = _call_completion(
            model=model,
            system_prompt=system_prompt,
            user_prompt="Write the Executive Summary now.",
            base_url=base_url,
            api_key=api_key,
        )
        return summary if summary else "_(summary generation produced no output)_"

    # Chunking fallback: batch findings in groups of 20
    batch_bullets: List[str] = []
    batch_size = 20
    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        batch_text = "\n".join(f"- {f}" for f in batch)
        map_prompt = MAP_SYSTEM_PROMPT.format(
            facts_text=facts_text,
            batch_findings_text=batch_text,
        )
        bullets = _call_completion(
            model=model,
            system_prompt=map_prompt,
            user_prompt="Summarize this batch in 2-3 bullet points now.",
            base_url=base_url,
            api_key=api_key,
        )
        if bullets:
            batch_bullets.append(bullets)

    combined_bullets = "\n\n".join(batch_bullets) if batch_bullets else "_(no findings summarized)_"
    reduce_prompt = REDUCE_SYSTEM_PROMPT.format(
        facts_text=facts_text,
        combined_bullets=combined_bullets,
    )
    summary = _call_completion(
        model=model,
        system_prompt=reduce_prompt,
        user_prompt="Write the Executive Summary now.",
        base_url=base_url,
        api_key=api_key,
    )
    return summary if summary else "_(summary generation produced no output)_"


def generate_report(
    result: EngagementResult,
    *,
    target: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    base_url: Optional[str] = DEFAULT_BASE_URL,
    api_key: Optional[str] = DEFAULT_API_KEY,
) -> Optional[str]:
    """Generates the complete security assessment report Markdown string.
    Returns None if there are neither findings nor facts recorded (refusal condition).
    Raises ValueError if model is empty."""
    if not model:
        raise ValueError(
            "no model configured for report generator -- set LLM_MODEL in .env "
            "or pass --report-model"
        )

    # Refusal condition: no findings and no facts
    if not result.findings and result.facts.render() == "(no facts recorded yet)":
        return None

    target_name = target or getattr(result, "target", None)
    if not target_name:
        sorted_recs = result.facts.sorted_records()
        target_name = sorted_recs[0][0][0] if sorted_recs else "Target"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    inventory_text = render_attack_surface_inventory(result.facts)
    findings_text = render_findings(result.findings)
    closing_notes_text = render_closing_notes(result.report)
    evidence_text = render_evidence_index(result.evidence)
    # v2 (Phase 5): deterministic triage appendix -- coverage matrix and
    # ATT&CK/CVSS mapping rendered from facts/findings, no LLM involved.
    coverage_matrix = CoverageMatrix.from_records(result.facts.sorted_records())
    coverage_text = "```\n" + coverage_matrix.render_compact() + "\n```\n"
    attack_text = render_attack_appendix(result.findings)

    exec_summary = generate_executive_summary(
        facts_text=inventory_text,
        findings=result.findings,
        model=model,
        base_url=base_url,
        api_key=api_key,
    )

    report_md = f"""# Security Assessment Report: {target_name}

*Report generated {now_iso} · engagement used {result.turns_used} turn(s)*

## Executive Summary

{exec_summary}

## Attack Surface Inventory

{inventory_text}

## Findings

{findings_text}

## Model's Closing Notes

{closing_notes_text}

## Coverage & ATT&CK Mapping

{coverage_text}
{attack_text}

## Evidence Index

{evidence_text}
"""
    return report_md


def normalize_report_formats(raw_formats: Optional[str | Sequence[str]]) -> List[str]:
    """Parses comma-separated format names ('md,html', 'all', etc.) into a validated list."""
    if not raw_formats:
        return ["md", "html"]
    if isinstance(raw_formats, str):
        tokens = [t.strip().lower() for t in raw_formats.split(",") if t.strip()]
    else:
        tokens = [str(t).strip().lower() for t in raw_formats if str(t).strip()]

    if not tokens:
        return ["md", "html"]
    if "all" in tokens:
        return list(SUPPORTED_REPORT_FORMATS)

    normalized: List[str] = []
    for tok in tokens:
        alias = "md" if tok == "markdown" else tok
        if alias not in SUPPORTED_REPORT_FORMATS:
            raise ValueError(
                f"unsupported report format '{tok}' -- supported: {list(SUPPORTED_REPORT_FORMATS)} or 'all'"
            )
        if alias not in normalized:
            normalized.append(alias)
    return normalized


def build_deterministic_summary(bundle: RunReportBundle) -> str:
    """Builds a strictly factual, zero-LLM summary when --no-llm is requested."""
    total_f = len(bundle.active_findings)
    verified_f = sum(1 for f in bundle.active_findings if f.verified)
    retracted_f = len(bundle.retracted_findings)
    records = bundle.facts.sorted_records()
    hosts = sorted({h for (h, _), _ in records})
    ports_count = len(records)

    parts = [
        f"Security assessment of {bundle.target} executed {bundle.turns_used} turn(s), "
        f"recording {total_f} active finding(s) ({verified_f} backed by persisted tool evidence) "
        f"and {ports_count} host:port attack-surface record(s) across {len(hosts)} unique host(s)."
    ]
    if retracted_f:
        parts.append(
            f"{retracted_f} initial hypothesis/finding(s) were explicitly retracted during the engagement after verification ruled them out."
        )
    if bundle.active_findings:
        lead_titles = "; ".join(
            f"Finding #{f.finding_id}: {f.title}" for f in bundle.active_findings[:5]
        )
        parts.append(f"Key logged findings include: {lead_titles}.")
    return "\n\n".join(parts)


def generate_reports_from_bundle(
    bundle: RunReportBundle,
    *,
    formats: Optional[str | Sequence[str]] = None,
    model: str = DEFAULT_MODEL,
    base_url: Optional[str] = DEFAULT_BASE_URL,
    api_key: Optional[str] = DEFAULT_API_KEY,
    use_llm: bool = True,
) -> Optional[Dict[str, str]]:
    """Generates one or more report formats ('md', 'html', 'json', 'sarif') from a RunReportBundle.
    Returns None if the bundle has neither findings nor facts (refusal condition)."""
    fmt_list = normalize_report_formats(formats)

    if bundle.is_empty:
        return None

    if not bundle.executive_summary:
        if use_llm:
            if not model:
                raise ValueError(
                    "no model configured for report generator -- set LLM_MODEL in .env, "
                    "pass --model, or use --no-llm for deterministic reporting"
                )
            inventory_text = render_attack_surface_inventory(bundle.facts)
            findings_strings = [f.formatted_bullet() for f in bundle.active_findings]
            bundle.executive_summary = generate_executive_summary(
                facts_text=inventory_text,
                findings=findings_strings,
                model=model,
                base_url=base_url,
                api_key=api_key,
            )
        else:
            bundle.executive_summary = build_deterministic_summary(bundle)

    outputs: Dict[str, str] = {}
    for fmt in fmt_list:
        if fmt == "md":
            outputs["md"] = render_markdown_bundle(bundle, include_extended_sections=True)
        elif fmt == "html":
            outputs["html"] = render_html_bundle(bundle)
        elif fmt == "json":
            outputs["json"] = render_json_bundle(bundle)
        elif fmt == "sarif":
            outputs["sarif"] = render_sarif_bundle(bundle)
    return outputs


def write_bundle_reports(
    outputs: Dict[str, str],
    *,
    run_dir: Optional[Path] = None,
    run_id: Optional[str] = None,
    output_path: Optional[str | Path] = None,
) -> Dict[str, Path]:
    """Writes rendered report strings to disk and returns {format: written_path}.

    - If `output_path` is None: writes `report.<ext>` inside `run_dir` (or `./report_<run_id>.<ext>`).
    - If `output_path` is an existing directory (or multiple formats are requested and `output_path` has no suffix):
      writes `report.<ext>` inside that directory.
    - If `output_path` is a file path and a single format is requested: writes directly to `output_path`.
    - If `output_path` is a file path (e.g. `/tmp/my_report.md`) and multiple formats are requested:
      uses `output_path`'s stem (`/tmp/my_report.<ext>`) for each format.
    """
    written: Dict[str, Path] = {}
    fmt_keys = list(outputs.keys())

    if output_path is None:
        base_dir = Path(run_dir) if run_dir else Path(".")
        stem = "report" if run_dir else f"report_{run_id or 'run'}"
        base_dir.mkdir(parents=True, exist_ok=True)
        for fmt, content in outputs.items():
            ext = FORMAT_FILE_EXTENSIONS[fmt]
            dest = base_dir / f"{stem}{ext}"
            dest.write_text(content, encoding="utf-8")
            written[fmt] = dest
        return written

    out_p = Path(output_path).expanduser()
    if out_p.is_dir() or (len(fmt_keys) > 1 and not out_p.suffix):
        out_p.mkdir(parents=True, exist_ok=True)
        for fmt, content in outputs.items():
            ext = FORMAT_FILE_EXTENSIONS[fmt]
            dest = out_p / f"report{ext}"
            dest.write_text(content, encoding="utf-8")
            written[fmt] = dest
        return written

    if len(fmt_keys) == 1:
        fmt = fmt_keys[0]
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(outputs[fmt], encoding="utf-8")
        written[fmt] = out_p
        return written

    # Multiple formats with a file-like path: strip known extension and write each format
    out_p.parent.mkdir(parents=True, exist_ok=True)
    stem_name = out_p.name
    for ext in (".sarif.json", ".md", ".html", ".json", ".sarif"):
        if stem_name.endswith(ext):
            stem_name = stem_name[: -len(ext)]
            break
    if not stem_name:
        stem_name = "report"
    for fmt, content in outputs.items():
        ext = FORMAT_FILE_EXTENSIONS[fmt]
        dest = out_p.parent / f"{stem_name}{ext}"
        dest.write_text(content, encoding="utf-8")
        written[fmt] = dest
    return written
