"""
Multi-format report renderers and exporters for Tradecraft engagements.

Supports:
- Markdown (`md`): PTES-structured Markdown with inline evidence proof blocks
  and retracted-hypothesis audit trail.
- Interactive HTML (`html`): Self-contained single-file HTML5 deliverable with
  tabs for Executive & Findings, Attack Surface Inventory, Roll-Down Engagement
  History (turn-by-turn reasoning & tool calls), and Evidence Index.
- Canonical JSON (`json`): Full structured engagement export for automation,
  dashboards, or custom ingestion pipelines.
- SARIF v2.1.0 (`sarif`): OASIS standard Static/Dynamic Analysis Results
  Interchange Format for GitHub Security, DefectDojo, GitLab, and Faraday.
"""
from __future__ import annotations

import html
import json
from dataclasses import asdict
from typing import Any, Dict, List

from tradecraft.reporting.loader import ParsedFinding, RunReportBundle, TurnHistoryEntry

_COVERAGE_FIELDS = (
    "sqli_tested",
    "sqli_injectable",
    "xss_tested",
    "cmdi_tested",
    "arjun_params_discovered",
    "params_discovered",
)


def _esc(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


def _format_paragraphs_html(text: str) -> str:
    if not text or not text.strip():
        return "<p class='muted'><em>No content available.</em></p>"
    blocks = [b.strip() for b in text.strip().split("\n\n") if b.strip()]
    out: List[str] = []
    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if all(line.startswith(("- ", "* ")) for line in lines):
            items = "".join(f"<li>{_esc(line[2:].strip())}</li>" for line in lines)
            out.append(f"<ul>{items}</ul>")
        else:
            joined = "<br>".join(_esc(line) for line in lines)
            out.append(f"<p>{joined}</p>")
    return "\n".join(out)


def render_markdown_bundle(
    bundle: RunReportBundle,
    *,
    include_extended_sections: bool = True,
) -> str:
    """Renders a RunReportBundle into a complete Markdown security assessment report."""
    records = bundle.facts.sorted_records()
    if not records:
        inventory_text = "_(no facts recorded for this engagement)_"
    else:
        inv_lines = [
            "| Host | Port | Details |",
            "|---|---|---|",
        ]
        for (host, port), record in records:
            details = ", ".join(f"{k}={v}" for k, v in record.items() if k not in ("host", "port"))
            inv_lines.append(f"| {host} | {port} | {details} |" if details else f"| {host} | {port} | |")
        inventory_text = "\n".join(inv_lines)

    if not bundle.active_findings:
        findings_text = "_(no findings logged)_"
    else:
        findings_text = "\n".join(f"- {f.formatted_bullet()}" for f in bundle.active_findings)

    if not bundle.closing_notes or not bundle.closing_notes.strip():
        closing_text = "> _(no closing notes)_"
    else:
        closing_text = "\n".join(
            f"> {line}" if line.strip() else ">" for line in bundle.closing_notes.splitlines()
        )

    if not bundle.evidence_keys:
        evidence_text = "_(no evidence persisted for this run)_"
    else:
        evidence_text = "\n".join(f"- `{k}`" for k in bundle.evidence_keys)

    exec_summary = bundle.executive_summary or "_(summary generation skipped or produced no output)_"

    meta_parts = [f"Report generated {bundle.generated_at}", f"engagement used {bundle.turns_used} turn(s)"]
    if bundle.run_id:
        meta_parts.append(f"run `{bundle.run_id}`")
    if bundle.manifest.get("profile"):
        meta_parts.append(f"profile `{bundle.manifest['profile']}`")
    if bundle.manifest.get("allow_destructive") is not None:
        mode_label = "destructive allowed" if bundle.manifest.get("allow_destructive") else "non-destructive only"
        meta_parts.append(mode_label)
    meta_line = " · ".join(meta_parts)
    header_block = f"*{meta_line}*"
    if bundle.manifest.get("guidance"):
        header_block += f"\n\n**Operator guidance:** {bundle.manifest['guidance']}"

    sections = [
        f"# Security Assessment Report: {bundle.target}",
        header_block,
        "## Executive Summary",
        exec_summary,
        "## Attack Surface Inventory",
        inventory_text,
        "## Findings",
        findings_text,
    ]

    if include_extended_sections:
        findings_with_proof = [f for f in bundle.active_findings if f.evidence_snippet]
        if findings_with_proof:
            proof_lines: List[str] = ["### Attached Tool Proof (Evidence Store)"]
            for f in findings_with_proof:
                fid_label = f"Finding #{f.finding_id}" if f.finding_id is not None else "Finding"
                proof_lines.append(
                    f"<details>\n<summary><strong>{fid_label}: {_esc(f.title)}</strong> "
                    f"(<code>{_esc(f.evidence_id)}</code>)</summary>\n\n```json\n{f.evidence_snippet}\n```\n</details>"
                )
            sections.append("\n\n".join(proof_lines))

        if bundle.retracted_findings:
            ret_lines = ["## Retracted Hypotheses (Ruled Out During Engagement)"]
            for rf in bundle.retracted_findings:
                reason_str = f" — *Reason: {rf.retraction_reason}*" if rf.retraction_reason else ""
                ret_lines.append(f"- ~~Finding #{rf.finding_id}: {rf.text}~~{reason_str}")
            sections.append("\n".join(ret_lines))

    sections.extend([
        "## Model's Closing Notes",
        closing_text,
        "## Evidence Index",
        evidence_text,
    ])

    return "\n\n".join(sections) + "\n"


def render_json_bundle(bundle: RunReportBundle) -> str:
    """Exports the RunReportBundle as a canonical, versioned JSON document."""
    payload: Dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": bundle.generated_at,
        "target": bundle.target,
        "run_id": bundle.run_id,
        "run_dir": str(bundle.run_dir) if bundle.run_dir else None,
        "turns_used": bundle.turns_used,
        "manifest": bundle.manifest,
        "stats": bundle.stats,
        "executive_summary": bundle.executive_summary,
        "closing_notes": bundle.closing_notes,
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "text": f.text,
                "verified": f.verified,
                "evidence_id": f.evidence_id,
                "tool_id": f.tool_id,
                "asset": f.asset,
                "evidence_snippet": f.evidence_snippet,
            }
            for f in bundle.active_findings
        ],
        "retracted_findings": [
            {
                "finding_id": rf.finding_id,
                "title": rf.title,
                "text": rf.text,
                "evidence_id": rf.evidence_id,
                "retraction_reason": rf.retraction_reason,
            }
            for rf in bundle.retracted_findings
        ],
        "attack_surface": [record for _, record in bundle.facts.sorted_records()],
        "notes": bundle.notes,
        "evidence_keys": bundle.evidence_keys,
        "history": [asdict(h) for h in bundle.history],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"


def render_sarif_bundle(bundle: RunReportBundle) -> str:
    """Exports active findings as a SARIF v2.1.0 JSON document for upload to
    GitHub Security, DefectDojo, GitLab, or Faraday."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for idx, f in enumerate(bundle.active_findings, 1):
        tool_slug = f.tool_id or "unverified_observation"
        rule_id = f"tradecraft/{tool_slug}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f"TradecraftFinding_{tool_slug}",
                "shortDescription": {
                    "text": f"Security finding backed by {tool_slug}" if f.tool_id else "Unverified security observation"
                },
                "helpUri": "https://github.com/tradecraft/tradecraft",
            }

        artifact_uri = f.asset or bundle.target
        if "://" not in artifact_uri:
            artifact_uri = f"https://{artifact_uri}"

        fid = f.finding_id if f.finding_id is not None else idx
        res_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": "warning",
            "message": {
                "text": f.text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "tradecraftFindingId": f"{bundle.run_id or 'run'}:{fid}",
            },
            "properties": {
                "finding_id": fid,
                "title": f.title,
                "verified": f.verified,
                "evidence_id": f.evidence_id,
                "tool_id": f.tool_id,
                "asset": f.asset or bundle.target,
                "run_id": bundle.run_id,
                "target": bundle.target,
            },
        }
        if f.evidence_snippet:
            res_entry["properties"]["evidence_snippet"] = f.evidence_snippet
        results.append(res_entry)

    invocation: Dict[str, Any] = {
        "executionSuccessful": True,
    }
    if bundle.manifest.get("started_at"):
        invocation["startTimeUtc"] = bundle.manifest["started_at"]
    if bundle.manifest.get("ended_at"):
        invocation["endTimeUtc"] = bundle.manifest["ended_at"]

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Tradecraft",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/tradecraft/tradecraft",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False, default=str) + "\n"


def _render_finding_card_html(f: ParsedFinding, idx: int) -> str:
    fid = f.finding_id if f.finding_id is not None else idx
    if f.verified:
        badge_html = f'<span class="badge badge-verified">VERIFIED · {_esc(f.evidence_id)}</span>'
    else:
        badge_html = '<span class="badge badge-unverified">UNVERIFIED · no evidence_id</span>'

    tool_badge = f'<span class="badge badge-tool">{_esc(f.tool_id)}</span>' if f.tool_id else ""
    asset_badge = f'<span class="badge badge-asset">{_esc(f.asset or "")}</span>' if f.asset else ""

    proof_block = ""
    if f.evidence_image_b64 and f.evidence_image_mime:
        proof_block += (
            f'<div class="evidence-img-wrap">'
            f'<div class="evidence-label">Captured Screenshot (<code>{_esc(f.evidence_id)}</code>)</div>'
            f'<img src="data:{_esc(f.evidence_image_mime)};base64,{f.evidence_image_b64}" '
            f'alt="Evidence screenshot for Finding #{fid}" class="evidence-screenshot" />'
            f'</div>'
        )
    if f.evidence_snippet:
        proof_block += (
            f'<details class="proof-accordion" open>'
            f'<summary>Attached Tool Evidence (<code>{_esc(f.evidence_id)}</code>)</summary>'
            f'<pre class="code-block">{_esc(f.evidence_snippet)}</pre>'
            f'</details>'
        )

    return f"""
    <article class="finding-card" id="finding-{fid}">
      <div class="finding-header">
        <div class="finding-title-group">
          <span class="finding-id">FINDING #{fid}</span>
          <h3 class="finding-title">{_esc(f.title)}</h3>
        </div>
        <div class="finding-badges">
          {tool_badge}
          {asset_badge}
          {badge_html}
        </div>
      </div>
      <div class="finding-body">
        <div class="finding-text">{_esc(f.text)}</div>
        {proof_block}
      </div>
    </article>
    """


def _render_turn_history_html(entry: TurnHistoryEntry) -> str:
    tc_badges = "".join(
        f'<span class="badge badge-tool">{_esc(tc.name)}</span>'
        for tc in entry.tool_calls
    )
    if not tc_badges:
        if entry.call_kind == "final_report" or entry.finish_reason == "stop":
            tc_badges = '<span class="badge badge-verified">Final Report / Stop</span>'
        else:
            tc_badges = f'<span class="badge badge-muted">{_esc(entry.finish_reason or "turn")}</span>'

    retry_badges = ""
    if entry.truncation_retries > 0:
        retry_badges += f'<span class="badge badge-warn">{entry.truncation_retries} truncation retry</span>'
    if entry.network_retries > 0:
        retry_badges += f'<span class="badge badge-warn">{entry.network_retries} net retry</span>'
    if entry.error:
        retry_badges += '<span class="badge badge-unverified">ERROR</span>'

    ts_label = _esc(entry.timestamp[:19].replace("T", " ") + " UTC") if entry.timestamp else ""

    reasoning_html = ""
    if entry.reasoning:
        reasoning_html = (
            f'<div class="turn-section">'
            f'<div class="turn-section-title">Model Reasoning</div>'
            f'<div class="reasoning-box">{_esc(entry.reasoning)}</div>'
            f'</div>'
        )

    assistant_html = ""
    if entry.assistant_text:
        assistant_html = (
            f'<div class="turn-section">'
            f'<div class="turn-section-title">Assistant Output</div>'
            f'<div class="assistant-box">{_esc(entry.assistant_text)}</div>'
            f'</div>'
        )

    tcs_html_parts: List[str] = []
    for tc in entry.tool_calls:
        try:
            args_str = json.dumps(tc.arguments, ensure_ascii=False)
        except Exception:
            args_str = str(tc.arguments)

        if tc.result is not None:
            try:
                res_str = json.dumps(tc.result, indent=2, ensure_ascii=False, default=str)
            except Exception:
                res_str = str(tc.result)
            if len(res_str) > 3000:
                res_str = res_str[:3000] + f"\n... [truncated {len(res_str) - 3000} chars]"
            res_block = f'<pre class="code-block tool-result-pre">{_esc(res_str)}</pre>'
        else:
            res_block = '<div class="muted small"><em>Tool result not captured in subsequent turn trace.</em></div>'

        ev_tag = f' <span class="badge badge-verified">{_esc(tc.evidence_id)}</span>' if tc.evidence_id else ""
        tcs_html_parts.append(
            f'<div class="tool-call-item">'
            f'<div class="tool-call-sig"><code>{_esc(tc.name)}({_esc(args_str)})</code>{ev_tag}</div>'
            f'{res_block}'
            f'</div>'
        )

    tcs_section = ""
    if tcs_html_parts:
        tcs_section = (
            f'<div class="turn-section">'
            f'<div class="turn-section-title">Tool Dispatches ({len(entry.tool_calls)})</div>'
            f'{"".join(tcs_html_parts)}'
            f'</div>'
        )

    err_section = ""
    if entry.error:
        err_section = (
            f'<div class="turn-section">'
            f'<div class="turn-section-title">Error</div>'
            f'<pre class="code-block">{_esc(entry.error)}</pre>'
            f'</div>'
        )

    return f"""
    <details class="turn-accordion" data-turn="{entry.turn}">
      <summary class="turn-summary">
        <div class="turn-summary-left">
          <span class="turn-num">Turn #{entry.turn}</span>
          <span class="turn-tools">{tc_badges}</span>
          {retry_badges}
        </div>
        <div class="turn-summary-right">
          <span class="turn-meta">{entry.duration_seconds:.1f}s</span>
          <span class="turn-meta">{entry.total_tokens:,} tok</span>
          <span class="turn-meta muted">{ts_label}</span>
        </div>
      </summary>
      <div class="turn-body">
        {reasoning_html}
        {assistant_html}
        {tcs_section}
        {err_section}
      </div>
    </details>
    """


def render_html_bundle(bundle: RunReportBundle) -> str:
    """Renders a self-contained, interactive single-file HTML5 security report
    with roll-down engagement history, filterable attack surface inventory,
    and inline tool proof."""
    verified_count = sum(1 for f in bundle.active_findings if f.verified)
    total_findings = len(bundle.active_findings)
    retracted_count = len(bundle.retracted_findings)
    surface_records = bundle.facts.sorted_records()
    surface_count = len(surface_records)
    total_tokens = int(bundle.stats.get("total_tokens") or 0)
    wall_secs = float(bundle.stats.get("total_wall_seconds") or 0.0)

    profile_name = bundle.manifest.get("profile") or "custom/default"
    destructive_flag = bool(bundle.manifest.get("allow_destructive"))
    destructive_badge = (
        '<span class="badge badge-unverified">Destructive Enabled</span>'
        if destructive_flag
        else '<span class="badge badge-verified">Non-Destructive Only</span>'
    )
    model_name = bundle.manifest.get("model") or "configured model"
    started_at = bundle.manifest.get("started_at") or "—"
    ended_at = bundle.manifest.get("ended_at") or "In-progress / Interrupted"
    guidance_html = (
        f'<div class="meta-item" style="flex-basis:100%;"><strong>Operator Guidance:</strong> '
        f'{_esc(bundle.manifest["guidance"])}</div>'
        if bundle.manifest.get("guidance")
        else ""
    )

    # Findings Summary Table
    if bundle.active_findings:
        summary_rows: List[str] = []
        for idx, f in enumerate(bundle.active_findings, 1):
            fid = f.finding_id if f.finding_id is not None else idx
            v_badge = (
                f'<span class="badge badge-verified">Verified</span>'
                if f.verified
                else '<span class="badge badge-unverified">Unverified</span>'
            )
            summary_rows.append(
                f"<tr onclick=\"document.getElementById('finding-{fid}').scrollIntoView({{behavior:'smooth'}})\" style='cursor:pointer'>"
                f"<td><strong>#{fid}</strong></td>"
                f"<td>{_esc(f.title)}</td>"
                f"<td><code>{_esc(f.asset or bundle.target)}</code></td>"
                f"<td><code>{_esc(f.tool_id or '—')}</code></td>"
                f"<td>{v_badge}</td>"
                f"</tr>"
            )
        findings_matrix_html = f"""
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Finding Summary</th>
                <th>Asset / Target</th>
                <th>Evidence Tool</th>
                <th>Verification</th>
              </tr>
            </thead>
            <tbody>
              {"".join(summary_rows)}
            </tbody>
          </table>
        </div>
        """
        finding_cards_html = "\n".join(
            _render_finding_card_html(f, i) for i, f in enumerate(bundle.active_findings, 1)
        )
    else:
        findings_matrix_html = "<p class='muted'><em>No active findings were logged during this engagement.</em></p>"
        finding_cards_html = ""

    retracted_html = ""
    if bundle.retracted_findings:
        ret_items = []
        for rf in bundle.retracted_findings:
            reason_html = (
                f'<div class="retraction-reason"><strong>Retraction Reason:</strong> {_esc(rf.retraction_reason)}</div>'
                if rf.retraction_reason
                else ""
            )
            ret_items.append(
                f'<div class="retracted-item">'
                f'<div><span class="badge badge-muted">RETRACTED #{rf.finding_id}</span> '
                f'<span class="retracted-text">{_esc(rf.text)}</span></div>'
                f'{reason_html}'
                f'</div>'
            )
        retracted_html = f"""
        <section class="card section-card">
          <h2>Retracted Hypotheses (Ruled Out During Testing)</h2>
          <p class="muted small">These initial hypotheses were logged and subsequently retracted by the agent after deeper verification ruled them out.</p>
          {"".join(ret_items)}
        </section>
        """

    # Attack Surface Inventory Table
    if surface_records:
        surf_rows: List[str] = []
        for (host, port), rec in surface_records:
            status_parts = []
            if "http_status" in rec:
                status_parts.append(f"HTTP {rec['http_status']}")
            if "service" in rec:
                status_parts.append(str(rec["service"]))
            if "http_title" in rec:
                status_parts.append(f"“{rec['http_title']}”")
            status_cell = " · ".join(status_parts) if status_parts else "—"

            cov_badges: List[str] = []
            for cf in _COVERAGE_FIELDS:
                if cf in rec:
                    val = rec[cf]
                    cls = "badge-unverified" if (cf == "sqli_injectable" and val) else "badge-tool"
                    cov_badges.append(f'<span class="badge {cls}">{_esc(cf)}={_esc(val)}</span>')
            cov_cell = " ".join(cov_badges) if cov_badges else '<span class="muted small">—</span>'

            ev_list = [e.strip() for e in str(rec.get("evidence") or "").split(",") if e.strip()]
            ev_cell = " ".join(f'<code>{_esc(e)}</code>' for e in ev_list) if ev_list else "—"

            other_kv = ", ".join(
                f"{k}={v}"
                for k, v in rec.items()
                if k not in ("host", "port", "http_status", "service", "http_title", "evidence", *_COVERAGE_FIELDS)
            )
            surf_rows.append(
                f"<tr class='surface-row'>"
                f"<td><strong>{_esc(host)}</strong></td>"
                f"<td><code>{_esc(port)}</code></td>"
                f"<td>{_esc(status_cell)}</td>"
                f"<td>{cov_cell}</td>"
                f"<td class='details-cell'>{_esc(other_kv) if other_kv else '—'}</td>"
                f"<td>{ev_cell}</td>"
                f"</tr>"
            )
        surface_table_html = f"""
        <div class="filter-bar">
          <input type="search" id="surface-filter" class="filter-input"
                 placeholder="Filter attack surface by host, port, service, status, or attribute..."
                 oninput="filterRows('surface-row', this.value)" />
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Service / HTTP Title</th>
                <th>Testing &amp; Discovery Coverage</th>
                <th>Attributes</th>
                <th>Evidence Pointers</th>
              </tr>
            </thead>
            <tbody>
              {"".join(surf_rows)}
            </tbody>
          </table>
        </div>
        """
    else:
        surface_table_html = "<p class='muted'><em>No attack surface facts recorded for this engagement.</em></p>"

    # Engagement History Roll-Down
    if bundle.history:
        turns_html = "\n".join(_render_turn_history_html(h) for h in bundle.history)
        history_section_html = f"""
        <div class="history-controls">
          <input type="search" id="history-filter" class="filter-input"
                 placeholder="Search turns by tool name, reasoning, parameter, or output..."
                 oninput="filterDetails('turn-accordion', this.value)" />
          <div class="btn-group">
            <button type="button" class="btn" onclick="toggleAllTurns(true)">Expand All Turns</button>
            <button type="button" class="btn" onclick="toggleAllTurns(false)">Collapse All Turns</button>
          </div>
        </div>
        <div class="turns-container">
          {turns_html}
        </div>
        """
    else:
        history_section_html = "<p class='muted'><em>No per-turn trace history (trace.jsonl) recorded for this run.</em></p>"

    # Raw Engagement Log Stream
    if bundle.log_lines:
        log_items = "\n".join(f'<div class="log-line">{_esc(line)}</div>' for line in bundle.log_lines)
        log_stream_html = f'<div class="log-stream">{log_items}</div>'
    else:
        log_stream_html = "<p class='muted'><em>No engagement log lines recorded.</em></p>"

    # Evidence Index
    cited_ev = {f.evidence_id for f in bundle.active_findings if f.evidence_id}
    if bundle.evidence_keys:
        ev_rows = []
        for k in bundle.evidence_keys:
            tool_part, tgt_part = k.split(":", 1) if ":" in k else (k, "")
            is_cited = k in cited_ev
            cited_badge = (
                '<span class="badge badge-verified">Cited in Finding</span>'
                if is_cited
                else '<span class="badge badge-muted">Stored</span>'
            )
            ev_rows.append(
                f"<tr class='ev-row'>"
                f"<td><code>{_esc(k)}</code></td>"
                f"<td><span class='badge badge-tool'>{_esc(tool_part)}</span></td>"
                f"<td><code>{_esc(tgt_part)}</code></td>"
                f"<td>{cited_badge}</td>"
                f"</tr>"
            )
        evidence_table_html = f"""
        <div class="filter-bar">
          <input type="search" id="ev-filter" class="filter-input"
                 placeholder="Filter evidence keys by tool or target..."
                 oninput="filterRows('ev-row', this.value)" />
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Evidence Key</th>
                <th>Tool ID</th>
                <th>Target / Scope</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {"".join(ev_rows)}
            </tbody>
          </table>
        </div>
        """
    else:
        evidence_table_html = "<p class='muted'><em>No evidence files persisted for this run.</em></p>"

    exec_summary_html = _format_paragraphs_html(
        bundle.executive_summary or "Executive summary generation was skipped or produced no output."
    )
    closing_notes_html = _format_paragraphs_html(bundle.closing_notes)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Assessment Report — {_esc(bundle.target)}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --bg-card: #1e293b;
      --bg-elevated: #0b1120;
      --border: #334155;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --verified-bg: rgba(16, 185, 129, 0.15);
      --verified-text: #34d399;
      --verified-border: rgba(16, 185, 129, 0.4);
      --unverified-bg: rgba(245, 158, 11, 0.15);
      --unverified-text: #fbbf24;
      --unverified-border: rgba(245, 158, 11, 0.4);
      --tool-bg: rgba(56, 189, 248, 0.14);
      --tool-text: #7dd3fc;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.6;
    }}
    .container {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 2rem 1.5rem 4rem;
    }}
    .report-header {{
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.75rem 2rem;
      margin-bottom: 1.5rem;
    }}
    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .brand-eyebrow {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      font-weight: 700;
      margin-bottom: 0.25rem;
    }}
    .report-title {{
      margin: 0;
      font-size: 1.75rem;
      font-weight: 700;
      color: #fff;
    }}
    .meta-grid {{
      display: flex;
      flex-wrap: wrap;
      gap: 1.25rem;
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      font-size: 0.85rem;
      color: var(--text-muted);
    }}
    .meta-item strong {{ color: var(--text); }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.35rem;
    }}
    .kpi-label {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}
    .kpi-value {{
      font-size: 1.65rem;
      font-weight: 700;
      margin-top: 0.25rem;
      color: #fff;
    }}
    .kpi-sub {{
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-top: 0.15rem;
    }}
    .tabs-nav {{
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
      overflow-x: auto;
    }}
    .tab-btn {{
      background: transparent;
      color: var(--text-muted);
      border: none;
      border-bottom: 2px solid transparent;
      padding: 0.75rem 1.25rem;
      font-size: 0.92rem;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s ease;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{
      color: var(--accent);
      border-bottom-color: var(--accent);
    }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1.25rem;
    }}
    .card h2 {{
      margin-top: 0;
      font-size: 1.2rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.65rem;
      margin-bottom: 1rem;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 0.18rem 0.6rem;
      border-radius: 999px;
      font-size: 0.74rem;
      font-weight: 600;
      font-family: var(--font-mono);
    }}
    .badge-verified {{
      background: var(--verified-bg);
      color: var(--verified-text);
      border: 1px solid var(--verified-border);
    }}
    .badge-unverified {{
      background: var(--unverified-bg);
      color: var(--unverified-text);
      border: 1px solid var(--unverified-border);
    }}
    .badge-tool {{
      background: var(--tool-bg);
      color: var(--tool-text);
      border: 1px solid rgba(56, 189, 248, 0.3);
    }}
    .badge-asset {{
      background: rgba(148, 163, 184, 0.15);
      color: #e2e8f0;
      border: 1px solid rgba(148, 163, 184, 0.3);
    }}
    .badge-muted {{
      background: rgba(148, 163, 184, 0.12);
      color: var(--text-muted);
    }}
    .badge-warn {{
      background: rgba(244, 63, 94, 0.15);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.35);
    }}
    .finding-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.35rem 1.5rem;
      margin-bottom: 1rem;
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 0.85rem;
    }}
    .finding-id {{
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--accent);
      font-weight: 700;
    }}
    .finding-title {{
      margin: 0.15rem 0 0;
      font-size: 1.08rem;
      color: #fff;
    }}
    .finding-badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }}
    .finding-text {{
      white-space: pre-wrap;
      color: #e2e8f0;
      margin-bottom: 0.9rem;
    }}
    .proof-accordion {{
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.65rem 0.9rem;
      margin-top: 0.75rem;
    }}
    .proof-accordion summary {{
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--accent);
    }}
    .code-block {{
      margin: 0.65rem 0 0;
      padding: 0.85rem;
      background: #070b14;
      border: 1px solid #1e293b;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: #cbd5e1;
      overflow-x: auto;
      max-height: 420px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .evidence-img-wrap {{
      margin-top: 0.85rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem;
    }}
    .evidence-label {{
      font-size: 0.82rem;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }}
    .evidence-screenshot {{
      max-width: 100%;
      border-radius: 6px;
      border: 1px solid var(--border);
    }}
    .table-wrap {{ overflow-x: auto; }}
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}
    .data-table th, .data-table td {{
      text-align: left;
      padding: 0.7rem 0.85rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .data-table th {{
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      background: rgba(15, 23, 42, 0.5);
    }}
    .data-table tr:hover td {{
      background: rgba(56, 189, 248, 0.04);
    }}
    .details-cell {{
      max-width: 340px;
      word-break: break-word;
      color: var(--text-muted);
      font-size: 0.82rem;
    }}
    .filter-bar, .history-controls {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }}
    .filter-input {{
      flex: 1;
      min-width: 240px;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.6rem 0.9rem;
      border-radius: 8px;
      font-size: 0.88rem;
    }}
    .btn-group {{ display: flex; gap: 0.5rem; }}
    .btn {{
      background: var(--bg-elevated);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 0.5rem 0.9rem;
      border-radius: 8px;
      font-size: 0.82rem;
      cursor: pointer;
      font-weight: 600;
    }}
    .btn:hover {{ border-color: var(--accent); color: var(--accent); }}
    .turn-accordion {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 0.75rem;
      overflow: hidden;
    }}
    .turn-summary {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.85rem 1.2rem;
      cursor: pointer;
      gap: 1rem;
      flex-wrap: wrap;
      user-select: none;
    }}
    .turn-summary:hover {{ background: rgba(56, 189, 248, 0.05); }}
    .turn-summary-left {{
      display: flex;
      align-items: center;
      gap: 0.65rem;
      flex-wrap: wrap;
    }}
    .turn-num {{
      font-family: var(--font-mono);
      font-weight: 700;
      color: var(--accent);
      min-width: 72px;
    }}
    .turn-tools {{ display: flex; gap: 0.35rem; flex-wrap: wrap; }}
    .turn-summary-right {{
      display: flex;
      gap: 0.9rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }}
    .turn-body {{
      padding: 1rem 1.25rem 1.25rem;
      border-top: 1px solid var(--border);
      background: var(--bg-elevated);
    }}
    .turn-section {{ margin-bottom: 1rem; }}
    .turn-section:last-child {{ margin-bottom: 0; }}
    .turn-section-title {{
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
      font-weight: 700;
    }}
    .reasoning-box {{
      background: rgba(56, 189, 248, 0.06);
      border-left: 3px solid var(--accent);
      padding: 0.75rem 1rem;
      border-radius: 4px;
      white-space: pre-wrap;
      font-size: 0.88rem;
      color: #cbd5e1;
    }}
    .assistant-box {{
      background: rgba(148, 163, 184, 0.08);
      padding: 0.75rem 1rem;
      border-radius: 6px;
      white-space: pre-wrap;
      font-size: 0.9rem;
    }}
    .tool-call-item {{
      margin-bottom: 0.75rem;
      padding: 0.65rem 0.85rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .tool-call-sig {{
      font-size: 0.83rem;
      word-break: break-all;
    }}
    .retracted-item {{
      padding: 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    .retracted-text {{
      text-decoration: line-through;
      color: var(--text-muted);
    }}
    .retraction-reason {{
      margin-top: 0.35rem;
      font-size: 0.85rem;
      color: #cbd5e1;
    }}
    .log-stream {{
      font-family: var(--font-mono);
      font-size: 0.82rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      max-height: 500px;
      overflow-y: auto;
    }}
    .log-line {{
      padding: 0.35rem 0;
      border-bottom: 1px dashed rgba(148, 163, 184, 0.15);
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .muted {{ color: var(--text-muted); }}
    .small {{ font-size: 0.84rem; }}
    code {{
      font-family: var(--font-mono);
      font-size: 0.84em;
      background: rgba(15, 23, 42, 0.6);
      padding: 0.12rem 0.35rem;
      border-radius: 4px;
    }}
    @media print {{
      body {{ background: #fff; color: #000; }}
      .tabs-nav, .filter-bar, .history-controls {{ display: none !important; }}
      .tab-panel {{ display: block !important; page-break-after: always; }}
      .card, .finding-card, .turn-accordion {{
        background: #fff !important;
        color: #000 !important;
        border-color: #cbd5e1 !important;
      }}
      .code-block {{ max-height: none !important; background: #f8fafc !important; color: #0f172a !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="report-header">
      <div class="header-top">
        <div>
          <div class="brand-eyebrow">Tradecraft Security Assessment Deliverable</div>
          <h1 class="report-title">{_esc(bundle.target)}</h1>
        </div>
        <div>
          {destructive_badge}
          <span class="badge badge-tool">Profile: {_esc(profile_name)}</span>
        </div>
      </div>
      <div class="meta-grid">
        <div class="meta-item"><strong>Run ID:</strong> <code>{_esc(bundle.run_id or "in-memory")}</code></div>
        <div class="meta-item"><strong>Model:</strong> <code>{_esc(model_name)}</code></div>
        <div class="meta-item"><strong>Started:</strong> {_esc(started_at)}</div>
        <div class="meta-item"><strong>Completed:</strong> {_esc(ended_at)}</div>
        <div class="meta-item"><strong>Report Generated:</strong> {_esc(bundle.generated_at)}</div>
        {guidance_html}
      </div>
    </header>

    <section class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Active Findings</div>
        <div class="kpi-value">{total_findings}</div>
        <div class="kpi-sub">{verified_count} tool-verified · {total_findings - verified_count} unverified</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Attack Surface</div>
        <div class="kpi-value">{surface_count}</div>
        <div class="kpi-sub">Discovered host:port records</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Engagement Depth</div>
        <div class="kpi-value">{bundle.turns_used} turns</div>
        <div class="kpi-sub">{len(bundle.evidence_keys)} persisted evidence artifacts</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Telemetry &amp; Audit</div>
        <div class="kpi-value">{retracted_count} retracted</div>
        <div class="kpi-sub">{total_tokens:,} tokens · {wall_secs:.1f}s LLM time</div>
      </div>
    </section>

    <nav class="tabs-nav" role="tablist">
      <button class="tab-btn active" onclick="switchTab(event, 'tab-findings')">
        Overview &amp; Findings ({total_findings})
      </button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-surface')">
        Attack Surface Inventory ({surface_count})
      </button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-history')">
        Engagement History ({len(bundle.history)} turns)
      </button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-evidence')">
        Evidence Vault ({len(bundle.evidence_keys)})
      </button>
    </nav>

    <!-- TAB 1: OVERVIEW & FINDINGS -->
    <div id="tab-findings" class="tab-panel active">
      <section class="card">
        <h2>Executive Summary</h2>
        {exec_summary_html}
      </section>

      <section class="card">
        <h2>Summary of Findings</h2>
        {findings_matrix_html}
      </section>

      <section>
        {finding_cards_html}
      </section>

      {retracted_html}

      <section class="card">
        <h2>Agent's Closing Assessment</h2>
        {closing_notes_html}
      </section>
    </div>

    <!-- TAB 2: ATTACK SURFACE INVENTORY -->
    <div id="tab-surface" class="tab-panel">
      <section class="card">
        <h2>Attack Surface Inventory (Deterministic FactStore)</h2>
        {surface_table_html}
      </section>
    </div>

    <!-- TAB 3: ENGAGEMENT HISTORY (ROLL-DOWN TIMELINE) -->
    <div id="tab-history" class="tab-panel">
      <section class="card">
        <h2>Turn-by-Turn Engagement Timeline</h2>
        <p class="muted small">Click any turn below to roll down the model's internal reasoning, tool invocations, parameters, and raw results.</p>
        {history_section_html}
      </section>

      <section class="card">
        <h2>Chronological Engagement Log (<code>log.txt</code>)</h2>
        {log_stream_html}
      </section>
    </div>

    <!-- TAB 4: EVIDENCE VAULT -->
    <div id="tab-evidence" class="tab-panel">
      <section class="card">
        <h2>Persisted Evidence Index</h2>
        {evidence_table_html}
      </section>
    </div>
  </div>

  <script>
    function switchTab(evt, tabId) {{
      document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      const target = document.getElementById(tabId);
      if (target) target.classList.add('active');
      if (evt && evt.currentTarget) evt.currentTarget.classList.add('active');
    }}

    function toggleAllTurns(openState) {{
      document.querySelectorAll('.turn-accordion').forEach(d => {{
        if (d.style.display !== 'none') d.open = openState;
      }});
    }}

    function filterRows(rowClass, query) {{
      const q = (query || '').toLowerCase().trim();
      document.querySelectorAll('.' + rowClass).forEach(row => {{
        const text = row.innerText.toLowerCase();
        row.style.display = (!q || text.includes(q)) ? '' : 'none';
      }});
    }}

    function filterDetails(detailClass, query) {{
      const q = (query || '').toLowerCase().trim();
      document.querySelectorAll('.' + detailClass).forEach(det => {{
        const text = det.innerText.toLowerCase();
        const match = !q || text.includes(q);
        det.style.display = match ? '' : 'none';
        if (q && match) det.open = true;
      }});
    }}
  </script>
</body>
</html>
"""
