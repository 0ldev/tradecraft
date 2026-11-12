"""Craft Studio API + embedded dashboard (Tradecraft 2.0, Phase 3).

A tiny read-only web app over persisted run directories:

    GET /                    -> dashboard (embedded single-file HTML)
    GET /api/runs            -> run list under TRADECRAFT_HOME (or --run-dir)
    GET /api/run/<run_id>    -> one run's full data payload

Deliberately dependency-light and deliberately static: the dashboard is
one HTML file with vanilla JS polling `/api/...` every few seconds. No
build step, no framework frontend, no websocket plumbing -- an
engagement's state changes at tool-result cadence (seconds), which
polling handles fine, and the whole UI stays auditable in one file.

FastAPI/uvicorn are optional extras (`pip install tradecraft[studio]`):
the import lives inside serve() so the rest of Tradecraft never needs
them.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List

from tradecraft.studio.data import list_runs, run_data

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Craft Studio — Tradecraft</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0d1117; --panel:#161b22; --edge:#30363d; --fg:#e6edf3;
          --dim:#8b949e; --vuln:#f85149; --clean:#3fb950; --part:#d29922;
          --untested:#21262d; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; padding:24px; }
  h1 { font-size:20px; margin-bottom:4px; }
  h2 { font-size:15px; margin:20px 0 8px; color:var(--dim); text-transform:uppercase; letter-spacing:.05em; }
  .sub { color:var(--dim); margin-bottom:16px; }
  .panel { background:var(--panel); border:1px solid var(--edge); border-radius:8px; padding:14px; margin-bottom:16px; }
  select { background:var(--panel); color:var(--fg); border:1px solid var(--edge); border-radius:6px; padding:6px 10px; }
  table { border-collapse:collapse; width:100%; }
  th,td { padding:6px 10px; border:1px solid var(--edge); text-align:left; }
  th { color:var(--dim); font-weight:600; }
  td.cell { text-align:center; font-weight:700; border-radius:4px; }
  .vuln { background:var(--vuln); color:#fff; }
  .clean { background:var(--clean); color:#0d1117; }
  .part { background:var(--part); color:#0d1117; }
  .untested { background:var(--untested); color:var(--dim); }
  .finding { padding:8px 10px; border-left:3px solid var(--vuln); background:var(--untested); border-radius:0 6px 6px 0; margin-bottom:8px; }
  .note { color:var(--dim); padding:2px 0; border-bottom:1px dotted var(--edge); }
  .stats span { display:inline-block; margin-right:16px; color:var(--dim); }
  .stats b { color:var(--fg); }
  #trace { font-family:ui-monospace,monospace; font-size:12px; max-height:300px; overflow:auto; white-space:pre-wrap; color:var(--dim); }
  .legend span { margin-right:14px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:middle; }
</style>
</head>
<body>
<h1> Craft Studio</h1>
<div class="sub">live view over persisted Tradecraft engagements — read-only</div>

<div class="panel">
  <select id="runSelect" onchange="load()"><option>loading runs…</option></select>
  <div class="stats" id="stats" style="margin-top:10px"></div>
</div>

<h2>Coverage Matrix</h2>
<div class="panel" id="coverage">no coverage data</div>

<h2>Findings</h2>
<div class="panel" id="findings">no findings</div>

<h2>Log Notes</h2>
<div class="panel" id="notes">no notes</div>

<h2>Trace Tail</h2>
<div class="panel"><div id="trace"></div></div>

<script>
const STATUS_CLASS = { vulnerable:'vuln', clean:'clean', partial:'part', untested:'untested' };
const STATUS_LABEL = { vulnerable:'VULN', clean:'clean', partial:'part!', untested:'-' };

async function j(url){ const r = await fetch(url); return r.json(); }

async function init(){
  const runs = await j('/api/runs');
  const sel = document.getElementById('runSelect');
  sel.innerHTML = '';
  if (!runs.length){ sel.innerHTML = '<option>no runs found</option>'; return; }
  for (const r of runs){
    const o = document.createElement('option');
    o.value = r.run_id;
    o.textContent = `${r.target} — ${r.run_id} (${r.findings_count||0} findings, ${r.turns_used||0} turns)`;
    sel.appendChild(o);
  }
  load();
}

async function load(){
  const id = document.getElementById('runSelect').value;
  if (!id) return;
  const d = await j('/api/run/' + encodeURIComponent(id));
  document.getElementById('stats').innerHTML =
    `target <b>${esc(d.manifest?.target||'?')}</b>
     <span>model <b>${esc(d.manifest?.model||'?')}</b></span>
     <span>turns <b>${d.manifest?.turns_used??'?'}</b></span>
     <span>findings <b>${d.log?.findings?.length??0}</b></span>`;

  const cov = document.getElementById('coverage');
  if (!d.coverage){ cov.textContent = 'no coverage data'; }
  else {
    let html = '<div class="legend" style="margin-bottom:8px">' +
      ['vulnerable|VULN','clean|clean','partial|part!','untested|-'].map(s=>{
        const [k,l]=s.split('|'); return `<span><span class="dot ${STATUS_CLASS[k]}"></span>${l}</span>`;
      }).join('') + '</div><table><tr><th>target</th>' +
      d.coverage.classes.map(c=>`<th>${esc(c)}</th>`).join('') + '</tr>';
    for (const row of d.coverage.rows){
      html += `<tr><td><b>${esc(row.target)}</b></td>` +
        d.coverage.classes.map(c=>{
          const s = row.cells[c];
          return `<td class="cell ${STATUS_CLASS[s]}">${STATUS_LABEL[s]}</td>`;
        }).join('') + '</tr>';
    }
    cov.innerHTML = html + '</table>';
  }

  document.getElementById('findings').innerHTML = (d.log?.findings?.length)
    ? d.log.findings.map(f=>`<div class="finding">${esc(f.raw)}</div>`).join('')
    : 'no findings';
  document.getElementById('notes').innerHTML = (d.log?.notes?.length)
    ? d.log.notes.map(n=>`<div class="note">${esc(n)}</div>`).join('')
    : 'no notes';
  document.getElementById('trace').textContent =
    (d.trace_lines||[]).slice(-40).join('\\n') || '(no trace)';
}

function esc(s){ return String(s??'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

init();
setInterval(load, 5000);
</script>
</body>
</html>"""


def build_app(runs_dir: str | Path | None = None) -> Any:
    """FastAPI app. `runs_dir` restricts /api/runs to one directory tree
    (e.g. a specific target's runs/); None scans the default home."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:
        raise ImportError(
            "Craft Studio needs the optional 'studio' extras: "
            "pip install 'tradecraft[studio]'"
        ) from exc

    app = FastAPI(title="Craft Studio", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _DASHBOARD_HTML

    @app.get("/api/runs", response_class=JSONResponse)
    def runs() -> List[Dict[str, str]]:
        return list_runs(runs_dir)

    @app.get("/api/run/{run_id}", response_class=JSONResponse)
    def one(run_id: str) -> Dict[str, Any]:
        # Resolve against the runs_dir scan first (safe ids only, since
        # run ids come from that listing), falling back to a direct path
        # for --run-dir-style single-run serving where the "run_id" may
        # be a path.
        for entry in list_runs(runs_dir):
            if entry["run_id"] == run_id:
                return run_data(entry["path"])
        candidate = Path(run_id)
        if candidate.is_dir():
            return run_data(candidate)
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")

    return app


def serve(
    runs_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8480,
) -> None:
    """Blocking serve (used by `tradecraft studio`). Returns when the
    server stops; the CLI wraps it so Ctrl-C stays clean."""
    import uvicorn

    app = build_app(runs_dir)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    # Run without signal handling so the outer KeyboardInterrupt reaches us.
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        server.should_exit = True
        thread.join(timeout=2)
