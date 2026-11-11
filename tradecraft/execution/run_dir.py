"""
Run directory, run identity, and storage management for Tradecraft engagements.

Storage layout:
$TRADECRAFT_HOME/targets/<safe_target>/
    runs/
        <run_id>/
            manifest.json
            log.txt
            trace.jsonl
            facts.json
            evidence/
                <safe_sub_target>/<tool_id>.json
    latest -> symlink to most recently completed run_id directory
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.policy.credential_budget import TOTAL_BUDGET_PER_ENDPOINT

TRADECRAFT_HOME_ENV = "TRADECRAFT_HOME"
DEFAULT_TRADECRAFT_HOME = "~/.tradecraft"


def get_tradecraft_home(env_val: Optional[str] = None) -> Path:
    """Resolves TRADECRAFT_HOME directory from environment or default."""
    raw = env_val if env_val is not None else os.environ.get(TRADECRAFT_HOME_ENV, DEFAULT_TRADECRAFT_HOME)
    path = Path(raw).expanduser().resolve()
    return path


def generate_run_id(now: Optional[datetime] = None) -> str:
    """Generates an ISO8601-compact timestamp + 6-hex-char run identifier.
    Format: YYYYMMDDTHHMMSSZ_<6hex>, e.g. 20261101T143200Z_a3f9c1.
    Sorts chronologically as a plain string."""
    ts_now = now or datetime.now(timezone.utc)
    ts = ts_now.strftime("%Y%m%dT%H%M%SZ")
    suffix = secrets.token_hex(3)
    return f"{ts}_{suffix}"


def get_target_dir(target: str, tradecraft_home: Optional[Path] = None) -> Path:
    """Computes the target directory path under TRADECRAFT_HOME using sanitized target."""
    home = tradecraft_home or get_tradecraft_home()
    safe_target = EvidenceStore._sanitize_component(target)
    return home / "targets" / safe_target


def create_run_dir(
    target: str,
    run_id: Optional[str] = None,
    tradecraft_home: Optional[Path] = None,
) -> Tuple[str, Path]:
    """Creates a new run directory with 0o700 permissions and an empty evidence/ subdir.
    Returns (run_id, run_dir_path)."""
    target_dir = get_target_dir(target, tradecraft_home)
    rid = run_id or generate_run_id()
    run_dir = target_dir / "runs" / rid
    evidence_dir = run_dir / "evidence"

    evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in (target_dir, target_dir / "runs", run_dir, evidence_dir):
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass

    return rid, run_dir


def update_latest_symlink(target_dir: Path, run_id: str) -> None:
    """Atomically updates the 'latest' symlink inside target_dir to point to runs/<run_id>.
    Uses a temporary symlink and atomic replace."""
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_path = Path("runs") / run_id
    latest_symlink = target_dir / "latest"

    temp_name = f".latest.tmp.{secrets.token_hex(4)}"
    temp_symlink = target_dir / temp_name

    try:
        if temp_symlink.is_symlink() or temp_symlink.exists():
            temp_symlink.unlink()
        os.symlink(target_path, temp_symlink)
        os.replace(temp_symlink, latest_symlink)
    except OSError:
        # Fallback if atomic replace fails
        if temp_symlink.is_symlink() or temp_symlink.exists():
            try:
                temp_symlink.unlink()
            except OSError:
                pass


def resolve_run_dir(
    target: str,
    run_ref: str,
    tradecraft_home: Optional[Path] = None,
) -> Tuple[str, Path]:
    """Resolves a run reference ('latest' or specific run_id) for a target.
    Returns (run_id, run_dir_path). Raises FileNotFoundError if not found."""
    home = tradecraft_home or get_tradecraft_home()
    target_dir = get_target_dir(target, home)

    if run_ref == "latest":
        latest_symlink = target_dir / "latest"
        if not latest_symlink.is_symlink() and not latest_symlink.exists():
            raise FileNotFoundError(f"no completed runs found for target '{target}'")
        run_dir = latest_symlink.resolve()
        if not run_dir.is_dir():
            raise FileNotFoundError(f"latest run directory does not exist for target '{target}'")
        return run_dir.name, run_dir

    p = Path(run_ref)
    if p.is_dir() and (p / "manifest.json").is_file():
        return p.name, p.resolve()

    run_dir = target_dir / "runs" / run_ref
    if run_dir.is_dir():
        return run_ref, run_dir

    targets_base = home / "targets"
    if targets_base.is_dir():
        for t_dir in targets_base.iterdir():
            candidate = t_dir / "runs" / run_ref
            if candidate.is_dir():
                return run_ref, candidate

    raise FileNotFoundError(f"run '{run_ref}' not found for target '{target}'")


def write_manifest(run_dir: Path, manifest_data: Dict[str, Any]) -> Path:
    """Writes manifest.json into run_dir with 0o600 permissions."""
    manifest_path = run_dir / "manifest.json"
    content = json.dumps(manifest_data, indent=2)
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content + "\n")
    return manifest_path


def read_manifest(run_dir: Path) -> Dict[str, Any]:
    """Reads manifest.json from run_dir."""
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest not found at {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def create_initial_manifest(
    run_dir: Path,
    run_id: str,
    target: str,
    model: str = "",
    max_turns: int = 0,
    mode: str = "fresh",
    seed_from: Optional[str] = None,
    started_at: Optional[str] = None,
    profile: Optional[str] = None,
    tool_ids: Optional[list] = None,
    allow_destructive: bool = False,
    allow_destructive_categories: Optional[frozenset] = None,
    credential_budget: Optional[int] = None,
    guidance: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates and writes the initial manifest.json at engagement start.

    profile/tool_ids/allow_destructive/allow_destructive_categories/
    credential_budget record how this run was actually launched --
    without them, a run directory on disk gives no way to tell afterwards
    whether a destructive tool (hydra, sqli_login, ...) was available for
    this specific run, what its account-lockout-risk budget per endpoint
    was, or which --tools/--profile selection was in effect. tool_ids is
    the resolved, effective id list
    (CLI --tools/--profile both collapse to this before run_engagement
    is called); None means "unrestricted" the same way it does in
    run_engagement itself, not "unknown."

    guidance is the operator's free-text --guidance string, if any, recorded
    for the same reason: a run directory on disk should say whether a
    narrower scope was deliberate operator instruction rather than an
    incomplete engagement.
    """
    now_iso = started_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "run_id": run_id,
        "target": target,
        "mode": mode,
        "seed_from": seed_from,
        "guidance": guidance,
        "model": model,
        "max_turns": max_turns,
        "profile": profile,
        "tool_ids": list(tool_ids) if tool_ids is not None else None,
        "allow_destructive": allow_destructive,
        "allow_destructive_categories": sorted(allow_destructive_categories) if allow_destructive_categories else [],
        "credential_budget": (
            credential_budget if credential_budget is not None else TOTAL_BUDGET_PER_ENDPOINT
        ),
        "started_at": now_iso,
        "ended_at": None,
        "turns_used": 0,
        "findings_count": 0,
    }
    write_manifest(run_dir, manifest)
    return manifest


def finalize_manifest(
    run_dir: Path,
    turns_used: int,
    findings_count: int,
    ended_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Updates manifest.json upon engagement completion with ended_at, turns_used, and findings_count."""
    manifest = read_manifest(run_dir)
    manifest["ended_at"] = ended_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest["turns_used"] = turns_used
    manifest["findings_count"] = findings_count
    write_manifest(run_dir, manifest)
    return manifest


def save_facts_json(run_dir: Path, facts: FactStore) -> Path:
    """Saves FactStore records to facts.json in run_dir with 0o600 permissions."""
    facts_path = run_dir / "facts.json"
    records = [record for _, record in facts.sorted_records()]
    content = json.dumps(records, indent=2)
    fd = os.open(facts_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content + "\n")
    return facts_path


def load_facts_json(run_dir: Path) -> FactStore:
    """Loads FactStore from facts.json in run_dir if present, otherwise returns empty FactStore."""
    store = FactStore()
    facts_path = run_dir / "facts.json"
    if facts_path.is_file():
        try:
            with open(facts_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    store.merge_many(data)
        except (json.JSONDecodeError, OSError):
            pass
    return store


def load_seed_context(
    target: str,
    seed_ref: str,
    tradecraft_home: Optional[Path] = None,
) -> Tuple[str, str]:
    """Loads prior facts and findings from a seed run for complement mode.
    Validates that the seed run's target matches `target`.
    Returns (seed_run_id, seed_context_prompt_block)."""
    seed_run_id, seed_dir = resolve_run_dir(target, seed_ref, tradecraft_home)
    manifest = read_manifest(seed_dir)

    seed_target = manifest.get("target")
    if seed_target != target:
        raise ValueError(
            f"seed run target '{seed_target}' does not match current target '{target}'"
        )

    ended_at = manifest.get("ended_at") or "(in-progress/interrupted)"

    prior_facts_store = load_facts_json(seed_dir)
    prior_facts_render = prior_facts_store.render()

    log_path = seed_dir / "log.txt"
    if log_path.is_file():
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                prior_log_render = f.read().strip()
                if not prior_log_render:
                    prior_log_render = "(empty -- nothing logged)"
        except OSError:
            prior_log_render = "(error reading prior log)"
    else:
        prior_log_render = "(no prior log recorded)"

    seed_context = (
        f"--- Known from a prior engagement (run {seed_run_id}, ended {ended_at}) ---\n"
        f"Prior facts:\n"
        f"{prior_facts_render}\n\n"
        f"Prior findings and notes:\n"
        f"{prior_log_render}\n"
        f"---"
    )
    return seed_run_id, seed_context
