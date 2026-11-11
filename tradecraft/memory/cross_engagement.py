"""
Cross-engagement vector + FTS5 hybrid memory store (`$TRADECRAFT_HOME/memory.db`).

Provides zero-external-dependency semantic and keyword retrieval across all
historical engagements. Uses:
1. SQLite FTS5 (BM25) for exact technical tokens (CVEs, headers, ports, paths, versions).
2. Deterministic local feature-hashed subword/word n-gram cosine vectors (256-dim)
   for fuzzy/conceptual similarity without requiring PyTorch or an external server.
3. Optional neural embeddings via `litellm.embedding()` when `LLM_EMBEDDING_MODEL`
   is set in the environment, fused with BM25 and local vectors via Reciprocal Rank
   Fusion (RRF).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import litellm

from tradecraft.execution.run_dir import get_tradecraft_home, load_facts_json, read_manifest
from tradecraft.memory.facts import FactStore
from tradecraft.memory.log import EngagementMemory, LogEntry

MEMORY_DB_FILENAME = "memory.db"
LOCAL_VECTOR_DIM = 256
RRF_K = 60

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-/]{1,62}", re.IGNORECASE)
_FINDING_LINE_RE = re.compile(
    r"^FINDING(?:\s+#(?P<id>\d+))?(?P<retracted>\s+\[RETRACTED\])?"
    r"(?:\s+\[(?:evidence:\s*(?P<ev>[^\]]+)|unverified:\s*(?P<unv>[^\]]+))\])?"
    r":\s*(?P<text>.*)$"
)
_RETRACTION_NOTE_RE = re.compile(
    r"^Finding\s+#(?P<id>\d+)\s+retracted:\s*(?P<reason>.*)$",
    re.IGNORECASE,
)

# Common two-label public suffix patterns (ccSLDs) so root domain extraction
# groups e.g. `api.example.com.br` and `www.example.com.br` under
# `example.com.br` instead of `com.br`.
_COMPOUND_TLD_SECOND_LABELS = {
    "com", "co", "org", "net", "gov", "edu", "mil", "ac", "Jus", "jus",
    "ind", "art", "tur", "etc", "adm", "adv", "agr", "arq", "ato", "bio",
    "bmd", "cim", "cng", "cnt", "ecn", "eng", "esp", "far", "fnd", "fot",
    "fst", "ggf", "imb", "inf", "jor", "lel", "mat", "med", "mus", "not",
    "ntr", "odo", "ppg", "pro", "psc", "psi", "qsl", "radio", "rec", "slg",
    "srv", "tmp", "trd", "vet", "zlg",
}


def extract_root_domain(target: str) -> str:
    """Extracts the registrable root domain (or IP address) from a target string."""
    cleaned = (target or "").strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned and not cleaned.startswith("["):
        cleaned = cleaned.split(":", 1)[0]
    cleaned = cleaned.strip(".")
    if not cleaned:
        return ""

    try:
        ipaddress.ip_address(cleaned.strip("[]"))
        return cleaned.strip("[]")
    except ValueError:
        pass

    parts = [p for p in cleaned.split(".") if p]
    if len(parts) <= 2:
        return cleaned
    if len(parts[-1]) == 2 and parts[-2] in _COMPOUND_TLD_SECOND_LABELS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def compute_local_vector(text: str, dim: int = LOCAL_VECTOR_DIM) -> List[float]:
    """Computes a L2-normalized dense vector via signed feature hashing over word
    unigrams, word bigrams, and character 3..5-grams. Deterministic, offline,
    and fast in pure Python."""
    vec = [0.0] * dim
    raw = (text or "").lower()
    tokens = _TOKEN_RE.findall(raw)
    if not tokens:
        return vec

    features: List[Tuple[str, float]] = []
    for tok in tokens:
        features.append((f"w:{tok}", 2.0))
        # Sub-tokens split on punctuation (e.g. cve-2024-1234 -> cve, 2024, 1234)
        subparts = [p for p in re.split(r"[_.\-/]+", tok) if len(p) >= 2]
        if len(subparts) > 1:
            for sp in subparts:
                features.append((f"sub:{sp}", 1.2))
        # Character n-grams for morphological/partial technical matches
        padded = f"<{tok}>"
        for n in (3, 4):
            if len(padded) >= n:
                for i in range(len(padded) - n + 1):
                    features.append((f"c{n}:{padded[i:i + n]}", 0.5))

    for i in range(len(tokens) - 1):
        features.append((f"bi:{tokens[i]}_{tokens[i + 1]}", 1.5))

    for feat, weight in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "little")
        idx = h % dim
        sign = 1.0 if ((h >> 32) & 1) == 0 else -1.0
        vec[idx] += sign * weight

    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0.0:
        vec = [v / norm for v in vec]
    return vec


def _pack_vector(vec: List[float]) -> bytes:
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack_vector(blob: bytes) -> List[float]:
    if not blob:
        return []
    count = len(blob) // 4
    return list(struct.unpack(f"<{count}f", blob))


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def compute_neural_embedding(
    text: str,
    model: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[List[float]]:
    """Optionally computes a neural embedding via litellm.embedding() if
    LLM_EMBEDDING_MODEL is configured. Never raises on failure -- falls back
    cleanly to None so local vector + BM25 search always succeeds."""
    emb_model = model if model is not None else os.environ.get("LLM_EMBEDDING_MODEL", "").strip()
    if not emb_model:
        return None
    base = api_base if api_base is not None else (os.environ.get("LLM_EMBEDDING_BASE_URL") or os.environ.get("LLM_BASE_URL") or None)
    key = api_key if api_key is not None else (os.environ.get("LLM_EMBEDDING_API_KEY") or os.environ.get("LLM_API_KEY") or None)
    try:
        kwargs: Dict[str, Any] = {"model": emb_model, "input": [text[:8000]], "timeout": 15}
        if base:
            kwargs["api_base"] = base
        if key:
            kwargs["api_key"] = key
        resp = litellm.embedding(**kwargs)
        data = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else None)
        if data and len(data) > 0:
            item = data[0]
            emb = getattr(item, "embedding", None) if not isinstance(item, dict) else item.get("embedding")
            if isinstance(emb, list) and emb:
                floats = [float(x) for x in emb]
                norm = math.sqrt(sum(v * v for v in floats))
                if norm > 0.0:
                    floats = [v / norm for v in floats]
                return floats
    except Exception:
        return None
    return None


@dataclass
class MemoryRecord:
    entry_id: int
    run_id: str
    target: str
    root_domain: str
    kind: str  # "finding" | "fact" | "note"
    text: str
    tags: str
    evidence_id: Optional[str] = None
    created_at: str = ""
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "run_id": self.run_id,
            "target": self.target,
            "root_domain": self.root_domain,
            "kind": self.kind,
            "text": self.text,
            "score": round(self.score, 4),
        }
        if self.tags:
            out["tags"] = self.tags
        if self.evidence_id:
            out["evidence_id"] = self.evidence_id
        if self.created_at:
            out["created_at"] = self.created_at
        return out


class CrossEngagementMemory:
    """SQLite-backed hybrid (FTS5 BM25 + local n-gram vector + optional neural
    embedding) store across historical engagements."""

    def __init__(self, db_path: Optional[str | Path] = None, tradecraft_home: Optional[Path] = None):
        self._is_memory_db = str(db_path) == ":memory:"
        self._shared_conn: Optional[sqlite3.Connection] = None
        if self._is_memory_db:
            self.db_path = Path(":memory:")
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
            self._init_db()
            return

        if db_path is not None:
            self.db_path = Path(db_path).expanduser().resolve()
        else:
            home = tradecraft_home or get_tradecraft_home()
            self.db_path = home / MEMORY_DB_FILENAME

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
        except (OSError, sqlite3.OperationalError):
            # Fallback to in-memory SQLite if the target filesystem is read-only
            # or uncreatable (e.g. non-persisted unit tests running without TRADECRAFT_HOME)
            self._is_memory_db = True
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_hash TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    root_domain TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    text TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '',
                    evidence_id TEXT,
                    created_at TEXT NOT NULL,
                    local_vec BLOB NOT NULL,
                    neural_vec BLOB,
                    neural_model TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_root_domain ON memory_entries(root_domain)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_target ON memory_entries(target)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_kind ON memory_entries(kind)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_run_id ON memory_entries(run_id)"
            )
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                    text,
                    tags,
                    target,
                    root_domain,
                    kind,
                    content='memory_entries',
                    content_rowid='id',
                    tokenize='unicode61 tokenchars ''_.-/'''
                )
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS memory_entries_ai AFTER INSERT ON memory_entries BEGIN
                    INSERT INTO memory_fts(rowid, text, tags, target, root_domain, kind)
                    VALUES (new.id, new.text, new.tags, new.target, new.root_domain, new.kind);
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS memory_entries_ad AFTER DELETE ON memory_entries BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, text, tags, target, root_domain, kind)
                    VALUES ('delete', old.id, old.text, old.tags, old.target, old.root_domain, old.kind);
                END
                """
            )
        if not self._is_memory_db:
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def add_entry(
        self,
        *,
        run_id: str,
        target: str,
        kind: str,
        text: str,
        tags: str = "",
        evidence_id: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> bool:
        """Inserts a single entry into the cross-engagement store. Deduplicates by
        (target, kind, text) content hash so re-indexing the same run is idempotent.
        Returns True if inserted, False if already present."""
        clean_text = (text or "").strip()
        if not clean_text:
            return False
        clean_target = (target or "").strip()
        root_domain = extract_root_domain(clean_target)
        now_iso = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        dedup_key = f"{clean_target.lower()}|{kind.lower()}|{clean_text}"
        content_hash = hashlib.sha256(dedup_key.encode("utf-8")).hexdigest()

        combined_for_embedding = f"{clean_target} {tags} {clean_text}".strip()
        local_vec = compute_local_vector(combined_for_embedding)
        local_blob = _pack_vector(local_vec)

        neural_model = os.environ.get("LLM_EMBEDDING_MODEL", "").strip() or None
        neural_vec = compute_neural_embedding(combined_for_embedding, model=neural_model) if neural_model else None
        neural_blob = _pack_vector(neural_vec) if neural_vec else None

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO memory_entries
                (content_hash, run_id, target, root_domain, kind, text, tags, evidence_id, created_at, local_vec, neural_vec, neural_model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    content_hash,
                    run_id,
                    clean_target,
                    root_domain,
                    kind,
                    clean_text,
                    tags,
                    evidence_id,
                    now_iso,
                    local_blob,
                    neural_blob,
                    neural_model if neural_blob else None,
                ),
            )
            return cursor.rowcount > 0

    def index_live_run(
        self,
        *,
        run_id: str,
        target: str,
        memory: EngagementMemory,
        facts: FactStore,
        created_at: Optional[str] = None,
    ) -> int:
        """Indexes active findings, substantive notes, and port/service facts from
        an in-memory engagement run. Returns the number of newly inserted entries."""
        inserted = 0
        now_iso = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        tech_tags = self._extract_tags_from_facts(facts)

        for entry in memory.entries:
            if entry.kind == "finding":
                if entry.retracted:
                    continue
                if self.add_entry(
                    run_id=run_id,
                    target=target,
                    kind="finding",
                    text=entry.text,
                    tags=tech_tags,
                    evidence_id=entry.evidence_id if entry.evidence_verified else None,
                    created_at=now_iso,
                ):
                    inserted += 1
            elif entry.kind == "note":
                if _RETRACTION_NOTE_RE.match(entry.text.strip()):
                    continue
                if len(entry.text.strip()) < 20:
                    continue
                if self.add_entry(
                    run_id=run_id,
                    target=target,
                    kind="note",
                    text=entry.text,
                    tags=tech_tags,
                    created_at=now_iso,
                ):
                    inserted += 1

        for (host, port), record in facts.sorted_records():
            details = ", ".join(
                f"{k}={v}" for k, v in sorted(record.items()) if k not in ("host", "port", "evidence")
            )
            if not details:
                continue
            fact_text = f"{host}:{port} -- {details}"
            ev = record.get("evidence")
            port_tags = self._extract_tags_from_record(record)
            if self.add_entry(
                run_id=run_id,
                target=host or target,
                kind="fact",
                text=fact_text,
                tags=port_tags,
                evidence_id=str(ev) if ev else None,
                created_at=now_iso,
            ):
                inserted += 1

        return inserted

    def index_run_dir(self, run_dir: Path) -> int:
        """Indexes a persisted run directory on disk (`manifest.json`, `log.txt`, `facts.json`).
        Idempotent -- safe to call repeatedly during backfill."""
        run_dir = Path(run_dir).expanduser().resolve()
        manifest: Dict[str, Any] = {}
        try:
            manifest = read_manifest(run_dir)
        except (FileNotFoundError, ValueError, OSError):
            pass

        run_id = str(manifest.get("run_id") or run_dir.name)
        target = str(manifest.get("target") or "")
        if not target and run_dir.parent.name == "runs":
            target = run_dir.parent.parent.name
        if not target:
            target = "unknown"
        created_at = str(manifest.get("ended_at") or manifest.get("started_at") or "") or None

        facts = load_facts_json(run_dir)
        memory = self._parse_log_file(run_dir / "log.txt")
        return self.index_live_run(
            run_id=run_id,
            target=target,
            memory=memory,
            facts=facts,
            created_at=created_at,
        )

    def backfill_all(self, tradecraft_home: Optional[Path] = None, target_filter: Optional[str] = None) -> Tuple[int, int]:
        """Scans `$TRADECRAFT_HOME/targets/*/runs/*` and indexes all persisted runs.
        Returns (runs_processed, entries_inserted)."""
        home = tradecraft_home or get_tradecraft_home()
        targets_base = home / "targets"
        if not targets_base.is_dir():
            return 0, 0

        runs_processed = 0
        entries_inserted = 0
        for t_dir in sorted(targets_base.iterdir()):
            if not t_dir.is_dir():
                continue
            if target_filter and t_dir.name.lower() != target_filter.lower():
                # Also check manifest target inside runs if directory name was sanitized
                pass
            runs_parent = t_dir / "runs"
            if not runs_parent.is_dir():
                continue
            for r_dir in sorted(runs_parent.iterdir()):
                if not r_dir.is_dir():
                    continue
                if not ((r_dir / "manifest.json").is_file() or (r_dir / "log.txt").is_file() or (r_dir / "facts.json").is_file()):
                    continue
                if target_filter:
                    try:
                        m = read_manifest(r_dir)
                        m_target = str(m.get("target") or "")
                    except Exception:
                        m_target = t_dir.name
                    if target_filter.lower() not in (m_target.lower(), t_dir.name.lower()):
                        continue
                runs_processed += 1
                entries_inserted += self.index_run_dir(r_dir)
        return runs_processed, entries_inserted

    def search(
        self,
        query: str,
        *,
        target: Optional[str] = None,
        kind: Optional[str] = None,
        limit: int = 10,
        exclude_run_id: Optional[str] = None,
    ) -> List[MemoryRecord]:
        """Hybrid search combining FTS5 BM25 keyword ranking, local n-gram vector
        cosine similarity, and optional neural embedding similarity via Reciprocal
        Rank Fusion (RRF)."""
        clean_query = (query or "").strip()
        max_limit = max(1, min(int(limit or 10), 50))

        where_clauses: List[str] = []
        params: List[Any] = []

        if target and target.strip():
            t_clean = target.strip().lower()
            root_dom = extract_root_domain(t_clean)
            where_clauses.append("(LOWER(target) = ? OR LOWER(root_domain) = ? OR LOWER(target) LIKE ?)")
            params.extend([t_clean, root_dom, f"%{t_clean}%"])

        if kind and kind.strip():
            where_clauses.append("LOWER(kind) = ?")
            params.append(kind.strip().lower())

        if exclude_run_id and exclude_run_id.strip():
            where_clauses.append("run_id != ?")
            params.append(exclude_run_id.strip())

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, run_id, target, root_domain, kind, text, tags, evidence_id, created_at, local_vec, neural_vec, neural_model
                FROM memory_entries
                {where_sql}
                ORDER BY id DESC
                """,
                params,
            ).fetchall()

            if not rows:
                return []

            if not clean_query:
                return [
                    MemoryRecord(
                        entry_id=r["id"],
                        run_id=r["run_id"],
                        target=r["target"],
                        root_domain=r["root_domain"],
                        kind=r["kind"],
                        text=r["text"],
                        tags=r["tags"],
                        evidence_id=r["evidence_id"],
                        created_at=r["created_at"],
                        score=1.0,
                    )
                    for r in rows[:max_limit]
                ]

            candidate_ids = {r["id"] for r in rows}

            # 1. FTS5 BM25 Ranking
            fts_ranks: Dict[int, int] = {}
            fts_query = self._build_fts_query(clean_query)
            if fts_query:
                try:
                    fts_rows = conn.execute(
                        """
                        SELECT rowid, bm25(memory_fts, 2.0, 1.5, 1.0, 1.0, 0.5) AS score
                        FROM memory_fts
                        WHERE memory_fts MATCH ?
                        ORDER BY score ASC
                        LIMIT 200
                        """,
                        (fts_query,),
                    ).fetchall()
                    rank_pos = 1
                    for fr in fts_rows:
                        rid = int(fr["rowid"])
                        if rid in candidate_ids:
                            fts_ranks[rid] = rank_pos
                            rank_pos += 1
                except sqlite3.OperationalError:
                    pass

        # 2. Local Dense Vector Cosine Ranking
        q_local_vec = compute_local_vector(clean_query)
        local_scores: List[Tuple[int, float]] = []
        for r in rows:
            entry_vec = _unpack_vector(r["local_vec"])
            sim = cosine_similarity(q_local_vec, entry_vec)
            if sim > 0.05:
                local_scores.append((r["id"], sim))
        local_scores.sort(key=lambda x: x[1], reverse=True)
        local_ranks: Dict[int, int] = {
            rid: idx + 1 for idx, (rid, _) in enumerate(local_scores)
        }
        local_sim_map: Dict[int, float] = dict(local_scores)

        # 3. Optional Neural Embedding Ranking
        neural_ranks: Dict[int, int] = {}
        neural_sim_map: Dict[int, float] = {}
        emb_model = os.environ.get("LLM_EMBEDDING_MODEL", "").strip()
        if emb_model and any(r["neural_vec"] is not None for r in rows):
            q_neural_vec = compute_neural_embedding(clean_query, model=emb_model)
            if q_neural_vec:
                neural_scores: List[Tuple[int, float]] = []
                for r in rows:
                    if r["neural_vec"] and r["neural_model"] == emb_model:
                        n_vec = _unpack_vector(r["neural_vec"])
                        sim = cosine_similarity(q_neural_vec, n_vec)
                        if sim > 0.1:
                            neural_scores.append((r["id"], sim))
                neural_scores.sort(key=lambda x: x[1], reverse=True)
                neural_ranks = {rid: idx + 1 for idx, (rid, _) in enumerate(neural_scores)}
                neural_sim_map = dict(neural_scores)

        # 4. Reciprocal Rank Fusion (RRF) + Kind Priority Boost (findings > facts > notes)
        kind_boost = {"finding": 1.15, "fact": 1.0, "note": 0.9}
        scored_records: List[MemoryRecord] = []
        for r in rows:
            rid = r["id"]
            rrf = 0.0
            if rid in fts_ranks:
                rrf += 1.5 / (RRF_K + fts_ranks[rid])
            if rid in local_ranks:
                rrf += 1.0 / (RRF_K + local_ranks[rid]) + (0.05 * local_sim_map.get(rid, 0.0))
            if rid in neural_ranks:
                rrf += 1.5 / (RRF_K + neural_ranks[rid]) + (0.05 * neural_sim_map.get(rid, 0.0))

            if rrf <= 0.0:
                continue

            rrf *= kind_boost.get(r["kind"], 1.0)
            scored_records.append(
                MemoryRecord(
                    entry_id=rid,
                    run_id=r["run_id"],
                    target=r["target"],
                    root_domain=r["root_domain"],
                    kind=r["kind"],
                    text=r["text"],
                    tags=r["tags"],
                    evidence_id=r["evidence_id"],
                    created_at=r["created_at"],
                    score=rrf,
                )
            )

        scored_records.sort(key=lambda rec: (rec.score, rec.entry_id), reverse=True)
        return scored_records[:max_limit]

    def build_target_seed_context(
        self,
        target: str,
        *,
        max_findings: int = 8,
        max_facts: int = 10,
        exclude_run_id: Optional[str] = None,
    ) -> str:
        """Builds a Turn-0 static seed context block from prior runs matching the
        same target or registrable root domain (e.g. sibling subdomains). Returns
        an empty string if no prior entries exist for this root domain."""
        root_dom = extract_root_domain(target)
        if not root_dom:
            return ""

        with self._connect() as conn:
            params: List[Any] = [root_dom.lower(), target.strip().lower()]
            excl_clause = ""
            if exclude_run_id:
                excl_clause = "AND run_id != ?"
                params.append(exclude_run_id)

            rows = conn.execute(
                f"""
                SELECT id, run_id, target, root_domain, kind, text, tags, evidence_id, created_at
                FROM memory_entries
                WHERE (LOWER(root_domain) = ? OR LOWER(target) = ?)
                {excl_clause}
                ORDER BY id DESC
                """,
                params,
            ).fetchall()

        if not rows:
            return ""

        findings = [r for r in rows if r["kind"] == "finding"][:max_findings]
        facts = [r for r in rows if r["kind"] == "fact"][:max_facts]
        if not findings and not facts:
            return ""

        lines: List[str] = [
            f"--- Cross-engagement memory for root domain '{root_dom}' ---"
        ]
        if findings:
            lines.append("Prior verified findings across this domain/organization:")
            for f in findings:
                ev_str = f" [evidence: {f['evidence_id']}]" if f["evidence_id"] else ""
                lines.append(f"- [{f['target']} | run {f['run_id']}] {f['text']}{ev_str}")
        if facts:
            if findings:
                lines.append("")
            lines.append("Prior known service facts across this domain/organization:")
            for fc in facts:
                lines.append(f"- [run {fc['run_id']}] {fc['text']}")
        lines.append("---")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        """Returns summary counts of indexed entries, targets, root domains, and runs."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]
            runs = conn.execute("SELECT COUNT(DISTINCT run_id) FROM memory_entries").fetchone()[0]
            targets = conn.execute("SELECT COUNT(DISTINCT target) FROM memory_entries").fetchone()[0]
            domains = conn.execute("SELECT COUNT(DISTINCT root_domain) FROM memory_entries").fetchone()[0]
            by_kind_rows = conn.execute(
                "SELECT kind, COUNT(*) AS cnt FROM memory_entries GROUP BY kind"
            ).fetchall()
            by_kind = {r["kind"]: r["cnt"] for r in by_kind_rows}
            neural_count = conn.execute(
                "SELECT COUNT(*) FROM memory_entries WHERE neural_vec IS NOT NULL"
            ).fetchone()[0]

        return {
            "db_path": str(self.db_path),
            "total_entries": total,
            "indexed_runs": runs,
            "distinct_targets": targets,
            "distinct_root_domains": domains,
            "by_kind": by_kind,
            "neural_embedded_entries": neural_count,
        }

    def clear(self, target: Optional[str] = None) -> int:
        """Deletes indexed entries (all or filtered by target/root_domain). Returns deleted count."""
        with self._connect() as conn:
            if target and target.strip():
                t_clean = target.strip().lower()
                root_dom = extract_root_domain(t_clean)
                cur = conn.execute(
                    "DELETE FROM memory_entries WHERE LOWER(target) = ? OR LOWER(root_domain) = ?",
                    (t_clean, root_dom),
                )
            else:
                cur = conn.execute("DELETE FROM memory_entries")
            return cur.rowcount

    @staticmethod
    def _build_fts_query(query: str) -> str:
        tokens = _TOKEN_RE.findall(query.lower())
        if not tokens:
            return ""
        quoted = [f'"{tok.replace(chr(34), "")}"' for tok in tokens[:16]]
        return " OR ".join(quoted)

    @staticmethod
    def _extract_tags_from_record(record: Dict[str, Any]) -> str:
        tag_keys = (
            "service", "product", "version", "http_title", "web_servers",
            "tech", "technologies", "waf", "cms", "framework", "server",
        )
        parts: List[str] = []
        for k in tag_keys:
            val = record.get(k)
            if isinstance(val, str) and val.strip():
                parts.append(val.strip())
            elif isinstance(val, list):
                parts.extend(str(x).strip() for x in val if str(x).strip())
        return ", ".join(dict.fromkeys(parts))

    @classmethod
    def _extract_tags_from_facts(cls, facts: FactStore) -> str:
        parts: List[str] = []
        for _, record in facts.sorted_records():
            rec_tags = cls._extract_tags_from_record(record)
            if rec_tags:
                parts.extend(t.strip() for t in rec_tags.split(",") if t.strip())
        return ", ".join(dict.fromkeys(parts))

    @staticmethod
    def _parse_log_file(log_path: Path) -> EngagementMemory:
        mem = EngagementMemory()
        if not log_path.is_file():
            return mem
        try:
            lines = log_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return mem

        retracted_ids: Set[int] = set()
        raw_entries: List[LogEntry] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line == "(empty -- nothing logged yet)":
                continue
            m = _FINDING_LINE_RE.match(line)
            if m:
                fid = int(m.group("id")) if m.group("id") else None
                is_retracted = bool(m.group("retracted"))
                ev_id = (m.group("ev") or "").strip() or None
                ftext = (m.group("text") or "").strip()
                if is_retracted and fid is not None:
                    retracted_ids.add(fid)
                raw_entries.append(
                    LogEntry(
                        kind="finding",
                        text=ftext,
                        finding_id=fid,
                        retracted=is_retracted,
                        evidence_id=ev_id,
                    )
                )
                continue
            if line.startswith("note:"):
                note_body = line[len("note:"):].strip()
                rm = _RETRACTION_NOTE_RE.match(note_body)
                if rm:
                    retracted_ids.add(int(rm.group("id")))
                raw_entries.append(LogEntry(kind="note", text=note_body))

        for entry in raw_entries:
            if entry.kind == "finding" and entry.finding_id is not None and entry.finding_id in retracted_ids:
                entry.retracted = True
            mem.entries.append(entry)
        return mem
