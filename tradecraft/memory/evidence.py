"""
Evidence store: stores detailed, full tool outputs outside the LLM context window
to disk, allowing on-demand retrieval by target and tool without bloating
conversation history.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceStore:
    """In-process and on-disk evidence store for one engagement run.
    Keyed by (target, tool_id); same key called again overwrites (last
    write wins) -- the right semantics for a tool whose target genuinely
    is the one resource being re-tested. A tool whose evidence is finer
    than its usual target (e.g. http_request fetching several distinct
    URLs on one host) should pass a target that includes enough of the
    URL to disambiguate (host+path, not just host) rather than relying on
    this store to detect the collision itself; read() resolves a plain
    bare-host lookup back to a single such path-qualified entry
    automatically, and lists the options when there's more than one. All
    operations are scoped to a per-run directory with restricted
    0o700 / 0o600 permissions."""

    def __init__(self, persist_dir: str | Path | None = None) -> None:
        if persist_dir:
            self.base_dir = Path(persist_dir)
            self._temp_dir = None
        else:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="tradecraft_evidence_")
            self.base_dir = Path(self._temp_dir.name)

        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            pass

    def cleanup(self) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()

    @staticmethod
    def _sanitize_component(name: str) -> str:
        """Sanitizes a component (target or tool_id) to prevent directory traversal
        and invalid characters."""
        if not name or ".." in name or "\0" in name:
            raise ValueError(f"invalid component name or potential traversal: '{name}'")
        s = re.sub(r"^[a-zA-Z]+://", "", name)
        s = s.rstrip("/")
        # Keep alphanumeric, dot, dash, underscore; replace slashes, colons, etc. with underscore
        sanitized = re.sub(r"[^a-zA-Z0-9.\-_]", "_", s)
        sanitized = re.sub(r"_+", "_", sanitized).strip("._")
        if not sanitized or sanitized in (".", ".."):
            raise ValueError(f"invalid sanitized component name: '{name}'")
        return sanitized

    def save(self, target: str, tool_id: str, data: Any, aliases: Optional[List[str]] = None) -> str:
        """Persists tool output for (target, tool_id). Last write wins (overwrites previous).
        Returns the evidence key (e.g. 'tool_id:target').

        `aliases`: other targets this same call's evidence also covers --
        a multi-host/multi-URL batch tool (dnsx, httpx_probe, http_request,
        subzy, shodan_internetdb) saves its full batch result once under
        one canonical target (usually the batch's first member) but the
        FactStore attaches that single evidence_id to *every* target's own
        fact. Without this, read_evidence(target=<any non-canonical batch
        member>, ...) always reports "no evidence found" even though real
        data exists -- it's just filed under a different target's
        directory. Each alias gets a small redirect stub
        (`_tradecraft_alias_of`) so read() can resolve it transparently; see
        read()'s handling of that key."""
        safe_target = self._sanitize_component(target)
        safe_tool = self._sanitize_component(tool_id)

        target_dir = self.base_dir / safe_target
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(target_dir, 0o700)
        except OSError:
            pass

        file_path = target_dir / f"{safe_tool}.json"
        content = json.dumps(data, indent=2, default=str)

        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)

        evidence_key = f"{safe_tool}:{target}"
        if aliases:
            self._write_alias_stubs(target, safe_target, safe_tool, evidence_key, aliases)
        return evidence_key

    def _write_alias_stubs(
        self, canonical_target: str, safe_canonical: str, safe_tool: str,
        canonical_key: str, aliases: List[str],
    ) -> None:
        """Writes a redirect stub under each alias target's own directory,
        pointing back at the canonical target actually holding the data.
        Never overwrites a real (non-stub) evidence file that already
        exists there -- a target probed solo earlier (or independently
        canonical for a different batch) keeps its own real data."""
        for alias in aliases:
            if not alias or alias == canonical_target:
                continue
            try:
                safe_alias = self._sanitize_component(alias)
            except ValueError:
                continue
            if safe_alias == safe_canonical:
                continue

            alias_dir = self.base_dir / safe_alias
            alias_file = alias_dir / f"{safe_tool}.json"
            if alias_file.is_file():
                try:
                    with open(alias_file, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    continue
                if not (isinstance(existing, dict) and "_tradecraft_alias_of" in existing):
                    continue  # real data already filed here -- leave it alone

            alias_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(alias_dir, 0o700)
            except OSError:
                pass

            stub = {"_tradecraft_alias_of": canonical_target, "_tradecraft_alias_key": canonical_key}
            fd = os.open(alias_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(stub))

    def save_binary(self, target: str, tool_id: str, data: bytes, ext: str = "png") -> str:
        """Identical sanitization/permission handling to save() (reuses the
        same self._sanitize_component calls), writes raw bytes to
        <target_dir>/<tool_id>.<ext> instead of a .json file, returns the
        same 'tool_id:target' key format save() does."""
        safe_target = self._sanitize_component(target)
        safe_tool = self._sanitize_component(tool_id)
        clean_ext = re.sub(r"[^a-zA-Z0-9]", "", ext) or "png"

        target_dir = self.base_dir / safe_target
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(target_dir, 0o700)
        except OSError:
            pass

        file_path = target_dir / f"{safe_tool}.{clean_ext}"
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

        return f"{safe_tool}:{target}"

    def _sanitized_url_target(self, url: str) -> str:
        """Best-effort host(+path) guess for a URL, sanitized the same way
        save()/read() sanitize any target -- so it can be compared directly
        against `clean_target` (itself always sanitized). Needed because a
        batch result's raw `url` field keeps real slashes (e.g.
        'host.com/some/path') while the target name on disk has them
        replaced with underscores; a plain substring check between the two
        never matches for a path-qualified target. Local to this module
        rather than importing tradecraft/adapters/http_request/parse.py's
        equivalent helper, which would invert the domain->adapters->tools
        layering this module sits below."""
        if not url:
            return ""
        try:
            raw = url if "://" in url else f"//{url}"
            parsed = urllib.parse.urlsplit(raw)
            host = (parsed.hostname or "").lower()
            path = parsed.path or ""
            guess = f"{host}{path}" if path and path != "/" else host
            return self._sanitize_component(guess).lower()
        except Exception:
            return ""

    def _candidate_target_dirs(self, target: str) -> List[Path]:
        """Resolves candidate target directories to inspect on disk.
        Order of precedence:
        1. Exact sanitized target directory (self.base_dir / safe_target)
        2. Hostname directory if target is a URL or has port/path
        3. Parent domains (e.g. mail.example.com.br -> example.com.br)
        """
        candidates: List[Path] = []
        try:
            safe_target = self._sanitize_component(target)
            direct_dir = self.base_dir / safe_target
            candidates.append(direct_dir)
        except ValueError:
            return []

        # If target has a port or path or scheme, extract the bare hostname
        extracted_host: Optional[str] = None
        if "://" in target or "/" in target or ":" in target:
            try:
                raw_url = target if "://" in target else f"//{target}"
                parsed = urllib.parse.urlsplit(raw_url)
                if parsed.hostname:
                    extracted_host = parsed.hostname.lower()
                    h_dir = self.base_dir / self._sanitize_component(extracted_host)
                    if h_dir not in candidates:
                        candidates.append(h_dir)
            except Exception:
                pass

        base_host = extracted_host or (safe_target if "." in safe_target else None)
        if base_host and "." in base_host:
            parts = base_host.split(".")
            # Walk up parent domains while parts length >= 2
            while len(parts) > 2:
                parts = parts[1:]
                parent = ".".join(parts)
                try:
                    p_dir = self.base_dir / self._sanitize_component(parent)
                    if p_dir not in candidates:
                        candidates.append(p_dir)
                except ValueError:
                    pass

        return candidates

    def read(self, target: str, tool_id: str) -> Dict[str, Any]:
        """Reads stored evidence for a target and tool, with automatic fallback
        normalization across subdomains, URLs, and parent domains."""
        try:
            safe_tool = self._sanitize_component(tool_id)
        except ValueError as exc:
            return {"error": str(exc)}

        candidates = self._candidate_target_dirs(target)
        if not candidates:
            return {"error": f"invalid target name: '{target}'"}

        exact_dir = candidates[0]
        file_path = exact_dir / f"{safe_tool}.json"

        found_path: Optional[Path] = None
        found_target_dir: Optional[Path] = None
        is_fallback = False

        if file_path.is_file():
            found_path = file_path
            found_target_dir = exact_dir
        else:
            if exact_dir.is_dir():
                matches = [f for f in exact_dir.glob(f"{safe_tool}.*") if f.is_file() and not f.name.startswith(".")]
                if matches:
                    bin_file = matches[0]
                    return {
                        "target": target,
                        "tool": tool_id,
                        "file_path": str(bin_file),
                        "size_bytes": bin_file.stat().st_size,
                        "is_binary": True,
                        "note": f"Binary evidence file '{bin_file.name}' stored on disk; contents cannot be rendered as JSON or text.",
                    }

            for cand_dir in candidates[1:]:
                cand_json = cand_dir / f"{safe_tool}.json"
                if cand_json.is_file():
                    found_path = cand_json
                    found_target_dir = cand_dir
                    is_fallback = True
                    break
                elif cand_dir.is_dir():
                    matches = [f for f in cand_dir.glob(f"{safe_tool}.*") if f.is_file() and not f.name.startswith(".")]
                    if matches:
                        bin_file = matches[0]
                        return {
                            "target": target,
                            "tool": tool_id,
                            "parent_target": cand_dir.name,
                            "file_path": str(bin_file),
                            "size_bytes": bin_file.stat().st_size,
                            "is_binary": True,
                            "note": f"Binary evidence file '{bin_file.name}' stored under parent '{cand_dir.name}'; contents cannot be rendered as JSON or text.",
                        }

        if not found_path or not found_path.is_file():
            # Reverse lookup check: if target is apex, did any subdomains save evidence for this tool?
            safe_target = candidates[0].name
            sub_matches = [
                d.name for d in self.base_dir.iterdir()
                if d.is_dir() and d.name.endswith(f".{safe_target}") and (d / f"{safe_tool}.json").is_file()
            ]
            if sub_matches:
                return {
                    "error": f"no direct evidence found for '{target}' and tool '{tool_id}'",
                    "target": target,
                    "tool": tool_id,
                    "note": f"Evidence exists for tool '{tool_id}' under subdomains: {sorted(sub_matches)}. Call read_evidence with the specific subdomain.",
                    "available_subdomains": sorted(sub_matches),
                }

            # Path-qualified sibling check: a tool whose evidence target is
            # host+path (e.g. http_request fetching more than one distinct
            # URL on the same host) stores each under its own
            # "<host>_<path>" directory rather than bare "<host>", so a
            # bare-host lookup finds nothing directly above. Resolve it
            # transparently when there's exactly one such sibling; list the
            # options when there's more than one, same shape as the
            # subdomain case above.
            path_matches = [
                d.name for d in self.base_dir.iterdir()
                if d.is_dir() and d.name != safe_target and d.name.startswith(f"{safe_target}_")
                and (d / f"{safe_tool}.json").is_file()
            ]
            if len(path_matches) == 1:
                resolved_dir = self.base_dir / path_matches[0]
                try:
                    with open(resolved_dir / f"{safe_tool}.json", "r", encoding="utf-8") as f:
                        resolved_data = json.load(f)
                    return {
                        "target": target,
                        "tool": tool_id,
                        "resolved_target": path_matches[0],
                        "note": f"No evidence stored exactly for '{target}'; resolved to the single more-specific match '{path_matches[0]}'.",
                        "evidence": resolved_data,
                    }
                except Exception:
                    pass
            elif path_matches:
                return {
                    "error": f"no direct evidence found for '{target}' and tool '{tool_id}'",
                    "target": target,
                    "tool": tool_id,
                    "note": f"Evidence exists for tool '{tool_id}' under more specific paths on this host: {sorted(path_matches)}. Call read_evidence with the specific path-qualified target.",
                    "available_paths": sorted(path_matches),
                }

            return {
                "error": f"no evidence found for target '{target}' and tool '{tool_id}'",
                "target": target,
                "tool": tool_id,
            }

        try:
            with open(found_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "_tradecraft_alias_of" in data:
                real_target = str(data["_tradecraft_alias_of"])
                try:
                    real_dir = self.base_dir / self._sanitize_component(real_target)
                except ValueError:
                    return {"error": f"alias evidence for '{target}' points to an invalid target"}
                real_file = real_dir / f"{safe_tool}.json"
                if not real_file.is_file():
                    return {
                        "error": (
                            f"alias evidence for '{target}' (tool '{tool_id}') points to "
                            f"'{real_target}', but no data is filed there"
                        ),
                    }
                with open(real_file, "r", encoding="utf-8") as f2:
                    data = json.load(f2)
                # Route through the same per-item filtering below used for
                # parent-domain fallback hits, scoped by this alias's own
                # (unresolved) requested target -- not the canonical one.
                is_fallback = True
                found_target_dir = real_dir

            if safe_tool == "gau" and isinstance(data, dict) and len(data.get("urls", [])) > 50:
                urls = data.get("urls", [])
                endpoints = data.get("endpoints", [])
                parameters = data.get("parameters", [])
                subdomains = data.get("subdomains", [])
                return {
                    "target": target,
                    "tool": tool_id,
                    "total_urls": len(urls),
                    "total_endpoints": len(endpoints),
                    "total_subdomains": len(subdomains),
                    "total_parameters": len(parameters),
                    "endpoints_sample": endpoints[:50],
                    "parameters": parameters,
                    "subdomains": subdomains,
                    "warning": (
                        f"Bulk URL list contains {len(urls)} entries ({len(json.dumps(data))} bytes). "
                        "Raw dump truncated to protect conversational context. "
                        "Use search_evidence(query=...) to query specific extensions (.php, .json), "
                        "paths (admin, api), or parameters across this dataset."
                    ),
                }

            # If fallback parent directory was used, try to filter to records relevant to target
            if is_fallback and found_target_dir:
                parent_name = found_target_dir.name
                clean_target = candidates[0].name.lower()

                if isinstance(data, dict) and isinstance(data.get("results"), list):
                    matching_results = [
                        item for item in data["results"]
                        if isinstance(item, dict) and (
                            clean_target == str(item.get("host", "")).lower()
                            or clean_target == str(item.get("input", "")).lower()
                            or clean_target == str(item.get("vhost", "")).lower()
                            or clean_target in str(item.get("url", "")).lower()
                            or self._sanitized_url_target(str(item.get("url", ""))) == clean_target
                        )
                    ]
                    if matching_results:
                        return {
                            "target": target,
                            "tool": tool_id,
                            "parent_target": parent_name,
                            "note": f"Found {len(matching_results)} matching item(s) for '{target}' in parent evidence '{parent_name}/{tool_id}'",
                            "evidence": matching_results if len(matching_results) > 1 else matching_results[0],
                        }

                if isinstance(data, dict) and isinstance(data.get("records"), list):
                    matching_records = [
                        item for item in data["records"]
                        if isinstance(item, dict) and clean_target == str(item.get("host", "")).lower()
                    ]
                    if matching_records:
                        return {
                            "target": target,
                            "tool": tool_id,
                            "parent_target": parent_name,
                            "note": f"Found matching DNS record for '{target}' in parent evidence '{parent_name}/{tool_id}'",
                            "evidence": matching_records if len(matching_records) > 1 else matching_records[0],
                        }

                if isinstance(data, dict) and isinstance(data.get("subdomains"), list):
                    if any(clean_target == str(s).lower() for s in data["subdomains"]):
                        return {
                            "target": target,
                            "tool": tool_id,
                            "parent_target": parent_name,
                            "found_in_subdomains": True,
                            "note": f"Target '{target}' is present in subdomain enumeration from '{parent_name}/subfinder'",
                        }

                # Default fallback: return parent evidence with context note
                return {
                    "target": target,
                    "tool": tool_id,
                    "parent_target": parent_name,
                    "note": f"Direct evidence for '{target}' was not stored separately; returning parent domain evidence from '{parent_name}/{tool_id}'",
                    "evidence": data,
                }

            return {"target": target, "tool": tool_id, "evidence": data}
        except Exception as exc:
            return {"error": f"failed to read evidence: {exc}"}

    @staticmethod
    def _context_window(line: str, start: int, end: int, max_len: int) -> str:
        """Returns up to max_len characters of `line` centered on the
        [start, end) match span, with a leading/trailing "..." marker
        wherever content was cut. A plain head-clip (the old behavior)
        always shows the first max_len characters regardless of where the
        match actually occurred -- for a line that is itself one huge
        unbroken JSON value (a tool's evidence stored via json.dumps
        escapes any real newlines inside a string field to "\\n", so the
        whole field lands on a single on-disk line), that means every
        match past the first max_len characters is reported as the same
        useless head fragment no matter the query. Centering on the match
        fixes that for any line length."""
        if len(line) <= max_len:
            return line
        match_len = max(end - start, 0)
        pad = max(max_len - match_len, 0) // 2
        window_start = max(start - pad, 0)
        window_end = min(window_start + max_len, len(line))
        window_start = max(window_end - max_len, 0)
        prefix = "..." if window_start > 0 else ""
        suffix = "..." if window_end < len(line) else ""
        return prefix + line[window_start:window_end] + suffix

    def search(
        self,
        query: str,
        target: Optional[str] = None,
        is_regex: bool = False,
        max_matches: int = 50,
        max_line_len: int = 200,
    ) -> Dict[str, Any]:
        """Searches across stored evidence for a query string or regex."""
        if not query:
            return {"error": "query cannot be empty"}

        if target:
            try:
                candidate_dirs = self._candidate_target_dirs(target)
                target_dirs = [d for d in candidate_dirs if d.is_dir()]

                # Also search child subdomains, and sibling path-qualified
                # directories (e.g. "host_some_path" for a tool keyed by
                # host+path -- see read()'s path_matches fallback), if
                # target is apex/domain/bare-host.
                safe_target = self._sanitize_component(target)
                for d in self.base_dir.iterdir():
                    if d.is_dir() and (
                        d.name == safe_target
                        or d.name.endswith(f".{safe_target}")
                        or d.name.startswith(f"{safe_target}_")
                    ):
                        if d not in target_dirs:
                            target_dirs.append(d)
            except ValueError as exc:
                return {"error": str(exc)}
        else:
            target_dirs = [d for d in self.base_dir.iterdir() if d.is_dir()]

        matches: List[Dict[str, Any]] = []
        pattern = None
        if is_regex:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except re.error as exc:
                return {"error": f"invalid regex pattern: {exc}"}

        total_found = 0
        for t_dir in sorted(target_dirs):
            if not t_dir.is_dir():
                continue
            tgt_name = t_dir.name
            for json_file in sorted(t_dir.glob("*.json")):
                tool_name = json_file.stem
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_no, line in enumerate(lines, 1):
                    line_str = line.strip()
                    match_start = 0
                    match_end = 0
                    if pattern:
                        m = pattern.search(line_str)
                        matched = bool(m)
                        if m:
                            match_start, match_end = m.start(), m.end()
                    else:
                        idx = line_str.lower().find(query.lower())
                        matched = idx != -1
                        if matched:
                            match_start, match_end = idx, idx + len(query)

                    if matched:
                        total_found += 1
                        if len(matches) < max_matches:
                            clipped = self._context_window(line_str, match_start, match_end, max_line_len)
                            matches.append({
                                "target": tgt_name,
                                "tool": tool_name,
                                "line": line_no,
                                "match": clipped,
                            })

        res: Dict[str, Any] = {
            "query": query,
            "total_matches": total_found,
            "matches": matches,
        }
        if total_found > max_matches:
            res["omitted_matches"] = total_found - max_matches
            res["note"] = (
                f"{total_found - max_matches} more match(es) omitted. "
                "Narrow your query with a target or a more specific string."
            )
        return res

    def has_evidence(self, evidence_id: str) -> bool:
        """True if `evidence_id` (formatted as 'tool_id:target') resolves to
        stored evidence in this store."""
        if not evidence_id or ":" not in evidence_id:
            return False
        tool_id, _, target = evidence_id.partition(":")
        tool_id = tool_id.strip()
        target = target.strip()
        if not tool_id or not target:
            return False
        res = self.read(target=target, tool_id=tool_id)
        return "error" not in res

    def keys(self) -> List[str]:
        """Sorted 'tool_id:target' strings for everything currently
        persisted under self.base_dir -- one entry per
        <base_dir>/<target>/<tool_id>.* file found. Pure filesystem
        listing, no parsing of file contents."""
        out: List[str] = []
        if self.base_dir.is_dir():
            for target_dir in self.base_dir.iterdir():
                if target_dir.is_dir():
                    for f in target_dir.iterdir():
                        if f.is_file() and not f.name.startswith("."):
                            out.append(f"{f.stem}:{target_dir.name}")
        return sorted(list(set(out)))
