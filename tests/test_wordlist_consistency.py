"""
config/wordlists/ is referenced two ways: a model-facing enum on a tool's
"wordlist"/"user_wordlist" parameter (config/tools/*.yaml), and a literal
name/constant inside an adapter's own source (tradecraft/adapters/*/execute.py,
parse.py). Both directions can drift from the real files on disk:

- An enum value that doesn't resolve to a real bundled file -- the model
  would ask for something that silently falls back to a different file
  (resolve_wordlist()'s own behavior), with no error.
- A bundled file nothing references at all, orphaned (this happened for
  real: config/wordlists/api-routes.json had zero consumers before it was
  deleted).

This file catches both directions.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from tradecraft.adapters.wordlists import WORDLISTS_DIR

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "config" / "tools"
ADAPTERS_DIR = ROOT / "tradecraft" / "adapters"


def _wordlist_enum_params():
    """Yields (yaml_filename, param_name, enum_value) for every parameter
    named 'wordlist' or 'user_wordlist' that declares an enum."""
    for path in sorted(TOOLS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        properties = (data.get("parameters") or {}).get("properties", {})
        for param_name, schema in properties.items():
            if param_name not in ("wordlist", "user_wordlist"):
                continue
            for value in schema.get("enum", []):
                yield path.name, param_name, value


def test_every_wordlist_enum_value_resolves_to_a_real_bundled_file():
    for yaml_name, param_name, value in _wordlist_enum_params():
        basenames = {value, f"{value}.txt", f"{value}.json", f"{value}.kite"}
        matches = [b for b in basenames if (WORDLISTS_DIR / b).is_file()]
        assert matches, (
            f"{yaml_name}: enum value {value!r} on parameter {param_name!r} "
            f"does not match any file in {WORDLISTS_DIR}"
        )


def _adapter_and_contract_text() -> str:
    """Adapter source (a literal default/fallback name, e.g. hydra's
    DEFAULT_USERNAMES_WORDLIST) and tool contract YAML (a wordlist
    parameter's enum:) are the two places a bundled file can legitimately
    be reachable from."""
    chunks = []
    for path in ADAPTERS_DIR.glob("*/*.py"):
        chunks.append(path.read_text())
    for path in TOOLS_DIR.glob("*.yaml"):
        chunks.append(path.read_text())
    return "\n".join(chunks)


def test_every_bundled_wordlist_file_is_referenced_by_some_adapter():
    source = _adapter_and_contract_text()
    unreferenced = []
    for path in sorted(WORDLISTS_DIR.glob("*")):
        if not path.is_file() or path.suffix == ".md":
            continue
        stem = path.stem
        if path.name not in source and stem not in source:
            unreferenced.append(path.name)
    assert not unreferenced, (
        f"config/wordlists/ file(s) with no reference in any adapter source: "
        f"{unreferenced} -- either wire them into a tool's wordlist enum, or "
        "delete them"
    )
