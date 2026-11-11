"""
Two structural adapter-authoring rules enforced mechanically instead of
by reviewer memory -- see "Adding a tool" in CONTRIBUTING.md.

1. Import shadowing: every `tradecraft/adapters/<tool>/__init__.py` re-exports
   its submodule functions (`from .execute import execute`, sometimes
   `from .parse import parse`), which rebinds that name in the package's
   own namespace from the submodule to the function. Any later
   `from tradecraft.adapters.<tool> import execute as X` or
   `import tradecraft.adapters.<tool>.execute as X` for a tool whose
   __init__.py shadows that exact name hands back the function, not the
   module -- verified empirically (fresh-interpreter import tests) while
   building this check. Hit once already, building `openvpn_probe` on
   2026-11-10. The fix is to import the function straight from the
   submodule (`from tradecraft.adapters.<tool>.execute import execute as X`),
   which is unambiguous regardless of what __init__.py does -- that's
   what every other adapter and every test file already does, which is
   why this check is scoped per-tool to the names that specific tool's
   __init__.py actually shadows, not a blanket ban: plenty of tests
   correctly import a *non*-shadowed submodule this way on purpose (e.g.
   to patch `fb_execute.requests.get`), and that pattern is fine.

2. Cloud-metadata direct-query hazard: 169.254.169.254 et al. are
   link-local/environment-specific -- they only ever resolve to
   "whichever machine is asking." A tool that issues a direct HTTP
   request to one of these from wherever Tradecraft itself runs leaks the
   *operator's* credentials, not the target's (nearly shipped in PR #194
   building `cloud_metadata_credential_probe`, caught in review). The
   only legitimate way to reach a target's metadata service is to relay
   through something inside the target's own environment (SSRF sink,
   kubectl exec, etc.) -- never issue the request from the scanner
   itself.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
ADAPTERS_DIR = REPO_ROOT / "tradecraft" / "adapters"
SCAN_ROOTS = [REPO_ROOT / "tradecraft", REPO_ROOT / "tests"]

SHADOWABLE_SUBMODULES = ("execute", "parse")


def _shadowed_names(init_path: Path) -> Set[str]:
    """Names this adapter's __init__.py rebinds from submodule to function."""
    if not init_path.is_file():
        return set()
    tree = ast.parse(init_path.read_text())
    shadowed: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            last_segment = node.module.rsplit(".", 1)[-1]
            if last_segment in SHADOWABLE_SUBMODULES:
                for alias in node.names:
                    if (alias.asname or alias.name) == last_segment:
                        shadowed.add(last_segment)
    return shadowed


def _shadow_map() -> Dict[str, Set[str]]:
    return {
        d.name: _shadowed_names(d / "__init__.py")
        for d in ADAPTERS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith("__")
    }


def _iter_py_files():
    for root in SCAN_ROOTS:
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            # Each adapter's own __init__.py is where the shadowing re-export
            # is declared on purpose -- not a violation of itself.
            if path.name == "__init__.py" and path.parent.parent == ADAPTERS_DIR:
                continue
            yield path


def _find_shadow_violations(shadow_map: Dict[str, Set[str]]) -> List[Tuple[Path, int, str, str]]:
    violations = []
    for path in _iter_py_files():
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tradecraft.adapters."):
                parts = node.module.split(".")
                if len(parts) == 3:  # exactly "tradecraft.adapters.<tool>"
                    shadowed = shadow_map.get(parts[2], set())
                    for alias in node.names:
                        if alias.name in shadowed:
                            violations.append((path, node.lineno, node.module, alias.name))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname and alias.name.startswith("tradecraft.adapters."):
                        parts = alias.name.split(".")
                        if len(parts) == 4:  # "tradecraft.adapters.<tool>.<submodule>"
                            shadowed = shadow_map.get(parts[2], set())
                            if parts[3] in shadowed:
                                violations.append((path, node.lineno, alias.name, parts[3]))
    return violations


def test_no_adapter_import_shadowing():
    violations = _find_shadow_violations(_shadow_map())
    assert not violations, (
        "Found import(s) that silently receive a function where the "
        "submodule's __init__.py re-export shadows that name, per "
        "CONTRIBUTING.md's \"Adapter\" section:\n"
        + "\n".join(f"  {p.relative_to(REPO_ROOT)}:{ln}: `{mod}` shadows `{name}`" for p, ln, mod, name in violations)
        + "\nFix: import the function directly from its submodule, e.g. "
        "`from tradecraft.adapters.<tool>.execute import execute as <alias>` "
        "-- not `from tradecraft.adapters.<tool> import execute` and not "
        "`import tradecraft.adapters.<tool>.execute as <alias>`."
    )


METADATA_HOST_LITERALS = (
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "fd00:ec2::254",
)

DIRECT_HTTP_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.request",
    "urllib.request.urlopen",
}


def _call_func_name(call: ast.Call) -> Optional[str]:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    parts = [func.attr]
    cur = func.value
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return None
    return ".".join(reversed(parts))


def _contains_metadata_literal(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(host in node.value for host in METADATA_HOST_LITERALS):
                return True
    return False


def _find_metadata_hazards() -> List[Tuple[Path, int, str]]:
    violations = []
    for path in ADAPTERS_DIR.rglob("execute.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = _call_func_name(node)
            if fname not in DIRECT_HTTP_CALLS:
                continue
            args = list(node.args) + [kw.value for kw in node.keywords]
            if any(_contains_metadata_literal(arg) for arg in args):
                violations.append((path, node.lineno, fname))
    return violations


def test_no_direct_metadata_service_query():
    violations = _find_metadata_hazards()
    assert not violations, (
        "Found a direct HTTP call to a cloud-metadata/link-local address "
        "literal from inside an adapter's execute.py. These addresses "
        "resolve to whichever machine asks -- issuing the request from "
        "the Tradecraft host itself leaks the *operator's* credentials, not "
        "the target's. Relay through something inside the target's own "
        "environment instead (SSRF sink, exec on an already-reached "
        "host, etc.); see tradecraft/adapters/cloud_metadata_credential_probe/"
        "execute.py's module docstring:\n"
        + "\n".join(f"  {p.relative_to(REPO_ROOT)}:{ln}: `{fn}(...)`" for p, ln, fn in violations)
    )
