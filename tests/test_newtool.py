"""Tests for Phase 5: new-tool scaffold generator."""
import pytest
import yaml

from tradecraft.newtool import registration_snippet, scaffold, validate_tool_id


def test_validate_tool_id():
    assert validate_tool_id("tls_expiry_probe") == "tls_expiry_probe"
    with pytest.raises(ValueError):
        validate_tool_id("Bad-Name")
    with pytest.raises(ValueError):
        validate_tool_id("1startsWithDigit")


def test_scaffold_creates_all_files(tmp_path):
    created = scaffold("demo_probe", root=tmp_path)
    names = {p.name for p in created}
    assert "demo_probe.yaml" in names
    assert "demo_probe.py" in names
    assert "test_demo_probe.py" in names
    assert (tmp_path / "tradecraft" / "adapters" / "demo_probe" / "execute.py").is_file()
    assert (tmp_path / "tradecraft" / "adapters" / "demo_probe" / "parse.py").is_file()


def test_scaffold_yaml_is_valid_and_contract_shape(tmp_path):
    scaffold("demo_probe", root=tmp_path)
    contract = yaml.safe_load((tmp_path / "config" / "tools" / "demo_probe.yaml").read_text())
    assert contract["name"] == "demo_probe"
    assert contract["scope_param"] == "target"
    assert contract["destructive"] is False
    assert contract["parameters"]["required"] == ["target"]


def test_scaffold_test_passes_import(tmp_path):
    """The generated starter test must actually pass -- a scaffold that
    fails its own test is a broken gift."""
    scaffold("demo_probe", root=tmp_path)
    import subprocess, sys, os
    env = dict(os.environ, PYTHONPATH=str(tmp_path))
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(tmp_path / "tests" / "test_demo_probe.py"), "-q"],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_scaffold_never_overwrites(tmp_path):
    scaffold("demo_probe", root=tmp_path)
    with pytest.raises(FileExistsError):
        scaffold("demo_probe", root=tmp_path)


def test_registration_snippet_names():
    snippet = registration_snippet("tls_expiry_probe")
    assert "TlsExpiryProbe" in snippet
    assert "ALL_TOOLS" in snippet
