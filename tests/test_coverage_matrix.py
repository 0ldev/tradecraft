"""Tests for the Phase 0 Coverage Matrix (tradecraft/coverage/matrix.py)."""
from tradecraft.coverage.matrix import (
    STATUS_CLEAN,
    STATUS_PARTIAL,
    STATUS_UNTESTED,
    STATUS_VULNERABLE,
    CoverageMatrix,
)


def _facts():
    """Three (host, port) records exercising every status path."""
    return [
        (
            ("10.0.0.5", 80),
            {
                "host": "10.0.0.5",
                "port": 80,
                "http_title": "Login",
                "arjun_params_discovered": "redirect,next",
                "open_redirect_tested": True,
                "xss_tested": True,
                "xss_vulnerable": True,
                "sqli_tested": True,
            },
        ),
        (
            ("10.0.0.5", 8080),
            {"host": "10.0.0.5", "port": 8080, "http_title": "Admin"},
        ),
        (
            ("app.local", 443),
            {
                "host": "app.local",
                "port": 443,
                "params_discovered": "url,dest",
                "ssrf_tested": True,
                # A brand-new class a future tool invents must show up.
                "prototype_pollution_tested": True,
                "prototype_pollution_vulnerable": True,
            },
        ),
    ]


def test_vulnerable_beats_tested_for_same_class():
    matrix = CoverageMatrix.from_records(_facts())
    assert matrix.status("10.0.0.5", 80, "xss") == STATUS_VULNERABLE
    # sqli was tested, nothing reported vulnerable -> clean.
    assert matrix.status("10.0.0.5", 80, "sqli") == STATUS_CLEAN


def test_untested_cell_defaults_to_untested():
    matrix = CoverageMatrix.from_records(_facts())
    assert matrix.status("10.0.0.5", 8080, "sqli") == STATUS_UNTESTED


def test_unknown_class_discovered_automatically():
    matrix = CoverageMatrix.from_records(_facts())
    assert "prototype_pollution" in matrix.classes
    assert matrix.status("app.local", 443, "prototype_pollution") == STATUS_VULNERABLE


def test_effective_status_partial_for_discovered_but_untested():
    matrix = CoverageMatrix.from_records(_facts())
    # 10.0.0.5:80 has arjun params, tested open_redirect but never touched
    # sqli... but sqli_tested IS present on that record. Use 8080? No
    # params there. app.local has params and ssrf_tested -- open_redirect
    # was never probed there:
    assert matrix.effective_status("app.local", 443, "open_redirect") == STATUS_PARTIAL
    # ssrf itself was tested:
    assert matrix.effective_status("app.local", 443, "ssrf") == STATUS_CLEAN


def test_effective_status_untested_without_discovery():
    matrix = CoverageMatrix.from_records(_facts())
    # 10.0.0.5:8080 has no params discovered -> plain untested, not partial.
    assert matrix.effective_status("10.0.0.5", 8080, "sqli") == STATUS_UNTESTED


def test_render_compact_drops_all_untested_columns():
    matrix = CoverageMatrix.from_records(_facts())
    text = matrix.render_compact()
    # Every row appears.
    assert "10.0.0.5:80" in text
    assert "10.0.0.5:8080" in text
    assert "app.local:443" in text
    # xss (tested on :80) is an active column:
    assert "xss" in text
    assert "VULN" in text
    # cmdi is untested everywhere -> column pruned.
    assert "cmdi" not in text


def test_render_compact_empty_facts():
    assert "no coverage data" in CoverageMatrix.from_records([]).render_compact()


def test_to_dict_shape_for_studio():
    data = CoverageMatrix.from_records(_facts()).to_dict()
    assert data["rows"][0]["target"] == "10.0.0.5:80"
    assert data["rows"][0]["cells"]["xss"] == STATUS_VULNERABLE
    assert data["summary"][STATUS_VULNERABLE] >= 2


def test_open_threads_surfaces_partial_cells():
    matrix = CoverageMatrix.from_records(_facts())
    threads = matrix.open_threads()
    assert any(c.target == "app.local:443" and c.vuln_class == "open_redirect" for c in threads)


def test_empty_matrix():
    matrix = CoverageMatrix.from_records([])
    assert matrix.rows == []
    assert matrix.classes == []
    assert matrix.summary() == {
        STATUS_VULNERABLE: 0,
        STATUS_CLEAN: 0,
        STATUS_PARTIAL: 0,
        STATUS_UNTESTED: 0,
    }
