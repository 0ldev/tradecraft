from tradecraft.adapters.subdomain_permute.execute import (
    KEYWORDS,
    SEPARATOR_PATTERNS,
    RawPermuteResult,
    _valid_hostname,
    generate_candidates,
    normalize_apex,
)
from tradecraft.adapters.subdomain_permute.parse import parse_permute_result


def test_keyword_and_pattern_tables():
    assert 85 <= len(KEYWORDS) <= 100
    assert SEPARATOR_PATTERNS == ["{kw}", "{kw}-", "{kw}.", "{kw}1", "{kw}2", "{kw}3"]


def test_normalize_apex_strips_scheme_path_port_and_case():
    assert normalize_apex("Example.COM") == "example.com"
    assert normalize_apex("https://shop.example.com/login?x=1") == "shop.example.com"
    assert normalize_apex("example.com:8443/path") == "example.com"
    assert normalize_apex("example.com.") == "example.com"
    assert normalize_apex("   ") == ""


def test_exact_candidates_for_a_known_keyword():
    raw = generate_candidates("example.com")
    assert raw.error == ""
    assert raw.target == "example.com"
    for expected in ["dev.example.com", "dev1.example.com", "dev2.example.com", "dev3.example.com"]:
        assert expected in raw.candidates
    # Separator rows that would produce invalid hostnames are dropped.
    assert "dev-.example.com" not in raw.candidates
    assert "dev..example.com" not in raw.candidates
    assert "api2.example.com" in raw.candidates


def test_candidates_are_sorted_unique_and_valid_hostnames():
    raw = generate_candidates("example.com")
    assert raw.candidates == sorted(set(raw.candidates))
    assert all(_valid_hostname(c) for c in raw.candidates)
    assert all(c.endswith(".example.com") for c in raw.candidates)


def test_candidate_count_matches_keywords_times_valid_patterns_after_dedupe():
    raw = generate_candidates("example.com")
    # 4 valid patterns per keyword ({kw}, {kw}1, {kw}2, {kw}3); a few collide
    # with existing keywords (e.g. api + '2' == api2), so dedupe reduces the count.
    assert len(raw.candidates) < len(KEYWORDS) * 4
    assert len(raw.candidates) > len(KEYWORDS) * 3


def test_seed_labels_from_matching_apex_are_added():
    raw = generate_candidates("example.com", seed_subdomains="billing-old.example.com, ops.example.com")
    assert "billing-old1.example.com" in raw.candidates
    assert "ops.example.com" in raw.candidates
    assert "ops1.example.com" in raw.candidates


def test_seed_from_unrelated_domain_is_ignored():
    raw = generate_candidates("example.com", seed_subdomains="secret.other.org, api.example.com")
    assert not any(c.startswith("secret") for c in raw.candidates)


def test_seed_label_already_in_keywords_is_not_duplicated():
    base = generate_candidates("example.com")
    seeded = generate_candidates("example.com", seed_subdomains="api.example.com")
    assert base.candidates == seeded.candidates


def test_empty_target_is_error():
    raw = generate_candidates("   ")
    assert raw.error.startswith("target is required")
    assert parse_permute_result(raw) == {
        "target": "   ",
        "error": raw.error,
    }


def test_parse_shape_and_dedupe():
    raw = RawPermuteResult(target="example.com", candidates=["b.example.com", "a.example.com", "b.example.com"])
    assert parse_permute_result(raw) == {
        "target": "example.com",
        "candidate_count": 2,
        "candidates": ["a.example.com", "b.example.com"],
    }
