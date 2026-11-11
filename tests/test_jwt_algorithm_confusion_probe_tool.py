import base64
import json
from unittest.mock import MagicMock, patch

from tradecraft.tools.jwt_algorithm_confusion_probe import JwtAlgorithmConfusionProbe

PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...\n-----END PUBLIC KEY-----\n"


def _make_token(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    s = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    return f"{h}.{p}.{s}"


def test_run_invalid_jwt():
    tool = JwtAlgorithmConfusionProbe()
    out = tool.run("https://example.com/api/user", "not.a.jwt", PUBLIC_KEY_PEM)
    assert "error" in out


def test_run_vulnerable_on_first_variant_skips_second_request():
    tool = JwtAlgorithmConfusionProbe()
    token = _make_token({"alg": "RS256"}, {"user": "john", "role": "user"})

    mock_base = MagicMock(status_code=401)
    mock_forged = MagicMock(status_code=200)
    with patch("requests.get", side_effect=[mock_base, mock_forged]) as mock_get:
        out = tool.run("https://example.com/api/user", token, PUBLIC_KEY_PEM)

    assert out["vulnerable"] is True
    assert out["technique"] == "rs256_hs256_key_confusion"
    assert out["key_variant"] == "exact_pem"
    assert mock_get.call_count == 2  # only the first variant's baseline+forged pair
    assert "_full_evidence" in out


def test_run_not_vulnerable_tries_both_variants():
    tool = JwtAlgorithmConfusionProbe()
    token = _make_token({"alg": "RS256"}, {"user": "john", "role": "user"})

    responses = [MagicMock(status_code=200)] * 4  # baseline+forged, twice, never 401/403->200
    with patch("requests.get", side_effect=responses) as mock_get:
        out = tool.run("https://example.com/api/user", token, PUBLIC_KEY_PEM)

    assert out["vulnerable"] is False
    assert mock_get.call_count == 4
    assert out["key_variant"] == "normalized_pem"


def test_extract_evidence_pops_full_evidence():
    tool = JwtAlgorithmConfusionProbe()
    fake_full = {"vulnerable": True}
    result_dict = {"_full_evidence": fake_full, "vulnerable": True}
    ev = tool.extract_evidence({"target": "https://example.com:8443/api"}, result_dict)
    assert ev is not None
    assert ev[0] == "example.com:8443"
    assert ev[1] == fake_full


def test_extract_facts_not_vulnerable_is_empty():
    tool = JwtAlgorithmConfusionProbe()
    assert tool.extract_facts({"target": "https://example.com"}, {"vulnerable": False}) == []


def test_extract_facts_vulnerable_is_critical():
    tool = JwtAlgorithmConfusionProbe()
    facts = tool.extract_facts({"target": "https://example.com/api"}, {"vulnerable": True})
    assert len(facts) == 1
    assert facts[0]["severity"] == "critical"
    assert facts[0]["host"] == "example.com"
    assert facts[0]["port"] == 443
