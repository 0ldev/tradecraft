import base64
import json
from unittest.mock import MagicMock, patch
import pytest
import requests

from tradecraft.adapters.jwt_analyze import execute as jwt_execute
from tradecraft.adapters.jwt_analyze import parse as jwt_parse


def _make_token(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    s = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    return f"{h}.{p}.{s}"


def test_decode_jwt_claims_valid():
    token = _make_token({"alg": "RS256", "typ": "JWT"}, {"user": "alice", "role": "viewer"})
    header, payload = jwt_execute.decode_jwt_claims(token)
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert payload == {"user": "alice", "role": "viewer"}


def test_decode_jwt_claims_invalid():
    with pytest.raises(ValueError, match="expected 3 segments"):
        jwt_execute.decode_jwt_claims("not.a.jwt.format")

    with pytest.raises(ValueError, match="invalid JWT header"):
        jwt_execute.decode_jwt_claims("invalid_b64.invalid_payload.sig")

    h = base64.urlsafe_b64encode(b"not-json").decode().rstrip("=")
    with pytest.raises(ValueError, match="invalid JWT header"):
        jwt_execute.decode_jwt_claims(f"{h}.{h}.sig")


def test_forge_none_alg_token():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "123", "user": "john", "role": "user", "admin": False}

    forged = jwt_execute.forge_none_alg_token(header, payload)
    assert forged.endswith(".")  # Trailing dot, empty signature

    f_header, f_payload = jwt_execute.decode_jwt_claims(forged + "dummy")
    assert f_header["alg"] == "none"
    assert f_payload["role"] == "admin"
    assert f_payload["admin"] is True
    assert f_payload["user"] == "admin"

    # Verify original dicts were not mutated
    assert header["alg"] == "HS256"
    assert payload["role"] == "user"
    assert payload["admin"] is False
    assert payload["user"] == "john"


def test_run_differential_success():
    mock_base = MagicMock(status_code=401)
    mock_forged = MagicMock(status_code=200)

    with patch("requests.get", side_effect=[mock_base, mock_forged]) as mock_get:
        diff = jwt_execute.run_differential("https://example.com/api/user", "forged.token.")
        assert diff.baseline_status == 401
        assert diff.forged_status == 200
        assert diff.error is None
        assert mock_get.call_count == 2
        second_kwargs = mock_get.call_args_list[1][1]
        assert second_kwargs["headers"] == {"Authorization": "Bearer forged.token."}


def test_run_differential_request_exception():
    with patch("requests.get", side_effect=requests.RequestException("connection dropped")):
        diff = jwt_execute.run_differential("https://example.com/api/user", "forged.token.")
        assert diff.error is not None
        assert "connection dropped" in diff.error


def test_parse_result():
    assert jwt_parse.parse_result(401, 200)["vulnerable"] is True
    assert jwt_parse.parse_result(403, 200)["vulnerable"] is True
    assert jwt_parse.parse_result(200, 200)["vulnerable"] is False
    assert jwt_parse.parse_result(401, 401)["vulnerable"] is False
    assert jwt_parse.parse_result(401, 403)["vulnerable"] is False
