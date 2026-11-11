from unittest.mock import patch

from tradecraft.adapters.jwt_crack.execute import RawJwtCrackResult
from tradecraft.tools.jwt_crack import JwtCrack
from tradecraft.tools.registry import ALL_TOOLS

TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_tool_identity_and_contract():
    tool = JwtCrack()
    assert tool.tool_id == "jwt_crack"
    assert tool.spec.name == "jwt_crack"
    assert tool.scope_param == "jwt"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "jwt_crack" for t in ALL_TOOLS)


def test_run_reports_cracked_secret_in_full():
    tool = JwtCrack()
    raw = RawJwtCrackResult(jwt=TOKEN, algorithm="HS256", attempted=5, cracked_secret="your-256-bit-secret")
    with patch("tradecraft.adapters.jwt_crack.execute.execute", return_value=raw) as ex:
        out = tool.run(jwt=TOKEN, wordlist="x")
    ex.assert_called_once_with(jwt=TOKEN, wordlist="x")
    assert out == {
        "jwt": TOKEN,
        "algorithm": "HS256",
        "cracked_secret": "your-256-bit-secret",
        "attempted": 5,
    }


def test_run_end_to_end_cracks_canonical_token():
    out = JwtCrack().run(jwt=TOKEN)
    assert out["cracked_secret"] == "your-256-bit-secret"


def test_extract_facts_is_empty():
    assert JwtCrack().extract_facts({"jwt": TOKEN}, {"cracked_secret": "x"}) == []
