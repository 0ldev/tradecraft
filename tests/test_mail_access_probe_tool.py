from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.mail_access_probe.execute import RawMailAccessResult
from tradecraft.tools.mail_access_probe import MailAccessProbe


class TestMailAccessProbeTool:
    def test_tool_metadata(self):
        tool = MailAccessProbe()
        assert tool.tool_id == "mail_access_probe"
        assert tool.scope_param == "target"
        assert tool.is_available() is True

    @patch("tradecraft.tools.mail_access_probe.mail_execute")
    def test_run_and_extract_evidence_facts(self, mock_exec):
        mock_exec.return_value = RawMailAccessResult(
            target="mail.example.com",
            host="mail.example.com",
            port=143,
            protocol="imap",
            connected=True,
            banner="* OK Dovecot 2.3 ready.",
            is_tls=False,
            starttls_advertised=True,
            capabilities_pre_tls=["IMAP4rev1", "STARTTLS", "AUTH=PLAIN"],
            rtt_ms=18.4,
        )

        tool = MailAccessProbe()
        result = tool.run(target="mail.example.com", port=143)

        assert result["connected"] is True
        assert result["protocol"] == "imap"
        assert result["software"] == "Dovecot 2.3"
        assert result["security_audit"]["cleartext_auth_allowed"] is True
        assert "_full_evidence" in result

        # Test evidence extraction
        ev = tool.extract_evidence({"target": "mail.example.com"}, result)
        assert ev is not None
        host, full = ev
        assert host == "mail.example.com"
        assert full["connected"] is True
        assert "_full_evidence" not in result

        facts = tool.extract_facts({"target": "mail.example.com"}, result)
        assert len(facts) == 2

        # Service fact
        assert facts[0]["host"] == "mail.example.com"
        assert facts[0]["port"] == 143
        assert facts[0]["service"] == "imap"
        assert facts[0]["version"] == "Dovecot 2.3"

        # Vulnerability fact
        assert facts[1]["host"] == "mail.example.com"
        assert facts[1]["port"] == 143
        assert facts[1]["severity"] == "medium"
        assert "RFC 3501" in facts[1]["vulnerability"]

    @patch("tradecraft.tools.mail_access_probe.mail_execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawMailAccessResult(
            target="mail.example.com",
            host="mail.example.com",
            port=143,
            connected=False,
            error="Connection timed out",
        )

        tool = MailAccessProbe()
        result = tool.run(target="mail.example.com", port=143)

        assert result["connected"] is False
        assert "timed out" in result["error"]
        facts = tool.extract_facts({"target": "mail.example.com"}, result)
        assert facts == []
