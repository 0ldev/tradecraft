from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.interactsh.execute import execute, is_daemon_running, stop_daemon
from tradecraft.adapters.interactsh.parse import (
    is_after,
    parse_interaction_record,
    parse_interactions_jsonl,
)


class TestIsAfter:
    def test_after(self):
        assert is_after("2026-11-04T12:00:00Z", "2026-11-04T11:00:00Z") is True

    def test_before(self):
        assert is_after("2026-11-03T10:00:00Z", "2026-11-04T11:00:00Z") is False

    def test_equal_counts_as_after(self):
        assert is_after("2026-11-04T11:00:00Z", "2026-11-04T11:00:00Z") is True

    def test_nanosecond_precision_is_truncated_not_rejected(self):
        # Go's RFC3339Nano can emit up to 9 fractional digits.
        assert is_after("2026-11-04T12:00:00.254726586Z", "2026-11-04T11:00:00Z") is True

    def test_unparseable_timestamp_returns_none_not_false(self):
        assert is_after("not-a-timestamp", "2026-11-04T11:00:00Z") is None
        assert is_after("2026-11-04T12:00:00Z", "") is None


class TestInteractshParse:
    def test_parse_http_record(self):
        raw = {
            "protocol": "http",
            "remote-address": "1.2.3.4:5678",
            "timestamp": "2026-11-01T20:00:00Z",
            "raw-request": "GET /ssrf_test HTTP/1.1\r\nHost: test.oast.me\r\n",
        }
        parsed = parse_interaction_record(raw)
        assert parsed["protocol"] == "http"
        assert parsed["remote_address"] == "1.2.3.4:5678"
        assert parsed["request_summary"] == "GET /ssrf_test HTTP/1.1"

    def test_parse_dns_record(self):
        raw = {
            "protocol": "dns",
            "remote-address": "8.8.8.8:1234",
            "timestamp": "2026-11-01T20:00:01Z",
            "q-type": "A",
            "raw-request": "dns query bytes",
        }
        parsed = parse_interaction_record(raw)
        assert parsed["protocol"] == "dns"
        assert parsed["query_type"] == "A"
        assert parsed["request_summary"] == "DNS A query"

    def test_parse_interactions_jsonl(self):
        jsonl = (
            '{"protocol": "dns", "remote-address": "1.1.1.1", "q-type": "A"}\n'
            'invalid line\n'
            '{"protocol": "http", "remote-address": "2.2.2.2", "raw-request": "POST /api HTTP/1.1"}\n'
        )
        records = parse_interactions_jsonl(jsonl)
        assert len(records) == 2
        assert records[0]["protocol"] == "dns"
        assert records[1]["protocol"] == "http"
        assert records[1]["request_summary"] == "POST /api HTTP/1.1"


class TestInteractshExecute:
    @patch("tradecraft.adapters.interactsh.execute.start_daemon")
    def test_execute_generate(self, mock_start):
        mock_start.return_value = ("testdomain123.oast.me", None)
        res = execute(action="generate")
        assert res["action"] == "generate"
        assert res["active"] is True
        assert res["payload_domain"] == "testdomain123.oast.me"
        assert res["payload_url"] == "http://testdomain123.oast.me"

    @patch("tradecraft.adapters.interactsh.execute.start_daemon")
    def test_execute_generate_error(self, mock_start):
        mock_start.return_value = (None, "interactsh-client not found")
        res = execute(action="generate")
        assert res["action"] == "generate"
        assert res["active"] is False
        assert "not found" in res["error"]

    @patch("tradecraft.adapters.interactsh.execute.is_daemon_running", return_value=(True, 1234))
    @patch("pathlib.Path.read_text")
    @patch("os.path.exists", return_value=True)
    def test_execute_poll(self, mock_exists, mock_read, mock_running):
        fake_jsonl = (
            '{"protocol": "http", "remote-address": "10.0.0.1", '
            '"raw-request": "GET / HTTP/1.1", "timestamp": "2026-11-04T12:00:00Z"}\n'
        )
        mock_read.side_effect = ["testdomain.oast.me", "2026-11-04T11:00:00Z", fake_jsonl]
        res = execute(action="poll")
        assert res["action"] == "poll"
        assert res["active"] is True
        assert res["payload_domain"] == "testdomain.oast.me"
        assert res["payload_domain_generated_at"] == "2026-11-04T11:00:00Z"
        assert res["total_interactions"] == 1
        assert res["interactions"][0]["protocol"] == "http"
        # Interaction timestamp (12:00) is after domain generation (11:00).
        assert res["interactions"][0]["after_domain_generated"] is True

    @patch("tradecraft.adapters.interactsh.execute.is_daemon_running", return_value=(True, 1234))
    @patch("pathlib.Path.read_text")
    @patch("os.path.exists", return_value=True)
    def test_execute_poll_flags_stale_interaction(self, mock_exists, mock_read, mock_running):
        # An interaction timestamped BEFORE the domain was generated --
        # e.g. stale state left behind by an earlier process -- must be
        # flagged, never silently treated as caused by this engagement.
        fake_jsonl = (
            '{"protocol": "dns", "remote-address": "8.8.8.8", '
            '"timestamp": "2026-11-03T10:00:00Z"}\n'
        )
        mock_read.side_effect = ["testdomain.oast.me", "2026-11-04T11:00:00Z", fake_jsonl]
        res = execute(action="poll")
        assert res["interactions"][0]["after_domain_generated"] is False

    @patch("tradecraft.adapters.interactsh.execute.stop_daemon", return_value=True)
    def test_execute_stop(self, mock_stop):
        res = execute(action="stop")
        assert res["action"] == "stop"
        assert res["stopped"] is True

    def test_execute_unknown_action(self):
        res = execute(action="invalid_action")
        assert "error" in res
        assert "unknown interactsh action" in res["error"]

    def test_stop_daemon_reaps_tracked_proc_and_cleans_log_file(self, tmp_path, monkeypatch):
        import sys

        mod = sys.modules["tradecraft.adapters.interactsh.execute"]

        pid_file = tmp_path / "daemon.pid"
        domain_file = tmp_path / "domain.txt"
        output_file = tmp_path / "interactions.jsonl"
        gen_file = tmp_path / "generated_at.txt"
        log_file = tmp_path / "daemon.log"
        for f in (pid_file, domain_file, output_file, gen_file, log_file):
            f.write_text("x", encoding="utf-8")

        fake_proc = MagicMock()
        fake_proc.pid = 999999
        fake_proc.poll.return_value = None

        monkeypatch.setattr(mod, "PID_FILE", str(pid_file))
        monkeypatch.setattr(mod, "DOMAIN_FILE", str(domain_file))
        monkeypatch.setattr(mod, "OUTPUT_FILE", str(output_file))
        monkeypatch.setattr(mod, "GENERATED_AT_FILE", str(gen_file))
        monkeypatch.setattr(mod, "LOG_FILE", str(log_file))
        monkeypatch.setattr(mod, "_DAEMON_PROC", fake_proc)
        monkeypatch.setattr(mod, "is_daemon_running", lambda: (False, None))

        assert stop_daemon() is True
        fake_proc.terminate.assert_called_once()
        fake_proc.wait.assert_called()
        assert mod._DAEMON_PROC is None
        for f in (pid_file, domain_file, output_file, gen_file, log_file):
            assert not f.exists()

    def test_start_daemon_redirects_output_to_log_file_and_extracts_domain(self, tmp_path, monkeypatch):
        import sys

        mod = sys.modules["tradecraft.adapters.interactsh.execute"]

        pid_file = tmp_path / "daemon.pid"
        domain_file = tmp_path / "domain.txt"
        output_file = tmp_path / "interactions.jsonl"
        gen_file = tmp_path / "generated_at.txt"
        log_file = tmp_path / "daemon.log"

        monkeypatch.setattr(mod, "PID_FILE", str(pid_file))
        monkeypatch.setattr(mod, "DOMAIN_FILE", str(domain_file))
        monkeypatch.setattr(mod, "OUTPUT_FILE", str(output_file))
        monkeypatch.setattr(mod, "GENERATED_AT_FILE", str(gen_file))
        monkeypatch.setattr(mod, "LOG_FILE", str(log_file))
        monkeypatch.setattr(mod.shutil, "which", lambda _b: "/usr/bin/interactsh-client")

        expected_domain = "c23b2la0000000000000abcd1234.oast.me"
        fake_proc = MagicMock()
        fake_proc.pid = 42424
        fake_proc.poll.return_value = None

        def fake_popen(cmd, **kwargs):
            # Confirm stdout goes to LOG_FILE (not subprocess.PIPE) so the
            # child can never block on a full pipe buffer after startup.
            assert kwargs.get("stdout") is not mod.subprocess.PIPE
            kwargs["stdout"].write(f"[INF] Listing 1 payload for OOB Testing\n[INF] {expected_domain}\n")
            kwargs["stdout"].flush()
            return fake_proc

        monkeypatch.setattr(mod.subprocess, "Popen", fake_popen)

        domain, err = mod.start_daemon()
        assert err is None
        assert domain == expected_domain
        assert pid_file.read_text() == "42424"
        assert domain_file.read_text() == expected_domain
        assert gen_file.exists()

        # Cleanup via stop_daemon
        monkeypatch.setattr(mod, "is_daemon_running", lambda: (False, None))
        mod.stop_daemon()
