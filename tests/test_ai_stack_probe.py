"""
Unit tests for ai_stack_probe adapter (execute, parse) and Tool glue.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.ai_stack_probe.execute import (
    RawAiStackProbeResult,
    ServiceCheckResult,
    execute,
    normalize_host_port,
    probe_flowise,
    probe_langflow,
    probe_litellm,
    probe_mlflow,
    probe_ollama,
    probe_ray,
    probe_vllm,
)
from tradecraft.adapters.ai_stack_probe.parse import parse_probe_result
from tradecraft.tools.ai_stack_probe import AiStackProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestAiStackProbeExecute:
    def test_normalize_host_port(self):
        assert normalize_host_port("http://ollama.local:11434") == ("ollama.local", 11434, "http")
        assert normalize_host_port("https://ai.internal") == ("ai.internal", 443, "https")
        assert normalize_host_port("10.0.0.5:8000") == ("10.0.0.5", 8000, "http")
        assert normalize_host_port("ai.corp", default_port=8265) == ("ai.corp", 8265, "http")

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_ollama_unauthenticated(self, mock_get):
        tags_resp = MagicMock(status_code=200)
        tags_resp.json.return_value = {
            "models": [{"name": "llama3:latest"}, {"name": "mistral:7b"}]
        }
        ver_resp = MagicMock(status_code=200)
        ver_resp.json.return_value = {"version": "0.3.14"}

        mock_get.side_effect = [tags_resp, ver_resp]
        res = probe_ollama("localhost", 11434)
        assert res.service == "ollama"
        assert res.port == 11434
        assert res.accessible is True
        assert res.unauthenticated is True
        assert res.version == "0.3.14"
        assert res.details["model_count"] == 2
        assert "llama3:latest" in res.details["models"]

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_vllm_unauthenticated(self, mock_get):
        models_resp = MagicMock(status_code=200)
        models_resp.json.return_value = {
            "object": "list",
            "data": [{"id": "meta-llama/Meta-Llama-3-8B-Instruct"}],
        }
        mock_get.return_value = models_resp
        res = probe_vllm("127.0.0.1", 8000)
        assert res.service == "vllm"
        assert res.accessible is True
        assert res.unauthenticated is True
        assert res.details["models"] == ["meta-llama/Meta-Llama-3-8B-Instruct"]

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_langflow_unauthenticated(self, mock_get):
        flows_resp = MagicMock(status_code=200)
        flows_resp.json.return_value = [{"name": "RAG-Pipeline"}, {"name": "AgentFlow"}]
        ver_resp = MagicMock(status_code=200)
        ver_resp.json.return_value = {"version": "1.0.15"}

        mock_get.side_effect = [flows_resp, ver_resp]
        res = probe_langflow("langflow.internal", 7860)
        assert res.service == "langflow"
        assert res.accessible is True
        assert res.unauthenticated is True
        assert res.details["flow_count"] == 2
        assert "RAG-Pipeline" in res.details["flows"]

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_flowise_unauthenticated(self, mock_get):
        flows_resp = MagicMock(status_code=200)
        flows_resp.json.return_value = [{"name": "SupportBot"}]
        mock_get.return_value = flows_resp
        res = probe_flowise("flowise.internal", 3000)
        assert res.service == "flowise"
        assert res.accessible is True
        assert res.unauthenticated is True
        assert res.details["chatflow_count"] == 1

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_ray_unauthenticated(self, mock_get):
        ver_resp = MagicMock(status_code=200)
        ver_resp.json.return_value = {"ray_version": "2.9.0"}
        jobs_resp = MagicMock(status_code=200)

        mock_get.side_effect = [ver_resp, jobs_resp]
        res = probe_ray("ray-cluster.local", 8265)
        assert res.service == "ray"
        assert res.accessible is True
        assert res.unauthenticated is True
        assert "CVE-2023-48022" in res.summary

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_litellm(self, mock_get):
        health_resp = MagicMock(status_code=200, text='{"status":"healthy"}')
        routes_resp = MagicMock(status_code=200)
        mock_get.side_effect = [health_resp, routes_resp]
        res = probe_litellm("litellm.local", 4000)
        assert res.service == "litellm"
        assert res.accessible is True
        assert res.unauthenticated is True

    @patch("tradecraft.adapters.ai_stack_probe.execute._safe_get")
    def test_probe_mlflow(self, mock_get):
        exp_resp = MagicMock(status_code=200)
        exp_resp.json.return_value = {"experiments": [{"experiment_id": "0"}]}
        mock_get.return_value = exp_resp
        res = probe_mlflow("mlflow.local", 5000)
        assert res.service == "mlflow"
        assert res.accessible is True
        assert res.unauthenticated is True
        assert res.details["experiments_count"] == 1

    def test_execute_empty_target(self):
        res = execute(target="")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.ai_stack_probe.execute.probe_ollama")
    def test_execute_single_service(self, mock_ollama):
        mock_ollama.return_value = ServiceCheckResult(
            service="ollama", port=11434, accessible=True, unauthenticated=True
        )
        res = execute("10.0.0.1", service="ollama")
        assert res.target == "10.0.0.1"
        assert res.vulnerable is True
        assert len(res.findings) == 1
        assert res.findings[0].service == "ollama"


class TestAiStackProbeParse:
    def test_parse_with_findings(self):
        finding = ServiceCheckResult(
            service="ollama",
            port=11434,
            accessible=True,
            unauthenticated=True,
            version="0.3.14",
            summary="Exposed Ollama API",
            details={"models": ["llama3"]},
        )
        raw = RawAiStackProbeResult(
            target="10.0.0.5",
            host="10.0.0.5",
            vulnerable=True,
            findings=[finding],
        )
        parsed = parse_probe_result(raw)
        assert parsed["target"] == "10.0.0.5"
        assert parsed["vulnerable"] is True
        assert parsed["count"] == 1
        assert parsed["unauthenticated_count"] == 1
        assert parsed["findings"][0]["service"] == "ollama"

    def test_parse_with_error(self):
        raw = RawAiStackProbeResult(target="foo", host="", error="connection failed")
        parsed = parse_probe_result(raw)
        assert parsed["error"] == "connection failed"
        assert parsed["count"] == 0
        assert parsed["vulnerable"] is False


class TestAiStackProbeTool:
    def test_registration(self):
        tool = next((t for t in ALL_TOOLS if t.tool_id == "ai_stack_probe"), None)
        assert tool is not None
        assert isinstance(tool, AiStackProbe)

    def test_spec_attributes(self):
        tool = AiStackProbe()
        assert tool.spec.name == "ai_stack_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True

    @patch("tradecraft.adapters.ai_stack_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawAiStackProbeResult(
            target="ai.local:11434",
            host="ai.local",
            vulnerable=True,
            findings=[
                ServiceCheckResult(
                    service="ollama",
                    port=11434,
                    accessible=True,
                    unauthenticated=True,
                    version="0.3.12",
                )
            ],
        )
        tool = AiStackProbe()
        res = tool.run(target="ai.local:11434")
        assert res["target"] == "ai.local:11434"
        assert res["host"] == "ai.local"
        assert res["vulnerable"] is True
        assert len(res["findings"]) == 1

        facts = tool.extract_facts({"target": "ai.local:11434"}, res)
        assert len(facts) == 1
        assert facts[0]["host"] == "ai.local"
        assert facts[0]["port"] == 11434
        assert facts[0]["service"] == "ollama"
        assert facts[0]["ai_unauthenticated"] is True

        # Evidence extraction
        ev = tool.extract_evidence({"target": "ai.local:11434"}, res)
        assert ev is not None
        assert ev[0] == "ai.local"

    def test_profile_membership(self):
        web = load_profile("web")
        assert "ai_stack_probe" in web
        cloud = load_profile("cloud")
        assert "ai_stack_probe" in cloud
