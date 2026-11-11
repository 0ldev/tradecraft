"""
Unit tests for OpenApiSpecDiscoveryProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.openapi_spec_discovery_probe.execute import OpenApiSpecDiscoveryResult, SpecHit
from tradecraft.tools.openapi_spec_discovery_probe import ENDPOINT_DISPLAY_CAP, OpenApiSpecDiscoveryProbe


def _result_with_n_endpoints(n):
    paths = {f"/path{i}": {"get": {}} for i in range(n)}
    spec = {"swagger": "2.0", "info": {"title": "Big API", "version": "1.0"}, "paths": paths}
    hit = SpecHit(path="/swagger.json", status_code=200, spec_version="2.0", title="Big API",
                  api_version="1.0", raw_spec=spec)
    return OpenApiSpecDiscoveryResult(target="api.example.com", base_url="https://api.example.com",
                                       hits=[hit], checked_paths=10)


def test_run_caps_endpoint_list_and_offloads_full_list():
    tool = OpenApiSpecDiscoveryProbe()
    with patch(
        "tradecraft.tools.openapi_spec_discovery_probe.spec_execute",
        return_value=_result_with_n_endpoints(ENDPOINT_DISPLAY_CAP + 10),
    ):
        out = tool.run("api.example.com")
    spec = out["specs_found"][0]
    assert len(spec["endpoints"]) == ENDPOINT_DISPLAY_CAP
    assert spec["endpoints_omitted"] == 10
    assert "_full_evidence" in out


def test_extract_evidence_has_full_endpoint_list():
    tool = OpenApiSpecDiscoveryProbe()
    with patch(
        "tradecraft.tools.openapi_spec_discovery_probe.spec_execute",
        return_value=_result_with_n_endpoints(ENDPOINT_DISPLAY_CAP + 10),
    ):
        out = tool.run("api.example.com")
    ev = tool.extract_evidence({"target": "api.example.com"}, out)
    assert ev is not None
    assert len(ev[1]["specs_found"][0]["endpoints"]) == ENDPOINT_DISPLAY_CAP + 10


def test_extract_facts_flags_admin_paths_medium():
    tool = OpenApiSpecDiscoveryProbe()
    res = {
        "specs_found": [
            {"path": "/swagger.json", "endpoint_count": 3, "of_interest": ["POST /admin/reset"]},
        ],
    }
    facts = tool.extract_facts({"target": "api.example.com"}, res)
    assert len(facts) == 1
    assert facts[0]["severity"] == "medium"


def test_extract_facts_no_admin_paths_low():
    tool = OpenApiSpecDiscoveryProbe()
    res = {"specs_found": [{"path": "/swagger.json", "endpoint_count": 3, "of_interest": []}]}
    facts = tool.extract_facts({"target": "api.example.com"}, res)
    assert facts[0]["severity"] == "low"
