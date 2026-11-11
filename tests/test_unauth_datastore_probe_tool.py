"""
Unit tests for UnauthDatastoreProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.unauth_datastore_probe.execute import (
    ElasticsearchResult,
    RedisResult,
    UnauthDatastoreResult,
)
from tradecraft.tools.unauth_datastore_probe import UnauthDatastoreProbe


def _vuln_redis_result():
    return UnauthDatastoreResult(
        target="10.0.0.5",
        host="10.0.0.5",
        redis=RedisResult(host="10.0.0.5", port=6379, connected=True, vulnerable=True, status="vulnerable"),
        vulnerable=True,
        summary="Redis (port 6379) VULNERABLE: unauthenticated command access",
    )


def test_unauth_datastore_probe_run():
    tool = UnauthDatastoreProbe()
    with patch("tradecraft.tools.unauth_datastore_probe.unauth_execute", return_value=_vuln_redis_result()):
        out = tool.run("10.0.0.5", service="redis")
    assert out["vulnerable"] is True
    assert out["host"] == "10.0.0.5"
    assert "_full_evidence" in out


def test_extract_evidence_pops_full_evidence():
    tool = UnauthDatastoreProbe()
    fake_full = {"vulnerable": False, "summary": "clean"}
    result_dict = {"_full_evidence": fake_full, "host": "10.0.0.5"}

    ev = tool.extract_evidence({"target": "10.0.0.5"}, result_dict)
    assert ev is not None
    assert ev[0] == "10.0.0.5"
    assert ev[1] == fake_full
    assert "_full_evidence" not in result_dict


def test_extract_evidence_none_when_missing():
    tool = UnauthDatastoreProbe()
    assert tool.extract_evidence({"target": "10.0.0.5"}, {"host": "10.0.0.5"}) is None


def test_extract_facts_redis_vulnerable_is_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "redis": {"connected": True, "port": 6379, "vulnerable": True, "redis_version": "7.0.5"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "redis"
    assert facts[0]["severity"] == "critical"
    assert facts[0]["version"] == "7.0.5"


def test_extract_facts_elasticsearch_vulnerable_is_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "elasticsearch": {"port": 9200, "vulnerable": True, "version": "8.11.0"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "elasticsearch"
    assert facts[0]["severity"] == "critical"
    assert facts[0]["version"] == "8.11.0"


def test_extract_facts_elasticsearch_sample_documents_retrieved():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "elasticsearch": {"port": 9200, "vulnerable": True, "version": "8.11.0", "sample_documents_count": 2},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert facts[0]["sample_documents_retrieved"] == 2
    # Facts carry a count only -- never the document content itself.
    assert "sample_documents" not in facts[0]


def test_extract_facts_both_present_neither_vulnerable():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "redis": {"connected": True, "port": 6379, "vulnerable": False, "redis_version": ""},
        "elasticsearch": {"port": 9200, "vulnerable": False, "status": "auth_required"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 2
    assert all("vulnerability" not in f for f in facts)
    assert {f["service"] for f in facts} == {"redis", "elasticsearch"}


def test_extract_facts_vault_vulnerable_is_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "vault": {"connected": True, "port": 8200, "vulnerable": True, "vault_version": "1.15.2"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "vault"
    assert facts[0]["severity"] == "critical"
    assert facts[0]["version"] == "1.15.2"


def test_extract_facts_couchdb_vulnerable_is_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "couchdb": {"connected": True, "port": 5984, "vulnerable": True, "couchdb_version": "3.3.3"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "couchdb"
    assert facts[0]["severity"] == "critical"
    assert "Admin Party" in facts[0]["vulnerability"]


def test_extract_facts_prometheus_vulnerable_is_high_not_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "prometheus": {"connected": True, "port": 9090, "vulnerable": True, "prometheus_version": "2.48.0"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "prometheus"
    assert facts[0]["severity"] == "high"


def test_extract_facts_memcached_not_connected_emits_nothing():
    tool = UnauthDatastoreProbe()
    res = {"host": "10.0.0.5", "memcached": {"connected": False, "port": 11211, "vulnerable": False}}
    assert tool.extract_facts({"target": "10.0.0.5"}, res) == []


def test_extract_facts_all_ten_present():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "redis": {"connected": True, "port": 6379, "vulnerable": True, "redis_version": "7.0.5"},
        "elasticsearch": {"port": 9200, "vulnerable": False},
        "vault": {"connected": True, "port": 8200, "vulnerable": True, "vault_version": "1.15.2"},
        "consul": {"connected": True, "port": 8500, "vulnerable": False, "consul_version": "1.17.0"},
        "prometheus": {"connected": True, "port": 9090, "vulnerable": True, "prometheus_version": "2.48.0"},
        "grafana": {"connected": True, "port": 3000, "vulnerable": False, "grafana_version": "10.2.2"},
        "kibana": {"connected": True, "port": 5601, "vulnerable": True, "kibana_version": "8.11.3"},
        "couchdb": {"connected": True, "port": 5984, "vulnerable": True, "couchdb_version": "3.3.3"},
        "memcached": {"connected": True, "port": 11211, "vulnerable": False, "memcached_version": "1.6.21"},
        "mongodb": {"connected": True, "port": 27017, "vulnerable": True, "mongodb_version": "7.0.5"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 10
    assert {f["service"] for f in facts} == {
        "redis", "elasticsearch", "vault", "consul", "prometheus", "grafana", "kibana", "couchdb", "memcached",
        "mongodb",
    }
    vulnerable_services = {f["service"] for f in facts if "vulnerability" in f}
    assert vulnerable_services == {"redis", "vault", "prometheus", "kibana", "couchdb", "mongodb"}


def test_extract_facts_mongodb_vulnerable_is_critical():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "mongodb": {"connected": True, "port": 27017, "vulnerable": True, "mongodb_version": "7.0.5"},
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "mongodb"
    assert facts[0]["severity"] == "critical"
    assert facts[0]["version"] == "7.0.5"


def test_extract_facts_mongodb_sample_documents_retrieved():
    tool = UnauthDatastoreProbe()
    res = {
        "host": "10.0.0.5",
        "mongodb": {
            "connected": True, "port": 27017, "vulnerable": True,
            "mongodb_version": "7.0.5", "sample_documents_count": 3,
        },
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, res)
    assert facts[0]["sample_documents_retrieved"] == 3
    assert "sample_documents" not in facts[0]
