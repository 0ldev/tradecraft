"""
Unit tests for unauth_datastore_probe adapter (execution and parsing).
"""
import socket
import struct
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.unauth_datastore_probe.execute import (
    ConsulResult,
    CouchDbResult,
    ElasticsearchResult,
    GrafanaResult,
    KibanaResult,
    MemcachedResult,
    MongoResult,
    PrometheusResult,
    RedisResult,
    UnauthDatastoreResult,
    VaultResult,
    _bson_encode_document,
    _mongo_sample_documents,
    execute,
    normalize_host,
    probe_consul,
    probe_couchdb,
    probe_elasticsearch,
    probe_grafana,
    probe_kibana,
    probe_memcached,
    probe_mongodb,
    probe_prometheus,
    probe_redis,
    probe_vault,
)
from tradecraft.adapters.unauth_datastore_probe.parse import parse


def _mongo_op_msg_response(doc: dict, request_id: int = 1) -> bytes:
    """Builds a protocol-accurate OP_MSG reply (header + flagBits + one
    kind-0 section) using the adapter's own BSON encoder, the same way a
    real mongod would frame a 'hello'/'listDatabases' reply."""
    doc_bytes = _bson_encode_document(doc)
    body = struct.pack("<I", 0) + b"\x00" + doc_bytes
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def test_normalize_host():
    assert normalize_host("10.0.0.5") == "10.0.0.5"
    assert normalize_host("redis://cache.example.com:6379/0") == "cache.example.com"
    assert normalize_host("es.internal:9200") == "es.internal"
    assert normalize_host("  target.host/  ") == "target.host"


# ---------------------------------------------------------------- Redis


@patch("socket.socket")
def test_probe_redis_vulnerable(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.side_effect = [
        b"+PONG\r\n",
        b"redis_version:7.0.5\r\nos:Linux 5.15.0\r\n",
    ]

    res = probe_redis("10.0.0.5", 6379, timeout=3.0)
    assert res.connected is True
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.redis_version == "7.0.5"
    assert res.os_info == "Linux 5.15.0"


@patch("socket.socket")
def test_probe_redis_auth_required(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.side_effect = [b"-NOAUTH Authentication required.\r\n"]

    res = probe_redis("10.0.0.5", 6379, timeout=3.0)
    assert res.connected is True
    assert res.status == "auth_required"
    assert res.vulnerable is False
    assert res.unauthenticated_access is False


@patch("socket.socket")
def test_probe_redis_refused(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = ConnectionRefusedError()

    res = probe_redis("10.0.0.5", 6379, timeout=3.0)
    assert res.connected is False
    assert res.status == "refused"
    assert res.vulnerable is False


@patch("socket.socket")
def test_probe_redis_timeout(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = socket.timeout()

    res = probe_redis("10.0.0.5", 6379, timeout=3.0)
    assert res.connected is False
    assert res.status == "timeout"
    assert res.vulnerable is False


# ---------------------------------------------------------------- Elasticsearch


def _resp(status_code, payload=None):
    r = MagicMock()
    r.status_code = status_code
    if payload is None:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = payload
    return r


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_elasticsearch_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"cluster_name": "my-cluster", "version": {"number": "8.11.0"}}),
        _resp(200, [{"index": "logs-2024"}, {"index": "users"}]),
        _resp(200, {"hits": {"hits": [{"_source": {"email": "a@example.com"}}, {"_source": {"email": "b@example.com"}}]}}),
    ]

    res = probe_elasticsearch("10.0.0.5", 9200, timeout=3.0)
    assert res.status_code == 200
    assert res.vulnerable is True
    assert res.unauthenticated_access is True
    assert res.status == "vulnerable"
    assert res.cluster_name == "my-cluster"
    assert res.version == "8.11.0"
    assert res.index_names == ["logs-2024", "users"]
    assert res.index_count == 2
    # Sampling never downgrades the already-proven finding above.
    assert res.sample_index == "logs-2024"
    assert res.sample_documents == [{"email": "a@example.com"}, {"email": "b@example.com"}]
    assert res.sample_error is None
    # The _search call used the same unauthenticated GET, bounded size.
    search_call = mock_get.call_args_list[2]
    assert search_call.args[0] == "http://10.0.0.5:9200/logs-2024/_search"
    assert search_call.kwargs["params"] == {"size": 3}


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_elasticsearch_sample_failure_does_not_downgrade_finding(mock_get):
    mock_get.side_effect = [
        _resp(200, {"cluster_name": "my-cluster", "version": {"number": "8.11.0"}}),
        _resp(200, [{"index": "logs-2024"}]),
        _resp(403),
    ]

    res = probe_elasticsearch("10.0.0.5", 9200, timeout=3.0)
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.sample_documents == []
    assert "403" in res.sample_error


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_elasticsearch_no_indices_skips_sampling(mock_get):
    mock_get.side_effect = [
        _resp(200, {"cluster_name": "my-cluster", "version": {"number": "8.11.0"}}),
        _resp(200, []),
    ]

    res = probe_elasticsearch("10.0.0.5", 9200, timeout=3.0)
    assert res.vulnerable is True
    assert res.sample_index == ""
    assert res.sample_documents == []
    assert res.sample_error is None
    assert mock_get.call_count == 2  # no third call attempted


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_elasticsearch_auth_required(mock_get):
    mock_get.return_value = _resp(401)

    res = probe_elasticsearch("10.0.0.5", 9200, timeout=3.0)
    assert res.status_code == 401
    assert res.status == "auth_required"
    assert res.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_elasticsearch_request_error(mock_get):
    mock_get.side_effect = requests.RequestException("connection reset")

    res = probe_elasticsearch("10.0.0.5", 9200, timeout=3.0)
    assert res.status == "error"
    assert res.vulnerable is False
    assert "connection reset" in res.error


# ---------------------------------------------------------------- Vault


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_vault_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "1.15.2", "sealed": False}),
        _resp(200, {"secret/": {"type": "kv"}}),
    ]

    res = probe_vault("10.0.0.5", 8200, timeout=3.0)
    assert res.connected is True
    assert res.vault_version == "1.15.2"
    assert res.sealed is False
    assert res.mounts_exposed is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_vault_auth_required(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "1.15.2", "sealed": False}),
        _resp(403),
    ]

    res = probe_vault("10.0.0.5", 8200, timeout=3.0)
    assert res.connected is True
    assert res.status == "auth_required"
    assert res.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_vault_not_vault(mock_get):
    mock_get.return_value = _resp(200, {"cluster_name": "not-vault"})

    res = probe_vault("10.0.0.5", 8200, timeout=3.0)
    assert res.connected is False
    assert res.status == "unexpected_response"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_vault_request_error(mock_get):
    mock_get.side_effect = requests.RequestException("refused")

    res = probe_vault("10.0.0.5", 8200, timeout=3.0)
    assert res.status == "error"
    assert res.vulnerable is False


# ---------------------------------------------------------------- Consul


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_consul_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"Config": {"Version": "1.17.0"}}),
        _resp(200, [{"Key": "secret/db-password", "Value": "cGFzcw=="}]),
    ]

    res = probe_consul("10.0.0.5", 8500, timeout=3.0)
    assert res.connected is True
    assert res.consul_version == "1.17.0"
    assert res.kv_keys_exposed == 1
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_consul_auth_required_on_agent_self(mock_get):
    mock_get.return_value = _resp(403)

    res = probe_consul("10.0.0.5", 8500, timeout=3.0)
    assert res.connected is True
    assert res.status == "auth_required"
    assert res.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_consul_agent_open_but_kv_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, {"Config": {"Version": "1.17.0"}}),
        _resp(403),
    ]

    res = probe_consul("10.0.0.5", 8500, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_consul_kv_404_is_not_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"Config": {"Version": "1.17.0"}}),
        _resp(404),
    ]

    res = probe_consul("10.0.0.5", 8500, timeout=3.0)
    assert res.vulnerable is False
    assert res.status == "unexpected_response"


# ---------------------------------------------------------------- Prometheus


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_prometheus_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"data": {"version": "2.48.0"}}),
        _resp(200, {"data": {"activeTargets": [{"job": "node"}, {"job": "api"}]}}),
    ]

    res = probe_prometheus("10.0.0.5", 9090, timeout=3.0)
    assert res.connected is True
    assert res.prometheus_version == "2.48.0"
    assert res.targets_exposed == 2
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_prometheus_buildinfo_auth_required(mock_get):
    mock_get.return_value = _resp(401)

    res = probe_prometheus("10.0.0.5", 9090, timeout=3.0)
    assert res.connected is False
    assert res.status == "auth_required"
    assert res.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_prometheus_targets_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, {"data": {"version": "2.48.0"}}),
        _resp(403),
    ]

    res = probe_prometheus("10.0.0.5", 9090, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


# ---------------------------------------------------------------- Grafana


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_grafana_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "10.2.2"}),
        _resp(200, [{"id": 1, "name": "InfluxDB"}, {"id": 2, "name": "Postgres"}]),
    ]

    res = probe_grafana("10.0.0.5", 3000, timeout=3.0)
    assert res.connected is True
    assert res.grafana_version == "10.2.2"
    assert res.datasources_exposed == 2
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_grafana_datasources_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "10.2.2"}),
        _resp(401),
    ]

    res = probe_grafana("10.0.0.5", 3000, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_grafana_health_fails(mock_get):
    mock_get.return_value = _resp(500)

    res = probe_grafana("10.0.0.5", 3000, timeout=3.0)
    assert res.connected is False
    assert res.status == "unexpected_response"


# ---------------------------------------------------------------- Kibana


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_kibana_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": {"number": "8.11.3"}}),
        _resp(200, {"total": 5}),
    ]

    res = probe_kibana("10.0.0.5", 5601, timeout=3.0)
    assert res.connected is True
    assert res.kibana_version == "8.11.3"
    assert res.saved_objects_exposed == 5
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_kibana_saved_objects_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": {"number": "8.11.3"}}),
        _resp(403),
    ]

    res = probe_kibana("10.0.0.5", 5601, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_kibana_status_auth_required(mock_get):
    mock_get.return_value = _resp(401)

    res = probe_kibana("10.0.0.5", 5601, timeout=3.0)
    assert res.connected is False
    assert res.status == "auth_required"


# ---------------------------------------------------------------- CouchDB


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_couchdb_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"couchdb": "Welcome", "version": "3.3.3"}),
        _resp(200, ["_replicator", "_users", "mydata"]),
    ]

    res = probe_couchdb("10.0.0.5", 5984, timeout=3.0)
    assert res.connected is True
    assert res.couchdb_version == "3.3.3"
    assert res.databases_exposed == 3
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_couchdb_all_dbs_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, {"couchdb": "Welcome", "version": "3.3.3"}),
        _resp(401),
    ]

    res = probe_couchdb("10.0.0.5", 5984, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.unauth_datastore_probe.execute.requests.get")
def test_probe_couchdb_not_couchdb(mock_get):
    mock_get.return_value = _resp(200, {"other": "thing"})

    res = probe_couchdb("10.0.0.5", 5984, timeout=3.0)
    assert res.connected is False
    assert res.status == "unexpected_response"


# ---------------------------------------------------------------- Memcached


@patch("socket.socket")
def test_probe_memcached_vulnerable(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.return_value = b"VERSION 1.6.21\r\n"

    res = probe_memcached("10.0.0.5", 11211, timeout=3.0)
    assert res.connected is True
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.memcached_version == "1.6.21"


@patch("socket.socket")
def test_probe_memcached_unexpected_response(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.return_value = b"ERROR\r\n"

    res = probe_memcached("10.0.0.5", 11211, timeout=3.0)
    assert res.vulnerable is False
    assert res.status == "unexpected_response"


@patch("socket.socket")
def test_probe_memcached_refused(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = ConnectionRefusedError()

    res = probe_memcached("10.0.0.5", 11211, timeout=3.0)
    assert res.connected is False
    assert res.status == "refused"
    assert res.vulnerable is False


@patch("socket.socket")
def test_probe_memcached_timeout(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = socket.timeout()

    res = probe_memcached("10.0.0.5", 11211, timeout=3.0)
    assert res.status == "timeout"
    assert res.vulnerable is False


# ---------------------------------------------------------------- MongoDB


@patch("socket.socket")
def test_probe_mongodb_vulnerable(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    hello = _mongo_op_msg_response({"ismaster": True, "maxWireVersion": 17}, request_id=1)
    list_dbs = _mongo_op_msg_response(
        {"ok": 1, "databases": [{"name": "admin"}, {"name": "config"}, {"name": "secrets"}]},
        request_id=2,
    )
    list_colls = _mongo_op_msg_response(
        {"ok": 1, "cursor": {"firstBatch": [{"name": "users", "type": "collection"}]}}, request_id=3
    )
    find = _mongo_op_msg_response(
        {"ok": 1, "cursor": {"firstBatch": [{"email": "a@example.com"}, {"email": "b@example.com"}]}},
        request_id=4,
    )
    mock_sock.recv.side_effect = [
        hello[:16], hello[16:], list_dbs[:16], list_dbs[16:],
        list_colls[:16], list_colls[16:], find[:16], find[16:],
    ]

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.connected is True
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.max_wire_version == 17
    assert res.databases_exposed == 3
    assert res.database_names == ["admin", "config", "secrets"]
    # Sampling skipped admin/config (system databases) and picked "secrets".
    assert res.sample_database == "secrets"
    assert res.sample_collection == "users"
    assert res.sample_documents == [{"email": "a@example.com"}, {"email": "b@example.com"}]
    assert res.sample_error is None


@patch("socket.socket")
def test_probe_mongodb_only_system_databases_skips_sampling(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    hello = _mongo_op_msg_response({"maxWireVersion": 17}, request_id=1)
    list_dbs = _mongo_op_msg_response(
        {"ok": 1, "databases": [{"name": "admin"}, {"name": "local"}, {"name": "config"}]}, request_id=2
    )
    mock_sock.recv.side_effect = [hello[:16], hello[16:], list_dbs[:16], list_dbs[16:]]

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.vulnerable is True  # listDatabases alone already proves it
    assert res.sample_database == ""
    assert res.sample_documents == []
    assert res.sample_error == "no non-system database to sample"
    assert mock_sock.recv.call_count == 4  # no listCollections/find attempted


@patch("socket.socket")
def test_mongo_sample_documents_no_collections_found(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    sock = socket.socket()  # mocked by the class patch above

    empty_colls = _mongo_op_msg_response({"ok": 1, "cursor": {"firstBatch": []}}, request_id=3)
    mock_sock.recv.side_effect = [empty_colls[:16], empty_colls[16:]]

    db, coll, docs, err = _mongo_sample_documents(sock, ["secrets"])
    assert db == "secrets"
    assert coll == ""
    assert docs == []
    assert err == "no collections found"


@patch("socket.socket")
def test_mongo_sample_documents_find_denied(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    sock = socket.socket()

    colls = _mongo_op_msg_response(
        {"ok": 1, "cursor": {"firstBatch": [{"name": "users", "type": "collection"}]}}, request_id=3
    )
    find_denied = _mongo_op_msg_response({"ok": 0, "errmsg": "not authorized"}, request_id=4)
    mock_sock.recv.side_effect = [colls[:16], colls[16:], find_denied[:16], find_denied[16:]]

    db, coll, docs, err = _mongo_sample_documents(sock, ["secrets"])
    assert db == "secrets"
    assert coll == "users"
    assert docs == []
    assert err == "find failed or was denied"


def test_mongo_sample_documents_no_non_system_database():
    db, coll, docs, err = _mongo_sample_documents(MagicMock(), ["admin", "local", "config"])
    assert (db, coll, docs) == ("", "", [])
    assert err == "no non-system database to sample"


@patch("socket.socket")
def test_probe_mongodb_sample_failure_does_not_downgrade_finding(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    hello = _mongo_op_msg_response({"maxWireVersion": 17}, request_id=1)
    list_dbs = _mongo_op_msg_response({"ok": 1, "databases": [{"name": "secrets"}]}, request_id=2)
    list_colls_denied = _mongo_op_msg_response({"ok": 0, "errmsg": "not authorized"}, request_id=3)
    mock_sock.recv.side_effect = [
        hello[:16], hello[16:], list_dbs[:16], list_dbs[16:],
        list_colls_denied[:16], list_colls_denied[16:],
    ]

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.sample_documents == []
    assert res.sample_error == "listCollections failed or was denied"


@patch("socket.socket")
def test_probe_mongodb_auth_required(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    hello = _mongo_op_msg_response({"maxWireVersion": 17}, request_id=1)
    list_dbs = _mongo_op_msg_response(
        {"ok": 0, "errmsg": "command listDatabases requires authentication", "code": 13},
        request_id=2,
    )
    mock_sock.recv.side_effect = [hello[:16], hello[16:], list_dbs[:16], list_dbs[16:]]

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"
    assert "authentication" in res.server_response


@patch("socket.socket")
def test_probe_mongodb_oversized_message_length_rejected(mock_sock_cls):
    """A peer claiming a huge declared message_length (legitimate
    hello/listDatabases replies are always small) must be rejected before
    _recv_exact tries to buffer that many bytes -- regression test for the
    unbounded-read gap in _mongo_send_command."""
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    hostile_header = struct.pack("<iiii", 16 + 50_000_000, 1, 0, 2013)
    mock_sock.recv.side_effect = [hostile_header]

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "unexpected_response"
    # Only the 16-byte header was ever read -- the oversized body was
    # never requested, let alone buffered.
    assert mock_sock.recv.call_count == 1


@patch("socket.socket")
def test_probe_mongodb_refused(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = ConnectionRefusedError()

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.connected is False
    assert res.status == "refused"
    assert res.vulnerable is False


@patch("socket.socket")
def test_probe_mongodb_timeout(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = socket.timeout()

    res = probe_mongodb("10.0.0.5", 27017, timeout=3.0)
    assert res.status == "timeout"
    assert res.vulnerable is False


# ---------------------------------------------------------------- execute() dispatcher


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_elasticsearch")
@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_redis")
def test_execute_auto_probes_both(mock_redis, mock_es):
    mock_redis.return_value = RedisResult(host="10.0.0.5", port=6379, connected=False, status="refused")
    mock_es.return_value = ElasticsearchResult(host="10.0.0.5", port=9200, status="error")

    out = execute("10.0.0.5", service="auto")
    mock_redis.assert_called_once()
    mock_es.assert_called_once()
    assert out.redis is not None
    assert out.elasticsearch is not None
    assert out.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_elasticsearch")
@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_redis")
def test_execute_redis_only(mock_redis, mock_es):
    mock_redis.return_value = RedisResult(host="10.0.0.5", port=6379, connected=True, vulnerable=True, status="vulnerable")

    out = execute("10.0.0.5", service="redis")
    mock_redis.assert_called_once()
    mock_es.assert_not_called()
    assert out.elasticsearch is None
    assert out.vulnerable is True


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_elasticsearch")
@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_redis")
def test_execute_vulnerable_aggregates_from_either_service(mock_redis, mock_es):
    mock_redis.return_value = RedisResult(host="10.0.0.5", port=6379, connected=True, status="auth_required")
    mock_es.return_value = ElasticsearchResult(host="10.0.0.5", port=9200, vulnerable=True, status="vulnerable")

    out = execute("10.0.0.5", service="auto")
    assert out.vulnerable is True


def test_execute_invalid_target():
    out = execute("   ")
    assert out.error is not None
    assert out.vulnerable is False


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_mongodb")
def test_execute_explicit_mongodb_only(mock_mongo):
    mock_mongo.return_value = MongoResult(host="10.0.0.5", port=27017, connected=True, vulnerable=True, status="vulnerable")

    out = execute("10.0.0.5", service="mongodb")
    mock_mongo.assert_called_once_with("10.0.0.5", port=27017, timeout=5.0)
    assert out.mongodb is not None
    assert out.redis is None
    assert out.vulnerable is True


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_vault")
def test_execute_explicit_vault_only(mock_vault):
    mock_vault.return_value = VaultResult(host="10.0.0.5", port=8200, connected=True, vulnerable=True, status="vulnerable")

    out = execute("10.0.0.5", service="vault")
    mock_vault.assert_called_once_with("10.0.0.5", port=8200, timeout=5.0)
    assert out.vault is not None
    assert out.redis is None
    assert out.elasticsearch is None
    assert out.vulnerable is True


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_memcached")
def test_execute_auto_with_memcached_default_port_dispatches_to_memcached(mock_memcached):
    # 'auto' never probes memcached by default (only redis+elasticsearch
    # do) -- but an explicit port matching memcached's known default
    # (11211) must still resolve to the right protocol, not silently
    # misread as Redis the way an unrecognized port falls back to.
    mock_memcached.return_value = MemcachedResult(host="10.0.0.5", port=11211, connected=True, vulnerable=True, status="vulnerable")

    out = execute("10.0.0.5", service="auto", port=11211)
    mock_memcached.assert_called_once_with("10.0.0.5", port=11211, timeout=5.0)
    assert out.memcached is not None
    assert out.redis is None


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_redis")
def test_execute_auto_with_unrecognized_port_falls_back_to_redis(mock_redis):
    mock_redis.return_value = RedisResult(host="10.0.0.5", port=12345, connected=False, status="refused")

    out = execute("10.0.0.5", service="auto", port=12345)
    mock_redis.assert_called_once_with("10.0.0.5", port=12345, timeout=5.0)
    assert out.redis is not None


@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_elasticsearch")
@patch("tradecraft.adapters.unauth_datastore_probe.execute.probe_redis")
def test_execute_auto_default_still_excludes_new_services(mock_redis, mock_es):
    # Regression: 'auto' with no port must stay scoped to exactly Redis +
    # Elasticsearch, never silently expanding to probe all nine services.
    mock_redis.return_value = RedisResult(host="10.0.0.5", port=6379, connected=False, status="refused")
    mock_es.return_value = ElasticsearchResult(host="10.0.0.5", port=9200, status="error")

    out = execute("10.0.0.5", service="auto")
    assert out.vault is None
    assert out.consul is None
    assert out.prometheus is None
    assert out.grafana is None
    assert out.kibana is None
    assert out.couchdb is None
    assert out.memcached is None
    assert out.mongodb is None


# ---------------------------------------------------------------- parse()


def test_parse_omits_full_index_list_and_redis_when_absent():
    res = UnauthDatastoreResult(
        target="10.0.0.5",
        host="10.0.0.5",
        elasticsearch=ElasticsearchResult(
            host="10.0.0.5",
            port=9200,
            status_code=200,
            vulnerable=True,
            status="vulnerable",
            cluster_name="my-cluster",
            version="8.11.0",
            index_names=["logs-2024", "users"],
            index_count=2,
        ),
        vulnerable=True,
        summary="Elasticsearch (port 9200) VULNERABLE: unauthenticated REST access",
    )
    out = parse(res)
    assert "redis" not in out
    assert out["elasticsearch"]["index_count"] == 2
    assert "index_names" not in out["elasticsearch"]
    assert out["vulnerable"] is True
    assert len(out["findings"]) == 1


def test_parse_includes_vault_consul_couchdb_memcached_when_present():
    res = UnauthDatastoreResult(
        target="10.0.0.5",
        host="10.0.0.5",
        vault=VaultResult(host="10.0.0.5", port=8200, vulnerable=True, status="vulnerable", vault_version="1.15.2", mounts_exposed=True),
        consul=ConsulResult(host="10.0.0.5", port=8500, vulnerable=False, status="auth_required", consul_version="1.17.0"),
        couchdb=CouchDbResult(host="10.0.0.5", port=5984, vulnerable=True, status="vulnerable", databases_exposed=3),
        memcached=MemcachedResult(host="10.0.0.5", port=11211, vulnerable=True, status="vulnerable", memcached_version="1.6.21"),
        vulnerable=True,
        summary="Vault VULNERABLE; Consul auth_required; CouchDB VULNERABLE; Memcached VULNERABLE",
    )
    out = parse(res)
    assert out["vault"]["mounts_exposed"] is True
    assert out["consul"]["vulnerable"] is False
    assert out["couchdb"]["databases_exposed"] == 3
    assert out["memcached"]["memcached_version"] == "1.6.21"
    assert "prometheus" not in out
    assert "grafana" not in out
    assert "kibana" not in out
    # Vault, CouchDB, and Memcached are each vulnerable; Consul is not.
    assert len(out["findings"]) == 3


def test_parse_includes_mongodb_when_present():
    res = UnauthDatastoreResult(
        target="10.0.0.5",
        host="10.0.0.5",
        mongodb=MongoResult(
            host="10.0.0.5", port=27017, connected=True, vulnerable=True, status="vulnerable",
            mongodb_version="7.0.5", databases_exposed=3,
        ),
        vulnerable=True,
        summary="MongoDB VULNERABLE: unauthenticated listDatabases access",
    )
    out = parse(res)
    assert out["mongodb"]["databases_exposed"] == 3
    assert out["mongodb"]["vulnerable"] is True
    assert len(out["findings"]) == 1
