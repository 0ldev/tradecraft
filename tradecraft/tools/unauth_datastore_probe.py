"""
Unauthenticated Service Probe tool: non-destructive verification of
unauthenticated access on Redis, Elasticsearch, HashiCorp Vault, Consul,
Prometheus, Grafana, Kibana, CouchDB, and Memcached.
Glues config/tools/unauth_datastore_probe.yaml to
tradecraft.adapters.unauth_datastore_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.unauth_datastore_probe.execute import execute as unauth_execute
from tradecraft.adapters.unauth_datastore_probe.parse import parse as unauth_parse
from tradecraft.tools.base import Tool


class UnauthDatastoreProbe(Tool):
    tool_id = "unauth_datastore_probe"

    def run(
        self,
        target: str,
        service: str = "auto",
        port: Optional[int] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        result = unauth_execute(
            target=target,
            service=service,
            port=port,
            timeout=timeout,
        )
        parsed = unauth_parse(result)

        full_evidence: Dict[str, Any] = {
            "target": target,
            "host": result.host,
            "vulnerable": result.vulnerable,
            "summary": result.summary,
            "error": result.error,
        }
        if result.redis is not None:
            full_evidence["redis"] = {
                "port": result.redis.port,
                "connected": result.redis.connected,
                "unauthenticated_access": result.redis.unauthenticated_access,
                "vulnerable": result.redis.vulnerable,
                "status": result.redis.status,
                "redis_version": result.redis.redis_version,
                "os_info": result.redis.os_info,
                "server_response": result.redis.server_response,
                "error": result.redis.error,
            }
        if result.elasticsearch is not None:
            full_evidence["elasticsearch"] = {
                "port": result.elasticsearch.port,
                "status_code": result.elasticsearch.status_code,
                "unauthenticated_access": result.elasticsearch.unauthenticated_access,
                "vulnerable": result.elasticsearch.vulnerable,
                "status": result.elasticsearch.status,
                "cluster_name": result.elasticsearch.cluster_name,
                "version": result.elasticsearch.version,
                "index_names": list(result.elasticsearch.index_names),
                "index_count": result.elasticsearch.index_count,
                "sample_index": result.elasticsearch.sample_index,
                "sample_documents": list(result.elasticsearch.sample_documents),
                "sample_error": result.elasticsearch.sample_error,
                "error": result.elasticsearch.error,
            }
        if result.vault is not None:
            full_evidence["vault"] = {
                "port": result.vault.port,
                "connected": result.vault.connected,
                "unauthenticated_access": result.vault.unauthenticated_access,
                "vulnerable": result.vault.vulnerable,
                "status": result.vault.status,
                "vault_version": result.vault.vault_version,
                "sealed": result.vault.sealed,
                "mounts_exposed": result.vault.mounts_exposed,
                "error": result.vault.error,
            }
        if result.consul is not None:
            full_evidence["consul"] = {
                "port": result.consul.port,
                "connected": result.consul.connected,
                "unauthenticated_access": result.consul.unauthenticated_access,
                "vulnerable": result.consul.vulnerable,
                "status": result.consul.status,
                "consul_version": result.consul.consul_version,
                "kv_keys_exposed": result.consul.kv_keys_exposed,
                "error": result.consul.error,
            }
        if result.prometheus is not None:
            full_evidence["prometheus"] = {
                "port": result.prometheus.port,
                "connected": result.prometheus.connected,
                "unauthenticated_access": result.prometheus.unauthenticated_access,
                "vulnerable": result.prometheus.vulnerable,
                "status": result.prometheus.status,
                "prometheus_version": result.prometheus.prometheus_version,
                "targets_exposed": result.prometheus.targets_exposed,
                "error": result.prometheus.error,
            }
        if result.grafana is not None:
            full_evidence["grafana"] = {
                "port": result.grafana.port,
                "connected": result.grafana.connected,
                "unauthenticated_access": result.grafana.unauthenticated_access,
                "vulnerable": result.grafana.vulnerable,
                "status": result.grafana.status,
                "grafana_version": result.grafana.grafana_version,
                "datasources_exposed": result.grafana.datasources_exposed,
                "error": result.grafana.error,
            }
        if result.kibana is not None:
            full_evidence["kibana"] = {
                "port": result.kibana.port,
                "connected": result.kibana.connected,
                "unauthenticated_access": result.kibana.unauthenticated_access,
                "vulnerable": result.kibana.vulnerable,
                "status": result.kibana.status,
                "kibana_version": result.kibana.kibana_version,
                "saved_objects_exposed": result.kibana.saved_objects_exposed,
                "error": result.kibana.error,
            }
        if result.couchdb is not None:
            full_evidence["couchdb"] = {
                "port": result.couchdb.port,
                "connected": result.couchdb.connected,
                "unauthenticated_access": result.couchdb.unauthenticated_access,
                "vulnerable": result.couchdb.vulnerable,
                "status": result.couchdb.status,
                "couchdb_version": result.couchdb.couchdb_version,
                "databases_exposed": result.couchdb.databases_exposed,
                "error": result.couchdb.error,
            }
        if result.memcached is not None:
            full_evidence["memcached"] = {
                "port": result.memcached.port,
                "connected": result.memcached.connected,
                "unauthenticated_access": result.memcached.unauthenticated_access,
                "vulnerable": result.memcached.vulnerable,
                "status": result.memcached.status,
                "memcached_version": result.memcached.memcached_version,
                "server_response": result.memcached.server_response,
                "error": result.memcached.error,
            }
        if result.mongodb is not None:
            full_evidence["mongodb"] = {
                "port": result.mongodb.port,
                "connected": result.mongodb.connected,
                "unauthenticated_access": result.mongodb.unauthenticated_access,
                "vulnerable": result.mongodb.vulnerable,
                "status": result.mongodb.status,
                "mongodb_version": result.mongodb.mongodb_version,
                "max_wire_version": result.mongodb.max_wire_version,
                "database_names": list(result.mongodb.database_names),
                "databases_exposed": result.mongodb.databases_exposed,
                "sample_database": result.mongodb.sample_database,
                "sample_collection": result.mongodb.sample_collection,
                "sample_documents": list(result.mongodb.sample_documents),
                "sample_error": result.mongodb.sample_error,
                "server_response": result.mongodb.server_response,
                "error": result.mongodb.error,
            }

        parsed["_full_evidence"] = full_evidence
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        host = result.get("host") or params.get("target", "")
        facts: List[Dict[str, Any]] = []

        redis_info = result.get("redis")
        if redis_info and redis_info.get("connected"):
            port = redis_info.get("port", 6379)
            fact: Dict[str, Any] = {"host": host, "port": port, "service": "redis", "state": "open"}
            if redis_info.get("redis_version"):
                fact["version"] = redis_info["redis_version"]
            if redis_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Redis Access"
                fact["severity"] = "critical"
            facts.append(fact)

        es_info = result.get("elasticsearch")
        if es_info is not None:
            port = es_info.get("port", 9200)
            fact = {"host": host, "port": port, "service": "elasticsearch", "state": "open"}
            if es_info.get("version"):
                fact["version"] = es_info["version"]
            if es_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Elasticsearch REST Access"
                fact["severity"] = "critical"
                if es_info.get("sample_documents_count"):
                    fact["sample_documents_retrieved"] = es_info["sample_documents_count"]
            facts.append(fact)

        vault_info = result.get("vault")
        if vault_info and vault_info.get("connected"):
            port = vault_info.get("port", 8200)
            fact = {"host": host, "port": port, "service": "vault", "state": "open"}
            if vault_info.get("vault_version"):
                fact["version"] = vault_info["vault_version"]
            if vault_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Vault Secrets-Engine Mount Table Access"
                fact["severity"] = "critical"
            facts.append(fact)

        consul_info = result.get("consul")
        if consul_info and consul_info.get("connected"):
            port = consul_info.get("port", 8500)
            fact = {"host": host, "port": port, "service": "consul", "state": "open"}
            if consul_info.get("consul_version"):
                fact["version"] = consul_info["consul_version"]
            if consul_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Consul KV Store Access"
                fact["severity"] = "critical"
            facts.append(fact)

        prometheus_info = result.get("prometheus")
        if prometheus_info and prometheus_info.get("connected"):
            port = prometheus_info.get("port", 9090)
            fact = {"host": host, "port": port, "service": "prometheus", "state": "open"}
            if prometheus_info.get("prometheus_version"):
                fact["version"] = prometheus_info["prometheus_version"]
            if prometheus_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Prometheus Scrape-Target Inventory Access"
                fact["severity"] = "high"
            facts.append(fact)

        grafana_info = result.get("grafana")
        if grafana_info and grafana_info.get("connected"):
            port = grafana_info.get("port", 3000)
            fact = {"host": host, "port": port, "service": "grafana", "state": "open"}
            if grafana_info.get("grafana_version"):
                fact["version"] = grafana_info["grafana_version"]
            if grafana_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Grafana Datasource Listing Access"
                fact["severity"] = "high"
            facts.append(fact)

        kibana_info = result.get("kibana")
        if kibana_info and kibana_info.get("connected"):
            port = kibana_info.get("port", 5601)
            fact = {"host": host, "port": port, "service": "kibana", "state": "open"}
            if kibana_info.get("kibana_version"):
                fact["version"] = kibana_info["kibana_version"]
            if kibana_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Kibana Saved-Object Access"
                fact["severity"] = "high"
            facts.append(fact)

        couchdb_info = result.get("couchdb")
        if couchdb_info and couchdb_info.get("connected"):
            port = couchdb_info.get("port", 5984)
            fact = {"host": host, "port": port, "service": "couchdb", "state": "open"}
            if couchdb_info.get("couchdb_version"):
                fact["version"] = couchdb_info["couchdb_version"]
            if couchdb_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated CouchDB Database Listing Access (Admin Party)"
                fact["severity"] = "critical"
            facts.append(fact)

        memcached_info = result.get("memcached")
        if memcached_info and memcached_info.get("connected"):
            port = memcached_info.get("port", 11211)
            fact = {"host": host, "port": port, "service": "memcached", "state": "open"}
            if memcached_info.get("memcached_version"):
                fact["version"] = memcached_info["memcached_version"]
            if memcached_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Memcached Command Access"
                fact["severity"] = "high"
            facts.append(fact)

        mongo_info = result.get("mongodb")
        if mongo_info and mongo_info.get("connected"):
            port = mongo_info.get("port", 27017)
            fact = {"host": host, "port": port, "service": "mongodb", "state": "open"}
            if mongo_info.get("mongodb_version"):
                fact["version"] = mongo_info["mongodb_version"]
            if mongo_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated MongoDB listDatabases Access"
                fact["severity"] = "critical"
                if mongo_info.get("sample_documents_count"):
                    fact["sample_documents_retrieved"] = mongo_info["sample_documents_count"]
            facts.append(fact)

        return facts
