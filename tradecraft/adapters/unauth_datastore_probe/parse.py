"""
Parsing logic for unauthenticated datastore/service probe results.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.unauth_datastore_probe.execute import UnauthDatastoreResult


def parse(result: UnauthDatastoreResult) -> Dict[str, Any]:
    """Formats UnauthDatastoreResult into dictionary suitable for model context
    and evidence persistence. Full detail lists (Elasticsearch index names,
    etc.) are intentionally omitted here -- only counts are exposed to the
    model; the tool layer's _full_evidence carries the complete lists."""
    output: Dict[str, Any] = {
        "target": result.target,
        "host": result.host,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
        "error": result.error,
    }

    findings: List[str] = []

    if result.redis is not None:
        output["redis"] = {
            "port": result.redis.port,
            "connected": result.redis.connected,
            "unauthenticated_access": result.redis.unauthenticated_access,
            "vulnerable": result.redis.vulnerable,
            "status": result.redis.status,
            "redis_version": result.redis.redis_version,
            "os_info": result.redis.os_info,
            "error": result.redis.error,
        }
        if result.redis.vulnerable:
            findings.append(f"Unauthenticated Redis command access on {result.host}:{result.redis.port}")

    if result.elasticsearch is not None:
        output["elasticsearch"] = {
            "port": result.elasticsearch.port,
            "status_code": result.elasticsearch.status_code,
            "unauthenticated_access": result.elasticsearch.unauthenticated_access,
            "vulnerable": result.elasticsearch.vulnerable,
            "status": result.elasticsearch.status,
            "cluster_name": result.elasticsearch.cluster_name,
            "version": result.elasticsearch.version,
            "index_count": result.elasticsearch.index_count,
            "sample_documents_count": len(result.elasticsearch.sample_documents),
            "error": result.elasticsearch.error,
        }
        if result.elasticsearch.vulnerable:
            findings.append(f"Unauthenticated Elasticsearch REST access on {result.host}:{result.elasticsearch.port}")
            if result.elasticsearch.sample_documents:
                findings.append(
                    f"Retrieved {len(result.elasticsearch.sample_documents)} real document(s) from "
                    f"index '{result.elasticsearch.sample_index}' with no credential"
                )

    if result.vault is not None:
        output["vault"] = {
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
        if result.vault.vulnerable:
            findings.append(f"Unauthenticated Vault secrets-engine mount table access on {result.host}:{result.vault.port}")

    if result.consul is not None:
        output["consul"] = {
            "port": result.consul.port,
            "connected": result.consul.connected,
            "unauthenticated_access": result.consul.unauthenticated_access,
            "vulnerable": result.consul.vulnerable,
            "status": result.consul.status,
            "consul_version": result.consul.consul_version,
            "kv_keys_exposed": result.consul.kv_keys_exposed,
            "error": result.consul.error,
        }
        if result.consul.vulnerable:
            findings.append(f"Unauthenticated Consul KV store access on {result.host}:{result.consul.port}")

    if result.prometheus is not None:
        output["prometheus"] = {
            "port": result.prometheus.port,
            "connected": result.prometheus.connected,
            "unauthenticated_access": result.prometheus.unauthenticated_access,
            "vulnerable": result.prometheus.vulnerable,
            "status": result.prometheus.status,
            "prometheus_version": result.prometheus.prometheus_version,
            "targets_exposed": result.prometheus.targets_exposed,
            "error": result.prometheus.error,
        }
        if result.prometheus.vulnerable:
            findings.append(f"Unauthenticated Prometheus scrape-target inventory access on {result.host}:{result.prometheus.port}")

    if result.grafana is not None:
        output["grafana"] = {
            "port": result.grafana.port,
            "connected": result.grafana.connected,
            "unauthenticated_access": result.grafana.unauthenticated_access,
            "vulnerable": result.grafana.vulnerable,
            "status": result.grafana.status,
            "grafana_version": result.grafana.grafana_version,
            "datasources_exposed": result.grafana.datasources_exposed,
            "error": result.grafana.error,
        }
        if result.grafana.vulnerable:
            findings.append(f"Unauthenticated Grafana datasource listing access on {result.host}:{result.grafana.port}")

    if result.kibana is not None:
        output["kibana"] = {
            "port": result.kibana.port,
            "connected": result.kibana.connected,
            "unauthenticated_access": result.kibana.unauthenticated_access,
            "vulnerable": result.kibana.vulnerable,
            "status": result.kibana.status,
            "kibana_version": result.kibana.kibana_version,
            "saved_objects_exposed": result.kibana.saved_objects_exposed,
            "error": result.kibana.error,
        }
        if result.kibana.vulnerable:
            findings.append(f"Unauthenticated Kibana saved-object access on {result.host}:{result.kibana.port}")

    if result.couchdb is not None:
        output["couchdb"] = {
            "port": result.couchdb.port,
            "connected": result.couchdb.connected,
            "unauthenticated_access": result.couchdb.unauthenticated_access,
            "vulnerable": result.couchdb.vulnerable,
            "status": result.couchdb.status,
            "couchdb_version": result.couchdb.couchdb_version,
            "databases_exposed": result.couchdb.databases_exposed,
            "error": result.couchdb.error,
        }
        if result.couchdb.vulnerable:
            findings.append(f"Unauthenticated CouchDB database listing access on {result.host}:{result.couchdb.port}")

    if result.memcached is not None:
        output["memcached"] = {
            "port": result.memcached.port,
            "connected": result.memcached.connected,
            "unauthenticated_access": result.memcached.unauthenticated_access,
            "vulnerable": result.memcached.vulnerable,
            "status": result.memcached.status,
            "memcached_version": result.memcached.memcached_version,
            "error": result.memcached.error,
        }
        if result.memcached.vulnerable:
            findings.append(f"Unauthenticated Memcached command access on {result.host}:{result.memcached.port}")

    if result.mongodb is not None:
        output["mongodb"] = {
            "port": result.mongodb.port,
            "connected": result.mongodb.connected,
            "unauthenticated_access": result.mongodb.unauthenticated_access,
            "vulnerable": result.mongodb.vulnerable,
            "status": result.mongodb.status,
            "mongodb_version": result.mongodb.mongodb_version,
            "databases_exposed": result.mongodb.databases_exposed,
            "sample_documents_count": len(result.mongodb.sample_documents),
            "error": result.mongodb.error,
        }
        if result.mongodb.vulnerable:
            findings.append(f"Unauthenticated MongoDB listDatabases access on {result.host}:{result.mongodb.port}")
            if result.mongodb.sample_documents:
                findings.append(
                    f"Retrieved {len(result.mongodb.sample_documents)} real document(s) from "
                    f"'{result.mongodb.sample_database}.{result.mongodb.sample_collection}' with no credential"
                )

    output["findings"] = findings
    return output
