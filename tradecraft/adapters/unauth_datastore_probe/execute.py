"""
Execution logic for unauthenticated access probing across Redis,
Elasticsearch, HashiCorp Vault, Consul, Prometheus, Grafana, Kibana,
CouchDB, and Memcached. Every prober is single-attempt and non-destructive:
Redis/Memcached send one plaintext command each (neither protocol has a
partial-auth state, so one successful command proves full unauthenticated
access); the HTTP-based probers (Elasticsearch, Vault, Consul, Prometheus,
Grafana, Kibana, CouchDB) each fingerprint the service with one GET, then
attempt exactly one GET to an endpoint that normally requires a credential
-- a 200 there, instead of the expected 401/403, is the vulnerability
signal. Mirrors tradecraft/adapters/anon_service_probe/execute.py's exact
shape and status-string convention.

'auto' (no explicit service) keeps its original meaning: Redis +
Elasticsearch only, on their standard ports. The newer services are
deliberately NOT folded into 'auto' -- probing all nine by default would
silently add real network latency/noise to the tool's cheapest, most
common call shape. Each new service is reached by naming it explicitly in
`service`, or via 'auto' + an explicit `port` that matches one of the
known default ports below.
"""
from __future__ import annotations

import socket
import struct
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

# Bounded, fixed sample size for the data-exfiltration completion step
# on MongoDB/Elasticsearch -- enough to prove real customer data is
# exposed (not just metadata), never an open-ended dump.
SAMPLE_DOCUMENT_LIMIT = 3


def normalize_host(target: str) -> str:
    """Extracts a clean hostname or IP address from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or raw
        return host.strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            return raw[1 : raw.index("]")]
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip()
    return raw.strip()


@dataclass
class RedisResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "timeout", "refused", "error", "unexpected_response"
    redis_version: str = ""
    os_info: str = ""
    server_response: str = ""
    error: Optional[str] = None


@dataclass
class ElasticsearchResult:
    host: str
    port: int
    status_code: Optional[int] = None
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    cluster_name: str = ""
    version: str = ""
    index_names: List[str] = field(default_factory=list)
    index_count: int = 0
    # Best-effort only: a failure here never changes vulnerable/status
    # above, which are already fully proven by index listing alone.
    sample_index: str = ""
    sample_documents: List[Dict] = field(default_factory=list)
    sample_error: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VaultResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    vault_version: str = ""
    sealed: Optional[bool] = None
    mounts_exposed: bool = False
    error: Optional[str] = None


@dataclass
class ConsulResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    consul_version: str = ""
    kv_keys_exposed: int = 0
    error: Optional[str] = None


@dataclass
class PrometheusResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    prometheus_version: str = ""
    targets_exposed: int = 0
    error: Optional[str] = None


@dataclass
class GrafanaResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    grafana_version: str = ""
    datasources_exposed: int = 0
    error: Optional[str] = None


@dataclass
class KibanaResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    kibana_version: str = ""
    saved_objects_exposed: int = 0
    error: Optional[str] = None


@dataclass
class CouchDbResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "error", "unexpected_response"
    couchdb_version: str = ""
    databases_exposed: int = 0
    error: Optional[str] = None


@dataclass
class MemcachedResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "timeout", "refused", "error", "unexpected_response"
    memcached_version: str = ""
    server_response: str = ""
    error: Optional[str] = None


@dataclass
class MongoResult:
    host: str
    port: int
    connected: bool = False
    unauthenticated_access: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "auth_required", "timeout", "refused", "error", "unexpected_response"
    mongodb_version: str = ""
    max_wire_version: Optional[int] = None
    databases_exposed: int = 0
    database_names: List[str] = field(default_factory=list)
    server_response: str = ""
    # Best-effort only: a failure here never changes vulnerable/status
    # above, which are already fully proven by listDatabases alone.
    sample_database: str = ""
    sample_collection: str = ""
    sample_documents: List[Dict] = field(default_factory=list)
    sample_error: Optional[str] = None
    error: Optional[str] = None


@dataclass
class UnauthDatastoreResult:
    target: str
    host: str
    redis: Optional[RedisResult] = None
    elasticsearch: Optional[ElasticsearchResult] = None
    vault: Optional[VaultResult] = None
    consul: Optional[ConsulResult] = None
    prometheus: Optional[PrometheusResult] = None
    grafana: Optional[GrafanaResult] = None
    kibana: Optional[KibanaResult] = None
    couchdb: Optional[CouchDbResult] = None
    memcached: Optional[MemcachedResult] = None
    mongodb: Optional[MongoResult] = None
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def probe_redis(host: str, port: int = 6379, timeout: float = 5.0) -> RedisResult:
    res = RedisResult(host=host, port=port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        res.connected = True
        s.sendall(b"PING\r\n")
        resp = s.recv(256).decode("latin-1", errors="replace").strip()
        if resp.startswith("+PONG"):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            # INFO is detail only; PING succeeding already proves full
            # command access since Redis has no partial-auth state.
            try:
                s.sendall(b"INFO server\r\n")
                info_resp = s.recv(4096).decode("latin-1", errors="replace")
                for line in info_resp.splitlines():
                    if line.startswith("redis_version:"):
                        res.redis_version = line.split(":", 1)[1].strip()
                    elif line.startswith("os:"):
                        res.os_info = line.split(":", 1)[1].strip()
            except Exception:
                pass
        elif resp.startswith("-NOAUTH") or "NOAUTH" in resp:
            res.unauthenticated_access = False
            res.status = "auth_required"
            res.server_response = resp
        else:
            res.status = "unexpected_response"
            res.server_response = resp
    except ConnectionRefusedError:
        res.status = "refused"
        res.error = "Connection refused on Redis port"
    except (socket.timeout, TimeoutError):
        res.status = "timeout"
        res.error = f"Redis probe timed out after {timeout:.1f}s"
    except Exception as exc:
        res.status = "error"
        res.error = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return res


def probe_elasticsearch(host: str, port: int = 9200, timeout: float = 5.0) -> ElasticsearchResult:
    res = ElasticsearchResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        resp = requests.get(f"http://{host}:{port}/", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    res.status_code = resp.status_code
    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            res.status = "unexpected_response"
            return res
        res.unauthenticated_access = True
        res.vulnerable = True
        res.status = "vulnerable"
        res.cluster_name = data.get("cluster_name", "")
        res.version = (data.get("version") or {}).get("number", "")
        try:
            idx_resp = requests.get(
                f"http://{host}:{port}/_cat/indices",
                params={"v": "true", "format": "json"},
                timeout=timeout,
            )
            if idx_resp.status_code == 200:
                indices = idx_resp.json()
                if isinstance(indices, list):
                    res.index_names = [i.get("index", "") for i in indices[:25]]
                    res.index_count = len(indices)
        except (requests.RequestException, ValueError):
            pass

        # Completion step: index listing already proved anonymous access;
        # a real sample of document content is what turns "exposed" into
        # "confirmed data breach" for a report. Same unauthenticated GET
        # that already worked above, just against _search instead of
        # _cat/indices -- no new privilege, no write, same risk tier.
        if res.index_names:
            res.sample_index = res.index_names[0]
            try:
                search_resp = requests.get(
                    f"http://{host}:{port}/{res.sample_index}/_search",
                    params={"size": SAMPLE_DOCUMENT_LIMIT},
                    timeout=timeout,
                )
                if search_resp.status_code == 200:
                    search_data = search_resp.json()
                    hits = ((search_data.get("hits") or {}).get("hits")) or []
                    res.sample_documents = [
                        h.get("_source", {}) for h in hits[:SAMPLE_DOCUMENT_LIMIT] if isinstance(h, dict)
                    ]
                else:
                    res.sample_error = f"_search returned HTTP {search_resp.status_code}"
            except (requests.RequestException, ValueError) as exc:
                res.sample_error = str(exc)
    elif resp.status_code == 401:
        res.unauthenticated_access = False
        res.status = "auth_required"
    else:
        res.status = "unexpected_response"
    return res


def probe_vault(host: str, port: int = 8200, timeout: float = 5.0) -> VaultResult:
    res = VaultResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    # /v1/sys/health is unauthenticated by Vault's own design (so monitoring
    # tools can poll it) -- it returns various status codes depending on
    # seal/standby state (200/429/472/473/501/503), not just 200. Reaching
    # it at all, with a real "version" field in the body, is fingerprint
    # only -- not itself a finding.
    try:
        health = requests.get(f"http://{host}:{port}/v1/sys/health", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    try:
        data = health.json()
    except ValueError:
        res.status = "unexpected_response"
        return res
    if "version" not in data:
        res.status = "unexpected_response"
        return res
    res.connected = True
    res.vault_version = data.get("version", "")
    res.sealed = data.get("sealed")
    # /v1/sys/mounts normally requires a valid token; a 200 here means
    # anonymous access to the full secrets-engine mount table.
    try:
        mounts = requests.get(f"http://{host}:{port}/v1/sys/mounts", timeout=timeout)
        if mounts.status_code == 200:
            res.mounts_exposed = True
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
        elif mounts.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_consul(host: str, port: int = 8500, timeout: float = 5.0) -> ConsulResult:
    res = ConsulResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        agent = requests.get(f"http://{host}:{port}/v1/agent/self", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    if agent.status_code == 200:
        res.connected = True
        try:
            data = agent.json()
            res.consul_version = (data.get("Config") or {}).get("Version", "")
        except ValueError:
            pass
    elif agent.status_code in (401, 403):
        res.connected = True
        res.status = "auth_required"
        return res
    else:
        res.status = "unexpected_response"
        return res
    # /v1/kv/?recurse=true dumps the entire KV store -- a direct secrets
    # leak when ACLs are disabled or default-allow. Only an explicit 200
    # with real data counts as vulnerable; 404 (no keys under this prefix)
    # is genuinely ambiguous under some ACL configurations, so it is
    # reported as a weaker, non-vulnerable status rather than guessed at.
    try:
        kv = requests.get(f"http://{host}:{port}/v1/kv/", params={"recurse": "true"}, timeout=timeout)
        if kv.status_code == 200:
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            try:
                entries = kv.json()
                if isinstance(entries, list):
                    res.kv_keys_exposed = len(entries)
            except ValueError:
                pass
        elif kv.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_prometheus(host: str, port: int = 9090, timeout: float = 5.0) -> PrometheusResult:
    res = PrometheusResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        build = requests.get(f"http://{host}:{port}/api/v1/status/buildinfo", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    if build.status_code != 200:
        res.status = "auth_required" if build.status_code in (401, 403) else "unexpected_response"
        return res
    res.connected = True
    try:
        data = build.json()
        res.prometheus_version = (data.get("data") or {}).get("version", "")
    except ValueError:
        pass
    # /api/v1/targets (the scrape-target inventory -- internal service
    # topology) succeeding alongside buildinfo confirms the whole HTTP API
    # is open, not just a health/build endpoint.
    try:
        targets = requests.get(f"http://{host}:{port}/api/v1/targets", timeout=timeout)
        if targets.status_code == 200:
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            try:
                data = targets.json()
                active = (data.get("data") or {}).get("activeTargets") or []
                res.targets_exposed = len(active)
            except ValueError:
                pass
        elif targets.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_grafana(host: str, port: int = 3000, timeout: float = 5.0) -> GrafanaResult:
    res = GrafanaResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        health = requests.get(f"http://{host}:{port}/api/health", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    if health.status_code != 200:
        res.status = "unexpected_response"
        return res
    res.connected = True
    try:
        data = health.json()
        res.grafana_version = data.get("version", "")
    except ValueError:
        pass
    # /api/datasources normally requires an authenticated session; a 200
    # here means anonymous access is enabled org-wide. Grafana itself
    # redacts secret fields in this response, but connection URLs,
    # usernames, and datasource types are still a real recon leak.
    try:
        ds = requests.get(f"http://{host}:{port}/api/datasources", timeout=timeout)
        if ds.status_code == 200:
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            try:
                data = ds.json()
                if isinstance(data, list):
                    res.datasources_exposed = len(data)
            except ValueError:
                pass
        elif ds.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_kibana(host: str, port: int = 5601, timeout: float = 5.0) -> KibanaResult:
    res = KibanaResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        status = requests.get(f"http://{host}:{port}/api/status", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    if status.status_code != 200:
        res.status = "auth_required" if status.status_code in (401, 403) else "unexpected_response"
        return res
    res.connected = True
    try:
        data = status.json()
        res.kibana_version = (data.get("version") or {}).get("number", "")
    except ValueError:
        pass
    # /api/saved_objects/_find normally requires an authenticated session
    # once Kibana/Elasticsearch security is enabled; a 200 here means
    # anonymous access to saved dashboards/index-patterns.
    try:
        saved = requests.get(
            f"http://{host}:{port}/api/saved_objects/_find",
            params={"type": "dashboard", "per_page": 1},
            headers={"kbn-xsrf": "true"},
            timeout=timeout,
        )
        if saved.status_code == 200:
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            try:
                data = saved.json()
                res.saved_objects_exposed = data.get("total", 0)
            except ValueError:
                pass
        elif saved.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_couchdb(host: str, port: int = 5984, timeout: float = 5.0) -> CouchDbResult:
    res = CouchDbResult(host=host, port=port)
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res
    try:
        root = requests.get(f"http://{host}:{port}/", timeout=timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res
    if root.status_code != 200:
        res.status = "unexpected_response"
        return res
    try:
        data = root.json()
    except ValueError:
        res.status = "unexpected_response"
        return res
    if "couchdb" not in data:
        res.status = "unexpected_response"
        return res
    res.connected = True
    res.couchdb_version = data.get("version", "")
    # /_all_dbs lists every database on the server -- CouchDB's classic
    # "Admin Party" misconfiguration grants this (and full read/write) with
    # no auth at all.
    try:
        dbs = requests.get(f"http://{host}:{port}/_all_dbs", timeout=timeout)
        if dbs.status_code == 200:
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            try:
                data = dbs.json()
                if isinstance(data, list):
                    res.databases_exposed = len(data)
            except ValueError:
                pass
        elif dbs.status_code in (401, 403):
            res.status = "auth_required"
        else:
            res.status = "unexpected_response"
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
    return res


def probe_memcached(host: str, port: int = 11211, timeout: float = 5.0) -> MemcachedResult:
    res = MemcachedResult(host=host, port=port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        res.connected = True
        # The classic ASCII protocol has no authentication step at all --
        # any command that gets a real reply proves full unauthenticated
        # command access (get/set/delete/flush_all).
        s.sendall(b"version\r\n")
        resp = s.recv(256).decode("latin-1", errors="replace").strip()
        if resp.startswith("VERSION "):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            res.memcached_version = resp[len("VERSION "):].strip()
            res.server_response = resp
        else:
            res.status = "unexpected_response"
            res.server_response = resp
    except ConnectionRefusedError:
        res.status = "refused"
        res.error = "Connection refused on Memcached port"
    except (socket.timeout, TimeoutError):
        res.status = "timeout"
        res.error = f"Memcached probe timed out after {timeout:.1f}s"
    except Exception as exc:
        res.status = "error"
        res.error = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return res


# --- Minimal BSON + MongoDB wire protocol (OP_MSG) ---------------------
# Just enough BSON/OP_MSG to send {"hello": 1}/{"listDatabases": 1} and
# read back the reply -- no pymongo dependency, same no-new-third-party-
# dependency rule the rest of this tool follows. Only the BSON types
# these two commands' requests/replies actually use are implemented;
# anything else raises and is caught as an "unexpected_response".

_BSON_DOUBLE, _BSON_STRING, _BSON_DOCUMENT, _BSON_ARRAY = 0x01, 0x02, 0x03, 0x04
_BSON_OBJECTID, _BSON_BOOL, _BSON_DATETIME, _BSON_NULL = 0x07, 0x08, 0x09, 0x0A
_BSON_INT32, _BSON_INT64 = 0x10, 0x12

# A real hello/listDatabases reply is a few hundred bytes. Capping well
# above that still rejects a hostile/compromised peer trying to make
# _recv_exact buffer an unbounded amount of declared-but-not-yet-sent data.
_MONGO_MAX_MESSAGE_BYTES = 1_000_000


def _bson_encode_cstring(name: str) -> bytes:
    return name.encode("utf-8") + b"\x00"


def _bson_encode_document(fields: Dict) -> bytes:
    body = bytearray()
    for key, value in fields.items():
        if isinstance(value, bool):
            body += bytes([_BSON_BOOL]) + _bson_encode_cstring(key) + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += bytes([_BSON_INT32]) + _bson_encode_cstring(key) + struct.pack("<i", value)
        elif isinstance(value, str):
            encoded = value.encode("utf-8") + b"\x00"
            body += bytes([_BSON_STRING]) + _bson_encode_cstring(key) + struct.pack("<i", len(encoded)) + encoded
        elif isinstance(value, dict):
            body += bytes([_BSON_DOCUMENT]) + _bson_encode_cstring(key) + _bson_encode_document(value)
        elif isinstance(value, list):
            array_doc = {str(i): item for i, item in enumerate(value)}
            body += bytes([_BSON_ARRAY]) + _bson_encode_cstring(key) + _bson_encode_document(array_doc)
        else:
            raise ValueError(f"unsupported BSON value type for key '{key}': {type(value)}")
    doc = bytes(body) + b"\x00"
    return struct.pack("<i", len(doc) + 4) + doc


def _bson_decode_element(data: bytes, offset: int) -> "tuple[str, object, int]":
    type_byte = data[offset]
    offset += 1
    name_end = data.index(b"\x00", offset)
    name = data[offset:name_end].decode("utf-8", errors="replace")
    offset = name_end + 1

    if type_byte == _BSON_DOUBLE:
        value = struct.unpack_from("<d", data, offset)[0]
        offset += 8
    elif type_byte == _BSON_STRING:
        length = struct.unpack_from("<i", data, offset)[0]
        offset += 4
        value = data[offset : offset + length - 1].decode("utf-8", errors="replace")
        offset += length
    elif type_byte in (_BSON_DOCUMENT, _BSON_ARRAY):
        value, consumed = _bson_decode_document(data, offset)
        offset += consumed
        if type_byte == _BSON_ARRAY:
            value = [value[k] for k in sorted(value.keys(), key=lambda k: int(k))]
    elif type_byte == _BSON_BOOL:
        value = data[offset] == 1
        offset += 1
    elif type_byte == _BSON_NULL:
        value = None
    elif type_byte == _BSON_INT32:
        value = struct.unpack_from("<i", data, offset)[0]
        offset += 4
    elif type_byte == _BSON_INT64:
        value = struct.unpack_from("<q", data, offset)[0]
        offset += 8
    elif type_byte == _BSON_OBJECTID:
        value = data[offset : offset + 12].hex()
        offset += 12
    elif type_byte == _BSON_DATETIME:
        value = struct.unpack_from("<q", data, offset)[0]
        offset += 8
    else:
        raise ValueError(f"unsupported BSON type 0x{type_byte:02x} for field '{name}'")
    return name, value, offset


def _bson_decode_document(data: bytes, offset: int) -> "tuple[Dict, int]":
    total_len = struct.unpack_from("<i", data, offset)[0]
    end = offset + total_len
    cursor = offset + 4
    result: Dict = {}
    while cursor < end - 1:
        name, value, cursor = _bson_decode_element(data, cursor)
        result[name] = value
    return result, total_len


def _build_op_msg(command: Dict, request_id: int) -> bytes:
    """OP_MSG (opcode 2013): header + flagBits(0) + one kind-0 section
    (a single BSON document, no sequence sections needed for these
    admin commands)."""
    doc_bytes = _bson_encode_document(command)
    body = struct.pack("<I", 0) + b"\x00" + doc_bytes
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _mongo_send_command(sock: socket.socket, command: Dict, request_id: int) -> Optional[Dict]:
    sock.sendall(_build_op_msg(command, request_id))
    header = _recv_exact(sock, 16)
    if header is None:
        return None
    message_length, _resp_id, _response_to, op_code = struct.unpack("<iiii", header)
    # message_length is server-declared, not validated by the wire format
    # itself -- a hello/listDatabases reply is always small, so a value
    # beyond this is either a different, unsupported message or a hostile
    # peer trying to make _recv_exact buffer an unbounded amount of data.
    if op_code != 2013 or message_length < 16 or message_length - 16 > _MONGO_MAX_MESSAGE_BYTES:
        return None
    body = _recv_exact(sock, message_length - 16)
    if body is None:
        return None
    # flagBits (4 bytes) + section kind byte (1 byte) precede the document.
    try:
        doc, _ = _bson_decode_document(body, 5)
    except Exception:
        return None
    return doc


# MongoDB's own built-in databases -- never the actual target data, so
# never picked as the database to sample from.
_MONGO_SYSTEM_DATABASES = ("admin", "local", "config")


def _mongo_sample_documents(
    sock: socket.socket, database_names: List[str]
) -> "tuple[str, str, List[Dict], Optional[str]]":
    """Given a socket already past hello/listDatabases on an
    unauthenticated server, lists collections in the first non-system
    database and reads up to SAMPLE_DOCUMENT_LIMIT documents from the
    first collection. Returns (database, collection, documents, error).
    Never raises -- any failure here is reported as an error string,
    the caller's already-proven vulnerable/status fields are untouched."""
    candidates = [d for d in database_names if d not in _MONGO_SYSTEM_DATABASES]
    if not candidates:
        return "", "", [], "no non-system database to sample"
    db_name = candidates[0]

    list_coll_doc = _mongo_send_command(sock, {"listCollections": 1, "$db": db_name}, request_id=3)
    if list_coll_doc is None or list_coll_doc.get("ok") not in (1, 1.0):
        return db_name, "", [], "listCollections failed or was denied"

    cursor = list_coll_doc.get("cursor") or {}
    batch = cursor.get("firstBatch") or []
    coll_names = [
        c.get("name", "") for c in batch if isinstance(c, dict) and c.get("type") == "collection"
    ]
    if not coll_names:
        return db_name, "", [], "no collections found"
    coll_name = coll_names[0]

    find_doc = _mongo_send_command(
        sock, {"find": coll_name, "$db": db_name, "limit": SAMPLE_DOCUMENT_LIMIT}, request_id=4
    )
    if find_doc is None or find_doc.get("ok") not in (1, 1.0):
        return db_name, coll_name, [], "find failed or was denied"

    find_cursor = find_doc.get("cursor") or {}
    docs = find_cursor.get("firstBatch") or []
    docs = [d for d in docs if isinstance(d, dict)][:SAMPLE_DOCUMENT_LIMIT]
    return db_name, coll_name, docs, None


def probe_mongodb(host: str, port: int = 27017, timeout: float = 5.0) -> MongoResult:
    res = MongoResult(host=host, port=port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        res.connected = True

        # 'hello' is answered by MongoDB before authentication by design
        # (clients need it to pick a server/wire version) -- it is
        # fingerprint only, never itself the vulnerability signal.
        hello_doc = _mongo_send_command(s, {"hello": 1, "$db": "admin"}, request_id=1)
        if hello_doc is None:
            res.status = "unexpected_response"
            return res
        res.max_wire_version = hello_doc.get("maxWireVersion")

        # listDatabases is admin-only once auth is enabled -- succeeding
        # here (ok: 1) with no credentials is the real signal, and it
        # hands over every database name on the server.
        list_dbs_doc = _mongo_send_command(s, {"listDatabases": 1, "$db": "admin"}, request_id=2)
        if list_dbs_doc is None:
            res.status = "unexpected_response"
            return res

        if list_dbs_doc.get("ok") in (1, 1.0):
            res.unauthenticated_access = True
            res.vulnerable = True
            res.status = "vulnerable"
            dbs = list_dbs_doc.get("databases") or []
            if isinstance(dbs, list):
                res.databases_exposed = len(dbs)
                res.database_names = [d.get("name", "") for d in dbs if isinstance(d, dict)][:25]
            if isinstance(hello_doc.get("version"), str):
                res.mongodb_version = hello_doc["version"]

            # Completion step: listDatabases already proved anonymous
            # access; a real document sample is what turns "exposed" into
            # "confirmed data breach" for a report. Same unauthenticated
            # connection that already worked above -- no new privilege,
            # no write, same risk tier.
            try:
                res.sample_database, res.sample_collection, res.sample_documents, res.sample_error = (
                    _mongo_sample_documents(s, res.database_names)
                )
            except Exception as exc:  # noqa: BLE001 - never downgrades the finding above
                res.sample_error = str(exc)
        else:
            res.status = "auth_required"
            res.server_response = str(list_dbs_doc.get("errmsg", ""))
    except ConnectionRefusedError:
        res.status = "refused"
        res.error = "Connection refused on MongoDB port"
    except (socket.timeout, TimeoutError):
        res.status = "timeout"
        res.error = f"MongoDB probe timed out after {timeout:.1f}s"
    except Exception as exc:
        res.status = "error"
        res.error = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return res


SERVICE_DEFAULT_PORTS: Dict[str, int] = {
    "redis": 6379,
    "elasticsearch": 9200,
    "vault": 8200,
    "consul": 8500,
    "prometheus": 9090,
    "grafana": 3000,
    "kibana": 5601,
    "couchdb": 5984,
    "memcached": 11211,
    "mongodb": 27017,
}

SERVICE_LABELS = {
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "vault": "Vault",
    "consul": "Consul",
    "prometheus": "Prometheus",
    "grafana": "Grafana",
    "kibana": "Kibana",
    "couchdb": "CouchDB",
    "memcached": "Memcached",
    "mongodb": "MongoDB",
}

# 'auto' (no explicit service) keeps its original scope: these two only.
AUTO_DEFAULT_SERVICES = ("redis", "elasticsearch")


def execute(
    target: str,
    service: str = "auto",
    port: Optional[int] = None,
    timeout: int = 5,
) -> UnauthDatastoreResult:
    host = normalize_host(target)
    if not host:
        return UnauthDatastoreResult(target=target, host=host, error=f"Invalid target: '{target}'")

    effective_timeout = max(1.0, min(float(timeout), 10.0))
    svc = (service or "auto").strip().lower()

    # Built fresh on every call (not at module level) so that patching an
    # individual probe_* name -- e.g. @patch("...execute.probe_redis") --
    # is honored here. A module-level dict would capture the original
    # function objects at import time and silently bypass any such patch.
    SERVICE_PROBERS = {
        "redis": probe_redis,
        "elasticsearch": probe_elasticsearch,
        "vault": probe_vault,
        "consul": probe_consul,
        "prometheus": probe_prometheus,
        "grafana": probe_grafana,
        "kibana": probe_kibana,
        "couchdb": probe_couchdb,
        "memcached": probe_memcached,
        "mongodb": probe_mongodb,
    }

    results: Dict[str, object] = {}

    if svc in SERVICE_PROBERS:
        chosen_port = int(port) if port else SERVICE_DEFAULT_PORTS[svc]
        results[svc] = SERVICE_PROBERS[svc](host, port=chosen_port, timeout=effective_timeout)
    elif svc == "auto" and port is None:
        # Unchanged original default: Redis + Elasticsearch only.
        for name in AUTO_DEFAULT_SERVICES:
            results[name] = SERVICE_PROBERS[name](host, port=SERVICE_DEFAULT_PORTS[name], timeout=effective_timeout)
    elif svc == "auto" and port is not None:
        matched = next((n for n, p in SERVICE_DEFAULT_PORTS.items() if p == port), None)
        if matched:
            results[matched] = SERVICE_PROBERS[matched](host, port=port, timeout=effective_timeout)
        else:
            # Unrecognized port in auto mode: fall back to a Redis-protocol
            # probe on that port, matching this tool's original behavior.
            results["redis"] = probe_redis(host, port=port, timeout=effective_timeout)
    else:
        # Unrecognized service string: same fallback as above.
        chosen_port = int(port) if port else SERVICE_DEFAULT_PORTS["redis"]
        results["redis"] = probe_redis(host, port=chosen_port, timeout=effective_timeout)

    is_vuln = any(getattr(r, "vulnerable", False) for r in results.values())

    summary_parts = []
    for name, r in results.items():
        label = SERVICE_LABELS.get(name, name)
        if getattr(r, "vulnerable", False):
            summary_parts.append(f"{label} (port {r.port}) VULNERABLE: unauthenticated access")
        else:
            summary_parts.append(f"{label} (port {r.port}): {r.status}")

    return UnauthDatastoreResult(
        target=target,
        host=host,
        redis=results.get("redis"),
        elasticsearch=results.get("elasticsearch"),
        vault=results.get("vault"),
        consul=results.get("consul"),
        prometheus=results.get("prometheus"),
        grafana=results.get("grafana"),
        kibana=results.get("kibana"),
        couchdb=results.get("couchdb"),
        memcached=results.get("memcached"),
        mongodb=results.get("mongodb"),
        vulnerable=is_vuln,
        summary="; ".join(summary_parts),
    )
