"""
Unit tests for the bucket_permission_probe adapter, parser, Tool wrapper,
and contract. requests is mocked; fixture bodies are modeled on the real
documented shapes of the AWS S3 ListObjectsV2 / AccessDenied / NoSuchBucket
XML, the GCS JSON objects.list / error envelopes, and the Azure Blob
EnumerationResults / ContainerNotFound XML.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.bucket_permission_probe import execute as bpp_execute
from tradecraft.adapters.bucket_permission_probe import parse as bpp_parse
from tradecraft.adapters.bucket_permission_probe.execute import (
    DEFAULT_AZURE_CONTAINERS,
    USER_AGENT,
    normalize_bucket_candidate,
)
from tradecraft.tools.bucket_permission_probe import BucketPermissionProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS

AWS_LIST_OK = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>examplecorp-backups</Name>
  <Prefix></Prefix>
  <KeyCount>1</KeyCount>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>db-dump-2024-01-01.sql.gz</Key>
    <Size>10422</Size>
  </Contents>
</ListBucketResult>"""

AWS_ACCESS_DENIED = """<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>4442587FB7D0A2F9</RequestId><HostId>bPxRfSMKX</HostId></Error>"""

AWS_NO_SUCH_BUCKET = """<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>examplecorp-nope</BucketName><RequestId>4442587FB7D0A2F9</RequestId><HostId>bPxRfSMKX</HostId></Error>"""

GCP_LIST_OK = """{
  "kind": "storage#objects",
  "items": [
    {"kind": "storage#object", "name": "exports/users.csv", "bucket": "examplecorp-prod", "size": "2048"}
  ]
}"""

GCP_FORBIDDEN = """{
  "error": {
    "code": 403,
    "message": "examplecorp-private does not have storage.objects.list access to the Google Cloud Storage bucket.",
    "errors": [{"message": "examplecorp-private does not have storage.objects.list access", "domain": "global", "reason": "forbidden"}],
    "status": "PERMISSION_DENIED"
  }
}"""

GCP_NOT_FOUND = """{
  "error": {
    "code": 404,
    "message": "The specified bucket does not exist.",
    "errors": [{"message": "The specified bucket does not exist.", "domain": "global", "reason": "notFound"}]
  }
}"""

AZURE_LIST_OK = """﻿<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://examplecorpstorage.blob.core.windows.net/" ContainerName="backup"><MaxResults>5</MaxResults><Containers /><NextMarker /></EnumerationResults>"""

AZURE_CONTAINER_NOT_FOUND = """﻿<?xml version="1.0" encoding="utf-8"?><Error><Code>ContainerNotFound</Code><Message>The specified container does not exist.
RequestId:0a1b2c3d-0001-0000-1234-567890abcdef
Time:2026-11-05T12:00:00.0000000Z</Message></Error>"""

AZURE_PRIVATE = """﻿<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthenticationFailed</Code><Message>Server failed to authenticate the request. Make sure the value of Authorization header is formed correctly including the signature.
RequestId:0a1b2c3d-0002-0000-1234-567890abcdef</Message></Error>"""


def _resp(status: int, text: str = ""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


# --- normalization -----------------------------------------------------------

def test_normalize_strips_known_suffixes():
    assert normalize_bucket_candidate("aws", "examplecorp-backups.s3.amazonaws.com") == "examplecorp-backups"
    assert normalize_bucket_candidate("aws", "examplecorp-backups.s3.eu-west-1.amazonaws.com") == "examplecorp-backups"
    assert normalize_bucket_candidate("aws", "examplecorp-backups.s3-us-west-2.amazonaws.com") == "examplecorp-backups"
    assert normalize_bucket_candidate("gcp", "examplecorp-prod.storage.googleapis.com") == "examplecorp-prod"
    assert normalize_bucket_candidate("azure", "examplecorpstorage.blob.core.windows.net") == "examplecorpstorage"
    assert normalize_bucket_candidate("aws", "  plain-name  ") == "plain-name"


# --- AWS ---------------------------------------------------------------------

def test_aws_urls_headers_and_classification():
    responses = {
        "examplecorp-backups": _resp(200, AWS_LIST_OK),
        "examplecorp-private": _resp(403, AWS_ACCESS_DENIED),
        "examplecorp-nope": _resp(404, AWS_NO_SUCH_BUCKET),
    }

    def fake_get(url, **kwargs):
        host = url.split("//", 1)[1].split(".s3.", 1)[0]
        return responses[host]

    with patch.object(bpp_execute.requests, "get", side_effect=fake_get) as get:
        raw = bpp_execute.execute("aws", "examplecorp-backups,examplecorp-private,examplecorp-nope", timeout=7)

    urls = [c.args[0] for c in get.call_args_list]
    assert urls == [
        "https://examplecorp-backups.s3.amazonaws.com/?list-type=2&max-keys=5",
        "https://examplecorp-private.s3.amazonaws.com/?list-type=2&max-keys=5",
        "https://examplecorp-nope.s3.amazonaws.com/?list-type=2&max-keys=5",
    ]
    for c in get.call_args_list:
        assert c.kwargs["timeout"] == 7
        assert c.kwargs["verify"] is False
        assert c.kwargs["headers"] == {"User-Agent": USER_AGENT}

    by = {c.candidate: c for c in raw.checks}
    assert (by["examplecorp-backups"].exists, by["examplecorp-backups"].publicly_listable) == (True, True)
    assert (by["examplecorp-private"].exists, by["examplecorp-private"].publicly_listable) == (True, False)
    assert (by["examplecorp-nope"].exists, by["examplecorp-nope"].publicly_listable) == (False, False)


def test_aws_unexpected_status_and_request_exception_are_per_check_errors():
    def fake_get(url, **kwargs):
        if "boom" in url:
            raise requests.ConnectionError("connection reset")
        return _resp(500, "")

    with patch.object(bpp_execute.requests, "get", side_effect=fake_get):
        raw = bpp_execute.execute("aws", "boom-bucket,weird-bucket")

    assert raw.error is None
    assert len(raw.checks) == 2
    assert "connection reset" in raw.checks[0].error
    assert raw.checks[1].error == "unexpected HTTP 500"
    assert raw.checks[1].publicly_listable is None


# --- GCP ---------------------------------------------------------------------

def test_gcp_urls_and_classification():
    responses = {
        "examplecorp-prod": _resp(200, GCP_LIST_OK),
        "examplecorp-private": _resp(403, GCP_FORBIDDEN),
        "examplecorp-nope": _resp(404, GCP_NOT_FOUND),
    }

    def fake_get(url, **kwargs):
        return responses[url.rsplit("/b/", 1)[1].split("/o?", 1)[0]]

    with patch.object(bpp_execute.requests, "get", side_effect=fake_get) as get:
        raw = bpp_execute.execute("gcp", "examplecorp-prod.storage.googleapis.com,examplecorp-private,examplecorp-nope")

    assert [c.args[0] for c in get.call_args_list] == [
        "https://storage.googleapis.com/storage/v1/b/examplecorp-prod/o?maxResults=5",
        "https://storage.googleapis.com/storage/v1/b/examplecorp-private/o?maxResults=5",
        "https://storage.googleapis.com/storage/v1/b/examplecorp-nope/o?maxResults=5",
    ]
    by = {c.candidate: c for c in raw.checks}
    assert (by["examplecorp-prod"].exists, by["examplecorp-prod"].publicly_listable) == (True, True)
    assert (by["examplecorp-private"].exists, by["examplecorp-private"].publicly_listable) == (True, False)
    assert (by["examplecorp-nope"].exists, by["examplecorp-nope"].publicly_listable) == (False, False)


def test_gcp_200_with_non_json_body_is_an_error_not_public():
    with patch.object(bpp_execute.requests, "get", return_value=_resp(200, "<html>captive portal</html>")):
        raw = bpp_execute.execute("gcp", "examplecorp-prod")
    assert raw.checks[0].publicly_listable is None
    assert raw.checks[0].error == "HTTP 200 with a non-JSON body"


# --- Azure -------------------------------------------------------------------

def test_azure_default_containers_and_urls():
    def fake_get(url, **kwargs):
        if "/backup?" in url and url.startswith("https://examplecorpstorage."):
            return _resp(200, AZURE_LIST_OK)
        return _resp(404, AZURE_CONTAINER_NOT_FOUND)

    with patch.object(bpp_execute.requests, "get", side_effect=fake_get) as get:
        raw = bpp_execute.execute("azure", "examplecorpstorage")

    assert len(raw.checks) == len(DEFAULT_AZURE_CONTAINERS) == 10
    assert get.call_args_list[0].args[0] == (
        "https://examplecorpstorage.blob.core.windows.net/data"
        "?restype=container&comp=list&maxresults=5"
    )
    assert get.call_args_list[-1].args[0] == (
        "https://examplecorpstorage.blob.core.windows.net/$root"
        "?restype=container&comp=list&maxresults=5"
    )
    assert raw.truncated is False
    public = [c for c in raw.checks if c.publicly_listable]
    assert [c.container for c in public] == ["backup"]
    # A container miss does not claim the account is missing.
    miss = [c for c in raw.checks if c.container == "data"][0]
    assert (miss.exists, miss.publicly_listable) == (False, False)


def test_azure_403_means_container_exists_but_not_listable():
    with patch.object(bpp_execute.requests, "get", return_value=_resp(403, AZURE_PRIVATE)):
        raw = bpp_execute.execute("azure", "examplecorpstorage", azure_containers="backup")
    assert len(raw.checks) == 1
    assert (raw.checks[0].exists, raw.checks[0].publicly_listable) == (True, False)


def test_azure_container_list_is_capped_at_ten():
    many = ",".join(f"c{i}" for i in range(15))
    with patch.object(bpp_execute.requests, "get", return_value=_resp(404, AZURE_CONTAINER_NOT_FOUND)) as get:
        raw = bpp_execute.execute("azure", "examplecorpstorage", azure_containers=many)
    assert len(raw.checks) == 10
    assert get.call_count == 10


def test_azure_candidate_by_container_product_is_capped_at_fifty():
    accounts = ",".join(f"acct{i}" for i in range(20))
    with patch.object(bpp_execute.requests, "get", return_value=_resp(404, AZURE_CONTAINER_NOT_FOUND)) as get:
        raw = bpp_execute.execute("azure", accounts)  # 20 x 10 = 200 pairs
    assert get.call_count == 50
    assert raw.truncated is True
    assert len({c.candidate for c in raw.checks}) == 5


# --- top-level errors --------------------------------------------------------

def test_top_level_errors():
    assert bpp_execute.execute("oracle", "x").error.startswith("unsupported provider")
    assert bpp_execute.execute("aws", " , ").error == "no bucket candidates given"


# --- parser ------------------------------------------------------------------

def test_parse_reports_public_aws_buckets_with_summary():
    with patch.object(bpp_execute.requests, "get", side_effect=[_resp(200, AWS_LIST_OK), _resp(403, AWS_ACCESS_DENIED)]):
        raw = bpp_execute.execute("aws", "examplecorp-backups,examplecorp-private")
    out = bpp_parse.parse_bucket_permission_result(raw)
    assert out["provider"] == "aws"
    assert out["public_buckets"] == [{"candidate": "examplecorp-backups", "status": 200}]
    assert out["all_checks_summary"] == {"total": 2, "exist": 2, "public": 1, "errored": 0}
    assert "azure_limitation" not in out


def test_parse_reason_when_nothing_public():
    with patch.object(bpp_execute.requests, "get", return_value=_resp(403, AWS_ACCESS_DENIED)):
        raw = bpp_execute.execute("aws", "examplecorp-private")
    out = bpp_parse.parse_bucket_permission_result(raw)
    assert "public_buckets" not in out
    assert out["reason"] == "no candidate is publicly listable"
    assert out["all_checks_summary"]["exist"] == 1


def test_parse_azure_includes_limitation_and_truncation_flag():
    def fake_get(url, **kwargs):
        return _resp(200, AZURE_LIST_OK) if "/backup?" in url else _resp(404, AZURE_CONTAINER_NOT_FOUND)

    with patch.object(bpp_execute.requests, "get", side_effect=fake_get):
        raw = bpp_execute.execute("azure", ",".join(f"acct{i}" for i in range(60)), azure_containers="backup")
    out = bpp_parse.parse_bucket_permission_result(raw)
    assert out["public_buckets"][0] == {"candidate": "acct0", "container": "backup", "status": 200}
    assert "azure_limitation" in out
    assert out["truncated"] is True


def test_parse_passes_error_through():
    raw = bpp_execute.RawBucketPermissionResult(provider="aws", error="no bucket candidates given")
    assert bpp_parse.parse_bucket_permission_result(raw) == {
        "provider": "aws",
        "error": "no bucket candidates given",
    }


# --- Tool wrapper + contract -------------------------------------------------

def test_tool_wrapper_end_to_end_with_mocked_requests():
    with patch.object(bpp_execute.requests, "get", return_value=_resp(200, GCP_LIST_OK)) as get:
        out = BucketPermissionProbe()(provider="gcp", buckets="examplecorp-prod")
    assert get.call_count == 1
    assert out["public_buckets"] == [{"candidate": "examplecorp-prod", "status": 200}]


def test_contract_is_non_destructive_and_in_web_and_cloud_profiles():
    tool = BucketPermissionProbe()
    assert tool.tool_id == "bucket_permission_probe"
    assert tool.destructive is False
    assert tool.scope_param == "buckets"
    assert tool.required_binary is None
    assert tool.is_available() is True
    assert tool.spec.parameters["required"] == ["provider", "buckets"]
    assert "bucket_permission_probe" in load_profile("web")
    assert "bucket_permission_probe" in load_profile("cloud")
    assert any(t.tool_id == "bucket_permission_probe" for t in ALL_TOOLS)
