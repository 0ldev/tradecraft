"""
Pure parsing functions for trufflehog output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Tuple

# trufflehog reports every custom-regex-config detector (ours or anyone
# else's) with DetectorName literally equal to "CustomRegex" -- the
# detector's own `name` field (what config/trufflehog_detectors/
# aspnet_machinekey.yaml calls each one) only shows up in
# ExtraData.name. Confirmed directly against the real binary (v3.99.7),
# not assumed from docs, which (at this version) say nothing about
# DetectorName itself being generic.
_CUSTOM_REGEX_DETECTOR_TYPE = "CustomRegex"

# Maps each of our four ASPNET* custom-detector names (see
# config/trufflehog_detectors/aspnet_machinekey.yaml) to the field name
# it fills on the dedicated aspnet_machinekey result below.
_ASPNET_MACHINEKEY_FIELDS: Dict[str, str] = {
    "ASPNETValidationKey": "validation_key",
    "ASPNETDecryptionKey": "decryption_key",
    "ASPNETValidationAlgorithm": "validation_algorithm",
    "ASPNETDecryptionAlgorithm": "decryption_algorithm",
}


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    if target.startswith("/"):
        return target, 80
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0].split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _display_detector_name(item: Dict[str, Any]) -> str:
    """The real detector name for both a built-in detector (DetectorName
    itself) and a custom-regex-config detector (DetectorName is always
    the generic "CustomRegex" there; the real name is ExtraData.name).
    Falls back to the raw DetectorName if ExtraData.name is missing, so
    a malformed custom-detector entry still gets some non-empty label
    rather than disappearing."""
    detector_type = str(item.get("DetectorName", "")).strip()
    if detector_type == _CUSTOM_REGEX_DETECTOR_TYPE:
        extra_name = str(item.get("ExtraData", {}).get("name", "")).strip()
        if extra_name:
            return extra_name
    return detector_type


def _mask_raw_secret(raw: str) -> str:
    """Mask high-entropy secret string to prevent large secrets leaking into model prompts."""
    raw = raw.strip()
    if len(raw) <= 12:
        return raw[:2] + "****" + raw[-2:] if len(raw) > 4 else "****"
    return raw[:6] + "..." + raw[-4:]


def parse_trufflehog_output(stdout: str = "") -> Dict[str, Any]:
    """
    Parses trufflehog JSON findings from stdout lines.
    Lines containing DetectorName represent detected credentials.
    """
    secrets: List[Dict[str, Any]] = []
    by_detector: Dict[str, int] = {}
    verified_count = 0
    unverified_count = 0
    machinekey: Dict[str, Any] = {}

    if not stdout or not stdout.strip():
        return {
            "secrets": [],
            "total_secrets": 0,
            "verified_count": 0,
            "unverified_count": 0,
            "by_detector": {},
            "aspnet_machinekey": None,
        }

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(item, dict):
            continue

        detector_type = str(item.get("DetectorName", "")).strip()
        if not detector_type:
            continue
        detector = _display_detector_name(item)

        raw = str(item.get("Raw", "")).strip()
        file_path = str(item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""))
        line_num = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line")
        verified = bool(item.get("Verified", False))
        desc = str(item.get("DetectorDescription", "")).strip()
        decoder = str(item.get("DecoderName", "")).strip()

        if verified:
            verified_count += 1
        else:
            unverified_count += 1

        by_detector[detector] = by_detector.get(detector, 0) + 1

        secrets.append({
            "detector": detector,
            "description": desc,
            "file": file_path,
            "line": line_num,
            "verified": verified,
            "masked_secret": _mask_raw_secret(raw),
            "raw_secret": raw,
            "decoder": decoder,
        })

        # Surface a leaked ASP.NET machineKey as a dedicated, unmasked,
        # directly-consumable structure (same "don't hide an actionable
        # credential behind generic masking" precedent auth_bootstrap's
        # session_token and jwt_analyze's forged_token already follow) --
        # on top of the normal masked entry in `secrets` above, not
        # instead of it.
        if detector in _ASPNET_MACHINEKEY_FIELDS and raw:
            machinekey[_ASPNET_MACHINEKEY_FIELDS[detector]] = raw
            machinekey.setdefault("file", file_path)

    return {
        "secrets": secrets,
        "total_secrets": len(secrets),
        "verified_count": verified_count,
        "unverified_count": unverified_count,
        "by_detector": by_detector,
        "aspnet_machinekey": machinekey or None,
    }
