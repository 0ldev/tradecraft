"""
Raw execution: derives the company keyword and runs cloud_enum against it.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

_MULTI_LABEL_PUBLIC_SUFFIXES = {
    # country-code second-level domains (ccSLD) used by .br
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    # other common ccSLD patterns
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "co.za", "org.za", "com.au",
    "com.ar", "com.mx", "com.co", "co.in", "org.in", "gen.in", "ac.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.tr", "com.ua", "com.pl", "com.my", "com.sg",
    "co.il", "org.il", "com.hk", "com.tw", "com.ph", "com.vn", "com.th",
    "co.nz", "net.nz", "org.nz", "com.eg", "com.sa", "com.ae", "com.pk",
    "com.bd", "com.ng", "com.ke", "com.gh",
}


@dataclass
class RawCloudEnumResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target: str = ""
    keyword: str = ""
    json_content: str = ""
    error: Optional[str] = None


def registrable_domain(hostname: str) -> Optional[str]:
    """
    Return the registrable (effective second-level) domain for a hostname.
    E.g. www.examplepaint.com.br -> examplepaint.com.br
         api.example.com -> example.com
    """
    host = hostname.strip().lower()
    if ":" in host:
        host = host.split(":", 1)[0]

    labels = host.split(".")
    if len(labels) < 2:
        return None

    for i in range(1, len(labels)):
        candidate_suffix = ".".join(labels[i:])
        if candidate_suffix in _MULTI_LABEL_PUBLIC_SUFFIXES:
            return ".".join(labels[i - 1:])
        if len(candidate_suffix.split(".")) == 1:
            break

    # Simple TLD case: last two labels
    return ".".join(labels[-2:])


def derive_keyword(target: str) -> str:
    """
    Extract the organization keyword from a target domain, URL, or string.
    Ensures that every subdomain of the same target (e.g. 'www.company.com.br',
    'mail.company.com.br') derives the identical company keyword ('company').
    """
    cleaned = target.strip().lower()
    if not cleaned:
        return ""

    if "://" in cleaned:
        parsed = urllib.parse.urlsplit(cleaned)
        cleaned = parsed.hostname or cleaned

    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]

    if "." in cleaned:
        root = registrable_domain(cleaned) or cleaned
        keyword = root.split(".")[0] if "." in root else root
    else:
        keyword = cleaned

    # Sanitize: letters, numbers, and hyphens only
    keyword = re.sub(r"[^a-z0-9\-]", "", keyword).strip("-")
    return keyword


def build_argv(
    keyword: str,
    quickscan: bool = True,
    disable_aws: bool = False,
    disable_azure: bool = False,
    disable_gcp: bool = False,
    threads: int = 5,
    output_file: str = "",
) -> List[str]:
    argv = ["cloud_enum", "-k", keyword, "-f", "json"]
    if output_file:
        argv.extend(["-l", output_file])
    if quickscan:
        argv.append("-qs")
    if disable_aws:
        argv.append("--disable-aws")
    if disable_azure:
        argv.append("--disable-azure")
    if disable_gcp:
        argv.append("--disable-gcp")
    if threads and threads != 5:
        argv.extend(["-t", str(max(1, threads))])
    return argv


def execute(
    target: str,
    quickscan: bool = True,
    disable_aws: bool = False,
    disable_azure: bool = False,
    disable_gcp: bool = False,
    threads: int = 5,
    subprocess_timeout: int = 60,
) -> RawCloudEnumResult:
    keyword = derive_keyword(target)
    if not keyword:
        return RawCloudEnumResult(
            target=target,
            error=f"Cannot derive a valid company keyword from target '{target}'",
        )

    binary = shutil.which("cloud_enum")
    if not binary:
        return RawCloudEnumResult(
            target=target,
            keyword=keyword,
            error="cloud_enum binary not found on PATH. Install cloud_enum to enable cloud enumeration.",
        )

    tmp_dir = tempfile.mkdtemp(prefix="cloudenum_")
    out_file = os.path.join(tmp_dir, "output.json")
    try:
        argv = build_argv(
            keyword=keyword,
            quickscan=quickscan,
            disable_aws=disable_aws,
            disable_azure=disable_azure,
            disable_gcp=disable_gcp,
            threads=threads,
            output_file=out_file,
        )

        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=subprocess_timeout,
        )

        json_content = ""
        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    json_content = f.read()
            except OSError:
                pass

        return RawCloudEnumResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target=target,
            keyword=keyword,
            json_content=json_content,
        )
    except subprocess.TimeoutExpired:
        return RawCloudEnumResult(
            target=target,
            keyword=keyword,
            error=f"cloud_enum execution timed out after {subprocess_timeout}s against keyword '{keyword}'",
        )
    except Exception as e:
        return RawCloudEnumResult(
            target=target,
            keyword=keyword,
            error=f"cloud_enum execution failed: {str(e)}",
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
