"""
Raw execution: builds the git-dumper argv and runs it against a target endpoint.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawGitDumperResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    recovered_files: List[str] = field(default_factory=list)
    git_commits: List[str] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to ensure a valid HTTP/HTTPS URL scheme."""
    target = target.strip()
    if not target:
        return ""
    if not target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit("//" + target)
        if parsed.port == 80:
            target = f"http://{target}"
        else:
            target = f"https://{target}"
    return target


def find_git_dumper_binary() -> Optional[str]:
    """Finds git-dumper or gitdumper binary on PATH."""
    return shutil.which("git-dumper") or shutil.which("gitdumper")


def build_argv(
    target_url: str,
    output_dir: str,
    jobs: int = 5,
    retry: int = 2,
    binary: str = "git-dumper",
) -> List[str]:
    """Builds the git-dumper command-line invocation."""
    return [
        binary,
        "-j",
        str(max(1, jobs)),
        "-r",
        str(max(0, retry)),
        target_url,
        output_dir,
    ]


def execute(
    target: str,
    jobs: int = 5,
    retry: int = 2,
    timeout: int = 60,
) -> RawGitDumperResult:
    """Executes git-dumper against a target URL."""
    target_url = normalize_target_url(target)
    if not target_url:
        return RawGitDumperResult(error="empty target URL")

    binary = find_git_dumper_binary()
    if binary is None:
        return RawGitDumperResult(target_url=target_url, error="git-dumper binary not found on PATH")

    temp_dir = tempfile.mkdtemp(prefix="gitdumper_")

    try:
        argv = build_argv(
            target_url=target_url,
            output_dir=temp_dir,
            jobs=jobs,
            retry=retry,
            binary=binary,
        )
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        recovered_files: List[str] = []
        git_commits: List[str] = []

        git_path = os.path.join(temp_dir, ".git")
        if os.path.isdir(git_path) or proc.returncode == 0:
            for root, _, files in os.walk(temp_dir):
                # Don't list internal .git objects
                rel_root = os.path.relpath(root, temp_dir)
                if rel_root == ".git" or rel_root.startswith(".git/"):
                    continue
                for f in files:
                    rel_file = os.path.normpath(os.path.join(rel_root, f))
                    if rel_file.startswith("./"):
                        rel_file = rel_file[2:]
                    recovered_files.append(rel_file)

            # Try to read git commit log
            if os.path.isdir(git_path):
                try:
                    log_proc = subprocess.run(
                        ["git", "-C", temp_dir, "log", "-n", "5", "--pretty=format:%h - %an: %s"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if log_proc.returncode == 0 and log_proc.stdout.strip():
                        git_commits = [line.strip() for line in log_proc.stdout.splitlines() if line.strip()]
                except Exception:
                    pass

        return RawGitDumperResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
            recovered_files=recovered_files,
            git_commits=git_commits,
        )
    except subprocess.TimeoutExpired:
        return RawGitDumperResult(
            target_url=target_url,
            error=f"git-dumper timed out after {timeout}s",
        )
    except Exception as exc:
        return RawGitDumperResult(
            target_url=target_url,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
