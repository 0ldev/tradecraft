"""
Container verification and environment smoke tests.

These tests verify that every registered tool in Tradecraft (or a specific profile)
is properly installed, resolves its binary or scripts, and reports is_available() == True
when run inside the container environment.

When run on a development host without full pentesting tools installed,
this test suite is skipped unless TRADECRAFT_CONTAINER_TEST=1 is set.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List

import pytest

from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS, by_name

RUNNING_IN_CONTAINER = (
    os.environ.get("TRADECRAFT_CONTAINER_TEST") == "1"
    or os.path.exists("/.dockerenv")
    or os.path.exists("/run/.containerenv")
)

pytestmark = pytest.mark.skipif(
    not RUNNING_IN_CONTAINER,
    reason="Container environment test (run inside container or set TRADECRAFT_CONTAINER_TEST=1)",
)


def test_bundled_wordlists_exist():
    """Verify that all core bundled wordlists are present."""
    from tradecraft.adapters.wordlists import WORDLISTS_DIR

    assert WORDLISTS_DIR.is_dir(), f"Wordlists directory {WORDLISTS_DIR} does not exist"
    required = [
        "common.txt",
        "small.txt",
        "admin.txt",
        "api.txt",
        "vhosts.txt",
        "vhosts-small.txt",
        "vhosts-large.txt",
        "kerbrute-usernames.txt",
        "kerbrute-usernames-medium.txt",
        "kerbrute-usernames-large.txt",
        "api-routes.kite",
    ]
    for filename in required:
        path = WORDLISTS_DIR / filename
        assert path.is_file(), f"Bundled wordlist missing: {path}"


def test_web_profile_tools_available():
    """Verify every tool declared in config/profiles/web.yaml is available in the container."""
    tool_map = by_name()
    web_tool_ids = load_profile("web")
    unavailable = []

    for tool_id in web_tool_ids:
        tool = tool_map.get(tool_id)
        assert tool is not None, f"Tool {tool_id} in web profile not found in registry"
        if not tool.is_available():
            unavailable.append((tool_id, tool.required_binary))

    assert not unavailable, f"The following web profile tools report is_available() == False: {unavailable}"


def test_external_binaries_smoke():
    """Smoke test execution of key external binaries and wrappers."""
    binaries = [
        ("nmap", ["nmap", "--version"]),
        ("sqlmap", ["sqlmap", "--version"]),
        ("subfinder", ["subfinder", "-version"]),
        ("katana", ["katana", "-version"]),
        ("nuclei", ["nuclei", "-version"]),
        ("ffuf", ["ffuf", "-V"]),
        ("dalfox", ["dalfox", "version"]),
        ("gau", ["gau", "--version"]),
        ("pd-httpx", ["pd-httpx", "-version"]),
        ("testssl", ["testssl", "-v"]),
        ("whatweb", ["whatweb", "--version"]),
        ("searchsploit", ["searchsploit", "-v"]),
        ("corsy", ["corsy", "-h"]),
        ("cloudfail", ["cloudfail", "-h"]),
        ("commix", ["commix", "--version"]),
        ("hydra", ["hydra", "-h"]),
        ("cewl", ["cewl", "--help"]),
        ("cupp.py", ["cupp.py", "-h"]),
    ]

    for name, cmd in binaries:
        if shutil.which(cmd[0]) is None:
            pytest.fail(f"Binary {cmd[0]} for tool {name} is not on PATH")
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        # Verify it didn't crash with a Python SyntaxError/Traceback or missing shared lib
        stderr = proc.stderr.lower()
        assert "traceback (most recent call last)" not in stderr, f"Tool {name} threw traceback: {proc.stderr}"
        assert "syntaxerror" not in stderr, f"Tool {name} threw syntax error: {proc.stderr}"
