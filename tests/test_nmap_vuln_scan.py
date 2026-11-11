import subprocess
import xml.etree.ElementTree as ET
from unittest.mock import patch

import pytest

from tradecraft.adapters.nmap_vuln_scan import execute as nvs_execute
from tradecraft.adapters.nmap_vuln_scan import parse as nvs_parse
from tradecraft.tools.nmap_vuln_scan import NmapVulnScan

# Hand-built to match the shape real `nmap -oX -` emits: DOCTYPE header,
# <host>/<ports>/<port> with <state>, <service>, and zero or more <script>
# elements. Port 22 has no scripts; 80 has one; 445 has multiple, one
# whose output carries XML-special characters that nmap escapes in the
# attribute (&amp; / &lt;).
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -T4 --max-retries 2 -p 22,80,445 --script &quot;(vuln or safe)&quot; -oX - 10.0.0.5" start="1762300000" version="7.94SVN">
<host starttime="1762300000" endtime="1762300020">
<status state="up" reason="user-set"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" method="table" conf="3"/>
<script id="http-title" output="Welcome &amp; Login &lt;admin&gt;"/>
</port>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="microsoft-ds" method="table" conf="3"/>
<script id="smb-protocols" output="dialects:&#10;  NT LM 0.12 (SMBv1)&#10;  2.02">
<table key="dialects">
<elem>NT LM 0.12 (SMBv1)</elem>
</table>
</script>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
<script id="smb-vuln-ms10-054" output="false"/>
</port>
<port protocol="tcp" portid="3306">
<state state="closed" reason="reset" reason_ttl="64"/>
<service name="mysql" method="table" conf="3"/>
</port>
</ports>
</host>
<runstats><finished time="1762300020" elapsed="20.11"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def _fake_process(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# -- argv construction -----------------------------------------------------


def test_argv_has_exact_boolean_script_filter_as_single_element():
    argv, host = nvs_execute.build_argv("10.0.0.5", "80,443,445")
    assert host == "10.0.0.5"
    idx = argv.index("--script")
    assert argv[idx + 1] == "(vuln or safe) and not (dos or exploit or brute or intrusive or external)"


def test_argv_uses_script_timeout_30s():
    argv, _ = nvs_execute.build_argv("10.0.0.5", "80")
    idx = argv.index("--script-timeout")
    assert argv[idx + 1] == "30s"


def test_argv_uses_xml_output_not_grepable():
    argv, _ = nvs_execute.build_argv("10.0.0.5", "80")
    idx = argv.index("-oX")
    assert argv[idx + 1] == "-"
    assert "-oG" not in argv


def test_argv_passes_explicit_port_list_and_host_last():
    argv, host = nvs_execute.build_argv("target.local", "80, 443,445")
    assert argv[argv.index("-p") + 1] == "80,443,445"
    assert argv[-1] == "target.local"
    assert host == "target.local"


def test_argv_never_uses_top_ports_or_full_range():
    argv, _ = nvs_execute.build_argv("10.0.0.5", "80,443")
    assert "--top-ports" not in argv
    assert "-F" not in argv


def test_execute_runs_argv_as_list_without_shell():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(stdout=NMAP_XML)) as run:
        raw = nvs_execute.execute("10.0.0.5", "22,80,445")
    assert raw.error is None
    args, kwargs = run.call_args
    argv = args[0]
    assert isinstance(argv, list)
    assert argv[0] == "nmap"
    assert "shell" not in kwargs or kwargs["shell"] is False
    assert argv[argv.index("--script") + 1].startswith("(vuln or safe) and not (")


# -- ports / target validation ---------------------------------------------


@pytest.mark.parametrize("ports", ["", "   ", None])
def test_missing_ports_rejected(ports):
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run") as run:
        raw = nvs_execute.execute("10.0.0.5", ports)
    assert raw.error and "ports" in raw.error
    run.assert_not_called()


def test_more_than_20_ports_rejected():
    too_many = ",".join(str(p) for p in range(1, 22))  # 21 ports
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run") as run:
        raw = nvs_execute.execute("10.0.0.5", too_many)
    assert raw.error and "20" in raw.error
    run.assert_not_called()


def test_exactly_20_ports_accepted():
    twenty = ",".join(str(p) for p in range(1, 21))
    assert len(nvs_execute.parse_ports(twenty)) == 20


@pytest.mark.parametrize("ports", ["1-1000", "1-65535", "http,https", "80,,443", "0", "70000", "80;rm"])
def test_ranges_words_and_invalid_ports_rejected(ports):
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run") as run:
        raw = nvs_execute.execute("10.0.0.5", ports)
    assert raw.error
    run.assert_not_called()


def test_valid_comma_separated_ports_accepted():
    assert nvs_execute.parse_ports("80,443,445") == [80, 443, 445]
    assert nvs_execute.parse_ports("22") == [22]


def test_host_port_target_rejected():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run") as run:
        raw = nvs_execute.execute("10.0.0.5:80", "80")
    assert raw.error and "ports" in raw.error
    run.assert_not_called()


def test_option_like_target_rejected():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run") as run:
        raw = nvs_execute.execute("-oN /tmp/x", "80")
    assert raw.error
    run.assert_not_called()


def test_tool_run_returns_error_dict_for_bad_ports_never_raises():
    result = NmapVulnScan().run(target="10.0.0.5", ports="1-65535")
    assert result["ports"] == []
    assert "error" in result


# -- XML parsing -----------------------------------------------------------


def test_parse_returns_open_ports_only():
    ports = nvs_parse.parse_script_results(NMAP_XML)
    assert [p["port"] for p in ports] == [22, 80, 445]
    assert all(p["state"] == "open" for p in ports)


def test_port_with_no_scripts_has_empty_scripts_list():
    ports = {p["port"]: p for p in nvs_parse.parse_script_results(NMAP_XML)}
    assert ports[22]["scripts"] == []
    assert ports[22]["service"] == "ssh"


def test_port_with_one_script():
    ports = {p["port"]: p for p in nvs_parse.parse_script_results(NMAP_XML)}
    assert ports[80]["scripts"] == [{"id": "http-title", "output": "Welcome & Login <admin>"}]


def test_port_with_multiple_scripts_and_multiline_output():
    ports = {p["port"]: p for p in nvs_parse.parse_script_results(NMAP_XML)}
    scripts = ports[445]["scripts"]
    assert [s["id"] for s in scripts] == ["smb-protocols", "smb2-security-mode", "smb-vuln-ms10-054"]
    assert scripts[0]["output"] == "dialects:\n  NT LM 0.12 (SMBv1)\n  2.02"
    assert scripts[1]["output"] == "Message signing enabled but not required"
    assert scripts[2]["output"] == "false"


def test_special_characters_in_output_are_unescaped():
    ports = {p["port"]: p for p in nvs_parse.parse_script_results(NMAP_XML)}
    assert "&" in ports[80]["scripts"][0]["output"]
    assert "<admin>" in ports[80]["scripts"][0]["output"]


def test_long_script_output_is_capped_and_flagged():
    long_output = "A" * (nvs_parse.MAX_SCRIPT_OUTPUT_CHARS + 500)
    xml = (
        '<nmaprun><host><ports><port protocol="tcp" portid="80">'
        '<state state="open"/><script id="big" output="' + long_output + '"/>'
        "</port></ports></host></nmaprun>"
    )
    script = nvs_parse.parse_script_results(xml)[0]["scripts"][0]
    assert len(script["output"]) == nvs_parse.MAX_SCRIPT_OUTPUT_CHARS
    assert script["output_truncated"] is True


def test_malformed_xml_raises_parse_error_in_parser():
    with pytest.raises(ET.ParseError):
        nvs_parse.parse_script_results("<nmaprun><host>")


def test_empty_xml_scan_with_no_ports_is_empty_list():
    xml = '<nmaprun><host><status state="up"/></host></nmaprun>'
    assert nvs_parse.parse_script_results(xml) == []


# -- execution failure -> error key ----------------------------------------


def test_nonzero_exit_sets_error():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(returncode=1, stderr="QUITTING!")):
        raw = nvs_execute.execute("10.0.0.5", "80")
    assert raw.error and "nmap failed" in raw.error


def test_missing_binary_sets_error():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run", side_effect=FileNotFoundError):
        raw = nvs_execute.execute("10.0.0.5", "80")
    assert raw.error == "nmap executable not found"


def test_timeout_sets_error():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=600)):
        raw = nvs_execute.execute("10.0.0.5", "80")
    assert raw.error and "timed out" in raw.error


def test_tool_run_maps_execution_error_to_error_key():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(returncode=1, stderr="boom")):
        result = NmapVulnScan().run(target="10.0.0.5", ports="80")
    assert "error" in result and result["ports"] == []


def test_tool_run_success_end_to_end_with_mocked_subprocess():
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(stdout=NMAP_XML)):
        result = NmapVulnScan().run(target="10.0.0.5", ports="22,80,445")
    assert "error" not in result
    assert [p["port"] for p in result["ports"]] == [22, 80, 445]


def _xml_with_many_scripts(num_ports: int, scripts_per_port: int) -> str:
    """Synthetic -oX fixture: num_ports open ports, each carrying
    scripts_per_port <script> elements, to exercise the aggregate cap."""
    ports_xml = []
    for i in range(num_ports):
        port_num = 1000 + i
        scripts_xml = "".join(
            f'<script id="safe-script-{j}" output="finding {j}"/>'
            for j in range(scripts_per_port)
        )
        ports_xml.append(
            f'<port protocol="tcp" portid="{port_num}">'
            f'<state state="open" reason="syn-ack" reason_ttl="64"/>'
            f'<service name="http" method="table" conf="3"/>'
            f'{scripts_xml}</port>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?><nmaprun>'
        '<host><status state="up" reason="user-set"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/>'
        f'<ports>{"".join(ports_xml)}</ports></host></nmaprun>'
    )


def test_tool_run_caps_total_scripts_across_all_ports():
    # 20 ports x 10 scripts each = 200 total script entries, well over the
    # 50-entry aggregate cap -- even though no single script output is
    # anywhere near the per-script MAX_SCRIPT_OUTPUT_CHARS.
    xml = _xml_with_many_scripts(num_ports=20, scripts_per_port=10)
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(stdout=xml)):
        result = NmapVulnScan().run(target="10.0.0.5", ports=",".join(str(1000 + i) for i in range(20)))
    assert "error" not in result
    total_returned = sum(len(p["scripts"]) for p in result["ports"])
    assert total_returned == 50
    assert result["truncated"] is True
    assert result["total_scripts_found"] == 200
    assert result["scripts_returned"] == 50
    assert len(result["ports"]) == 20  # every port is still listed, just capped


def test_tool_run_does_not_cap_when_under_the_aggregate_limit():
    xml = _xml_with_many_scripts(num_ports=3, scripts_per_port=2)
    with patch("tradecraft.adapters.nmap_vuln_scan.execute.subprocess.run",
               return_value=_fake_process(stdout=xml)):
        result = NmapVulnScan().run(target="10.0.0.5", ports="1000,1001,1002")
    assert "truncated" not in result
    assert sum(len(p["scripts"]) for p in result["ports"]) == 6
