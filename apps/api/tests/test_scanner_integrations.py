from __future__ import annotations

from ipaddress import ip_address

import pytest

from traceless_api.integrations.scanners import (
    HostState,
    NaabuOutputError,
    NmapOutputError,
    ScanProfile,
    ScopeValidationError,
    build_nmap_command,
    normalize_scope,
    parse_naabu_jsonl,
    parse_nmap_xml,
    validate_observations,
    validate_targets,
)

NMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="10.20.30.40" addrtype="ipv4" />
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Devices" />
    <hostnames><hostname name="api.internal.example" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" />
        <service name="https" product="nginx" version="1.26.2" tunnel="ssl"
                 method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.26.2</cpe>
        </service>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 6.x" accuracy="96">
        <osclass><cpe>cpe:/o:linux:linux_kernel:6</cpe></osclass>
      </osmatch>
    </os>
  </host>
  <runstats><finished exit="success" elapsed="1.0" /></runstats>
</nmaprun>
"""


def test_scope_canonicalizes_and_deduplicates_targets() -> None:
    scope = normalize_scope(["10.20.30.0/24"], max_hosts=8)

    targets = validate_targets(scope, ["10.20.30.40", "10.20.30.40/32"])

    assert targets.argv == ("10.20.30.40/32",)
    assert targets.host_count == 1
    assert targets.contains(ip_address("10.20.30.40"))


def test_scope_accepts_a_single_literal_without_iterating_its_characters() -> None:
    scope = normalize_scope("10.20.30.0/24")

    targets = validate_targets(scope, "10.20.30.40")

    assert targets.argv == ("10.20.30.40/32",)


def test_scope_rejects_out_of_scope_target() -> None:
    scope = normalize_scope(["10.20.30.0/24"])

    with pytest.raises(ScopeValidationError, match="outside the approved scope"):
        validate_targets(scope, ["10.20.31.1"])


@pytest.mark.parametrize(
    ("approved", "target"),
    [
        ("127.0.0.0/8", "127.0.0.1"),
        ("169.254.0.0/16", "169.254.169.254"),
        ("192.0.2.0/24", "192.0.2.1"),
        ("224.0.0.0/4", "224.0.0.1"),
        ("::1", "::1"),
        ("fe80::/10", "fe80::1"),
        ("fd00:ec2::254", "fd00:ec2::254"),
    ],
)
def test_scope_always_rejects_forbidden_targets(approved: str, target: str) -> None:
    scope = normalize_scope([approved], allow_public_targets=True)

    with pytest.raises(ScopeValidationError, match="forbidden range"):
        validate_targets(scope, [target])


def test_public_target_requires_separate_explicit_approval() -> None:
    default_scope = normalize_scope(["8.8.8.8"])
    approved_public_scope = normalize_scope(["8.8.8.8"], allow_public_targets=True)

    with pytest.raises(ScopeValidationError, match="separate explicit approval"):
        validate_targets(default_scope, ["8.8.8.8"])

    assert validate_targets(approved_public_scope, ["8.8.8.8"]).host_count == 1


def test_scope_rejects_target_set_over_maximum_host_count() -> None:
    scope = normalize_scope(["10.20.30.0/24"], max_hosts=4)

    with pytest.raises(ScopeValidationError, match="contains 8 addresses; maximum is 4"):
        validate_targets(scope, ["10.20.30.0/29"])


def test_nmap_builder_rejects_command_injection_as_invalid_target() -> None:
    scope = normalize_scope(["10.20.30.0/24"])

    with pytest.raises(ScopeValidationError, match="IP address or canonical CIDR"):
        build_nmap_command(
            profile=ScanProfile.discovery,
            targets=["10.20.30.40;--script=default"],
            scope=scope,
        )


def test_nmap_builder_uses_only_fixed_non_privileged_profiles() -> None:
    scope = normalize_scope(["10.20.30.0/24"])

    discovery = build_nmap_command(
        profile=ScanProfile.discovery, targets=["10.20.30.40"], scope=scope
    )
    inventory = build_nmap_command(
        profile=ScanProfile.service_inventory,
        targets=["10.20.30.40"],
        scope=scope,
    )

    assert discovery.argv[0] == "nmap"
    assert "-sn" in discovery.argv
    assert "-sT" in inventory.argv
    assert "-sV" in inventory.argv
    assert inventory.argv[inventory.argv.index("--max-rate") + 1] == "100"
    assert "sudo" not in discovery.argv + inventory.argv
    assert not any(
        argument == "--script" or argument.startswith("--script=") for argument in inventory.argv
    )
    assert discovery.argv[-1] == "10.20.30.40/32"


def test_nmap_parser_normalizes_inventory_and_cpe_data() -> None:
    scope = normalize_scope(["10.20.30.0/24"])
    targets = validate_targets(scope, ["10.20.30.40"])

    result = parse_nmap_xml(NMAP_XML, targets=targets)

    assert result.scanner == "nmap"
    assert result.scanner_version == "7.95"
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.state is HostState.up
    assert str(host.addresses[0].address) == "10.20.30.40"
    assert host.hardware_addresses[0].address == "00:11:22:33:44:55"
    assert host.hostnames == ("api.internal.example",)
    assert host.services[0].product == "nginx"
    assert host.services[0].cpes == ("cpe:/a:nginx:nginx:1.26.2",)
    assert host.operating_systems[0].accuracy == 96
    assert validate_observations(result, targets=targets) is result


def test_nmap_parser_rejects_xxe_and_dtd() -> None:
    malicious = """\
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <address addr="10.20.30.40" addrtype="ipv4" />
    <hostnames><hostname name="&xxe;" /></hostnames>
  </host>
</nmaprun>
"""

    with pytest.raises(NmapOutputError, match="forbidden XML features"):
        parse_nmap_xml(malicious)


def test_nmap_parser_rejects_invalid_xml() -> None:
    with pytest.raises(NmapOutputError, match="malformed"):
        parse_nmap_xml("<nmaprun><host></nmaprun>")


def test_nmap_parser_rejects_out_of_target_observation() -> None:
    targets = validate_targets(normalize_scope(["10.20.30.0/24"]), ["10.20.30.41"])

    with pytest.raises(NmapOutputError, match="outside the validated targets"):
        parse_nmap_xml(NMAP_XML, targets=targets)


def test_naabu_jsonl_parser_groups_services_and_checks_scope() -> None:
    targets = validate_targets(normalize_scope(["10.20.30.0/24"]), ["10.20.30.40"])
    payload = "\n".join(
        [
            '{"ip":"10.20.30.40","host":"api.internal","port":443,"protocol":"tcp","tls":true}',
            '{"ip":"10.20.30.40","host":"api.internal","port":80,"protocol":"tcp"}',
        ]
    )

    result = parse_naabu_jsonl(payload, targets=targets)

    assert result.scanner == "naabu"
    assert len(result.hosts) == 1
    assert result.hosts[0].hostnames == ("api.internal",)
    assert [service.port for service in result.hosts[0].services] == [80, 443]
    assert result.hosts[0].services[1].tunnel == "tls"


def test_naabu_parser_rejects_invalid_json_and_out_of_target_address() -> None:
    targets = validate_targets(normalize_scope(["10.20.30.0/24"]), ["10.20.30.40"])

    with pytest.raises(NaabuOutputError, match="invalid JSON"):
        parse_naabu_jsonl("{not-json}", targets=targets)
    with pytest.raises(NaabuOutputError, match="outside the validated targets"):
        parse_naabu_jsonl('{"ip":"10.20.30.41","port":443,"protocol":"tcp"}', targets=targets)
