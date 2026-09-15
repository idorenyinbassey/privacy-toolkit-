"""
Tests for gateway mode: gateway.py, workstation.py, gateway_topology.py.
Same mocked-subprocess approach as the rest of the suite.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import environment as envmod, state as statemod, gateway, workstation


def make_env(**overrides):
    base = dict(
        termux=False, root=True, distro="Test Linux",
        has_iproute2=True, has_tor=True, has_obfs4proxy=False,
        has_proxychains=True, has_torsocks=False, has_macchanger=True,
        has_iptables=True, has_ip6tables=True, has_sysctl=True,
        has_systemctl=True, has_sdmem=False, has_vboxmanage=False,
        has_virsh=False, has_scapy=False, has_stem=False,
        has_cryptography=True, interfaces=["eth0", "eth1"],
    )
    base.update(overrides)
    return envmod.Environment(**base)


# ----------------------------------------------------------------
# gateway.py — torrc snippet management
# ----------------------------------------------------------------

def test_torrc_snippet_written_fresh(tmp_path):
    torrc = tmp_path / "torrc"
    gateway._write_gateway_torrc_snippet("10.152.152.10", torrc_path=torrc)
    content = torrc.read_text()
    assert "TransPort 10.152.152.10:9040" in content
    assert "DNSPort 10.152.152.10:5353" in content
    assert "PrivacyGuard gateway mode (managed block)" in content


def test_torrc_snippet_idempotent_replace(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text("SocksPort 9050\n")
    gateway._write_gateway_torrc_snippet("10.152.152.10", torrc_path=torrc)
    gateway._write_gateway_torrc_snippet("10.152.152.20", torrc_path=torrc)  # re-run with different IP
    content = torrc.read_text()
    assert content.count("PrivacyGuard gateway mode") == 2  # start+end marker, not duplicated blocks
    assert "10.152.152.10" not in content  # old IP replaced
    assert "10.152.152.20" in content
    assert "SocksPort 9050" in content  # pre-existing content preserved


# ----------------------------------------------------------------
# gateway.py — idempotency / conflict guards
# ----------------------------------------------------------------

def test_enable_gateway_skips_when_already_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(gateway_mode_active=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        gateway.enable_gateway(env, "eth1", "10.152.152.10")
        mock_run.assert_not_called()


def test_enable_gateway_refuses_with_kill_switch_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(tor_kill_switch=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        gateway.enable_gateway(env, "eth1", "10.152.152.10")
        mock_run.assert_not_called()


def test_enable_gateway_requires_tor_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env(has_tor=False)
    with patch("subprocess.run") as mock_run:
        gateway.enable_gateway(env, "eth1", "10.152.152.10")
        mock_run.assert_not_called()


def test_enable_gateway_no_masquerade_rule_ever_issued(tmp_path, monkeypatch):
    """The core security property: no rule should ever ask iptables to
    MASQUERADE or ACCEPT-forward traffic from internal to external."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n")
    with patch("subprocess.run", return_value=mock_result) as mock_run, \
         patch.object(gateway, "_write_gateway_torrc_snippet"):
        gateway.enable_gateway(env, "eth1", "10.152.152.10", external_iface="eth0")
        all_calls = [c.args[0] for c in mock_run.call_args_list]
        assert not any("MASQUERADE" in " ".join(c) for c in all_calls), \
            "no MASQUERADE rule should ever be issued — that would defeat the isolation"
        assert not any("FORWARD" in c and "ACCEPT" in c for c in all_calls), \
            "no FORWARD ACCEPT rule should ever be issued"
        assert ["iptables", "-P", "FORWARD", "DROP"] in all_calls


def test_enable_gateway_sets_state_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n")
    with patch("subprocess.run", return_value=mock_result), patch.object(gateway, "_write_gateway_torrc_snippet"):
        gateway.enable_gateway(env, "eth1", "10.152.152.10")
    assert statemod.get("gateway_mode_active") is True
    cfg = statemod.get("gateway_config")
    assert cfg["internal_iface"] == "eth1"
    assert cfg["internal_ip"] == "10.152.152.10"


def test_disable_gateway_noop_when_not_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    with patch("subprocess.run") as mock_run:
        gateway.disable_gateway(env)
        mock_run.assert_not_called()


# ----------------------------------------------------------------
# workstation.py — isolation verification logic
# ----------------------------------------------------------------

def test_verify_isolation_passes_with_single_interface_and_route(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.152.152.10\n")
    monkeypatch.setattr(workstation, "Path", lambda p: resolv if p == "/etc/resolv.conf" else Path(p))

    def fake_run(cmd, **kwargs):
        result = MagicMock(returncode=0)
        if cmd[:3] == ["ip", "-o", "link"]:
            result.stdout = "1: lo: <LOOPBACK>\n2: eth0: <UP>\n"
        elif cmd[:4] == ["ip", "route", "show", "default"]:
            result.stdout = "default via 10.152.152.10 dev eth0\n"
        return result

    env = make_env()
    with patch("subprocess.run", side_effect=fake_run):
        report = workstation.verify_isolation(env, expected_gateway_ip="10.152.152.10")
    assert report["passed"] is True


def test_verify_isolation_fails_with_two_interfaces(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.152.152.10\n")
    monkeypatch.setattr(workstation, "Path", lambda p: resolv if p == "/etc/resolv.conf" else Path(p))

    def fake_run(cmd, **kwargs):
        result = MagicMock(returncode=0)
        if cmd[:3] == ["ip", "-o", "link"]:
            result.stdout = "1: lo: <LOOPBACK>\n2: eth0: <UP>\n3: eth1: <UP>\n"  # second real NIC = leak risk
        elif cmd[:4] == ["ip", "route", "show", "default"]:
            result.stdout = "default via 10.152.152.10 dev eth0\n"
        return result

    env = make_env()
    with patch("subprocess.run", side_effect=fake_run):
        report = workstation.verify_isolation(env, expected_gateway_ip="10.152.152.10")
    assert report["passed"] is False
    assert report["interfaces"] == 2


def test_verify_isolation_fails_with_wrong_dns(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 8.8.8.8\n")  # not the gateway — a leak
    monkeypatch.setattr(workstation, "Path", lambda p: resolv if p == "/etc/resolv.conf" else Path(p))

    def fake_run(cmd, **kwargs):
        result = MagicMock(returncode=0)
        if cmd[:3] == ["ip", "-o", "link"]:
            result.stdout = "1: lo: <LOOPBACK>\n2: eth0: <UP>\n"
        elif cmd[:4] == ["ip", "route", "show", "default"]:
            result.stdout = "default via 10.152.152.10 dev eth0\n"
        return result

    env = make_env()
    with patch("subprocess.run", side_effect=fake_run):
        report = workstation.verify_isolation(env, expected_gateway_ip="10.152.152.10")
    assert report["passed"] is False


def test_configure_networking_noop_without_root(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env(root=False)
    with patch("subprocess.run") as mock_run:
        workstation.configure_networking(env, "eth0", "10.152.152.11", "10.152.152.10")
        mock_run.assert_not_called()
