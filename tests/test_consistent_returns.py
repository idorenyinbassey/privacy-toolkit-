"""
Tests for making every enable_*() function's success/failure signal
consistent. core.enable_kill_switch and proxy_only.enable_proxy_kill_switch
already returned bool ("True only if genuinely active now") as a
correctness fix (see CHANGELOG 2.2.2: callers need to distinguish
"applied" from "correctly declined"). anti_recon.enable_stealth_sysctls,
anti_recon.enable_portscan_protection, core.block_ipv6, and
gateway.enable_gateway now follow the exact same contract, so a caller
can finally tell "declined/failed" from "applied" for all of them, not
just the original two kill switches.
"""
import subprocess as sp
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import anti_recon, core, gateway, environment as envmod, state as statemod


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
# anti_recon.enable_stealth_sysctls
# ----------------------------------------------------------------

def test_enable_stealth_sysctls_returns_false_without_root():
    env = make_env(root=False)
    assert anti_recon.enable_stealth_sysctls(env) is False


def test_enable_stealth_sysctls_returns_true_when_already_applied(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(stealth_sysctls=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        assert anti_recon.enable_stealth_sysctls(env) is True
        mock_run.assert_not_called()


def test_enable_stealth_sysctls_returns_true_on_full_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="0")
    with patch("subprocess.run", return_value=mock_result):
        assert anti_recon.enable_stealth_sysctls(env) is True


def test_enable_stealth_sysctls_returns_false_on_partial_failure(tmp_path, monkeypatch):
    """Best-effort: state is still marked applied (whatever DID apply
    stays genuinely in effect), but the return value must honestly
    reflect that not every key succeeded."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["sysctl", "-n"]:
            return MagicMock(returncode=0, stdout="0")
        raise sp.CalledProcessError(1, cmd)  # every "sysctl -w" fails

    with patch("subprocess.run", side_effect=fake_run):
        result = anti_recon.enable_stealth_sysctls(env)
    assert result is False
    assert statemod.get("stealth_sysctls") is True  # best-effort: still marked applied


# ----------------------------------------------------------------
# anti_recon.enable_portscan_protection
# ----------------------------------------------------------------

def test_enable_portscan_protection_returns_false_without_root():
    env = make_env(root=False)
    assert anti_recon.enable_portscan_protection(env) is False


def test_enable_portscan_protection_returns_true_when_already_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(portscan_protection=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        assert anti_recon.enable_portscan_protection(env) is True
        mock_run.assert_not_called()


def test_enable_portscan_protection_returns_true_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0, stderr="")
    with patch("subprocess.run", return_value=mock_result):
        assert anti_recon.enable_portscan_protection(env) is True


def test_enable_portscan_protection_returns_false_on_rule_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=1, stderr="iptables: some real error")
    with patch("subprocess.run", return_value=mock_result):
        assert anti_recon.enable_portscan_protection(env) is False


# ----------------------------------------------------------------
# core.block_ipv6
# ----------------------------------------------------------------

def test_block_ipv6_returns_false_without_root():
    env = make_env(root=False)
    assert core.block_ipv6(env) is False


def test_block_ipv6_returns_true_when_already_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(ipv6_blocked=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        assert core.block_ipv6(env) is True
        mock_run.assert_not_called()


def test_block_ipv6_returns_true_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=mock_result):
        assert core.block_ipv6(env) is True


def test_block_ipv6_returns_false_on_rule_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    with patch("subprocess.run", side_effect=sp.CalledProcessError(1, ["ip6tables"])):
        assert core.block_ipv6(env) is False


# ----------------------------------------------------------------
# gateway.enable_gateway
# ----------------------------------------------------------------

def test_enable_gateway_returns_false_without_tor():
    env = make_env(has_tor=False)
    assert gateway.enable_gateway(env, "eth1", "10.152.152.10") is False


def test_enable_gateway_returns_true_when_already_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(gateway_mode_active=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        assert gateway.enable_gateway(env, "eth1", "10.152.152.10") is True
        mock_run.assert_not_called()


def test_enable_gateway_returns_true_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n", stderr="")
    with patch("subprocess.run", return_value=mock_result), patch.object(gateway, "_write_gateway_torrc_snippet"):
        assert gateway.enable_gateway(env, "eth1", "10.152.152.10") is True


def test_enable_gateway_returns_false_on_rule_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()

    def fake_run(cmd, **kwargs):
        if cmd == ["iptables-save"]:
            return MagicMock(returncode=0, stdout="# fake\n", stderr="")
        if cmd[:2] == ["iptables", "-F"]:
            return MagicMock(returncode=1, stdout="", stderr="boom")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run), patch.object(gateway, "_write_gateway_torrc_snippet"):
        assert gateway.enable_gateway(env, "eth1", "10.152.152.10") is False
