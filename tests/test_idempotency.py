"""
Tests for the idempotency/state-guard logic added in the production
hardening pass — these mock subprocess.run so they run without root
or real iptables, and check the *decisions* (does it skip, does it
back up, does it restore) rather than actual firewall behavior.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import core, environment as envmod, state as statemod


def make_env(**overrides):
    base = dict(
        termux=False, root=True, distro="Test Linux",
        has_iproute2=True, has_tor=True, has_obfs4proxy=False,
        has_proxychains=True, has_torsocks=False, has_macchanger=True,
        has_iptables=True, has_ip6tables=True, has_sysctl=True,
        has_systemctl=True, has_sdmem=False, has_vboxmanage=False,
        has_virsh=False, has_scapy=False, has_stem=False,
        has_cryptography=True, interfaces=["eth0"],
    )
    base.update(overrides)
    return envmod.Environment(**base)


def test_enable_kill_switch_skips_when_already_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(tor_kill_switch=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        core.enable_kill_switch(env)
        mock_run.assert_not_called()  # should skip entirely, no iptables commands issued


def test_enable_kill_switch_refuses_when_proxy_only_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(proxy_only_kill_switch=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        core.enable_kill_switch(env)
        mock_run.assert_not_called()


def test_enable_kill_switch_backs_up_before_flushing(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake ruleset\n")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        core.enable_kill_switch(env)
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["iptables-save"] in calls, "must back up existing rules before flushing"
        flush_index = next(i for i, c in enumerate(calls) if c[:2] == ["iptables", "-F"])
        backup_index = calls.index(["iptables-save"])
        assert backup_index < flush_index, "backup must happen BEFORE the flush"


def test_disable_kill_switch_noop_when_not_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    with patch("subprocess.run") as mock_run:
        core.disable_kill_switch(env)
        mock_run.assert_not_called()


def test_kill_switch_noop_without_root():
    env = make_env(root=False)
    with patch("subprocess.run") as mock_run:
        core.enable_kill_switch(env)
        mock_run.assert_not_called()


def test_kill_switch_noop_on_termux():
    env = make_env(termux=True, root=False)
    with patch("subprocess.run") as mock_run:
        core.enable_kill_switch(env)
        mock_run.assert_not_called()


def test_block_ipv6_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(ipv6_blocked=True)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        core.block_ipv6(env)
        mock_run.assert_not_called()


def test_block_ipv6_sets_state_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=mock_result):
        core.block_ipv6(env)
    assert statemod.get("ipv6_blocked") is True
