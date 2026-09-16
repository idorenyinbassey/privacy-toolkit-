"""
Tests for the second half of the "enabled kill switch, lost internet"
bug report: even after enable_kill_switch correctly refused to touch
the firewall, orchestrate.full_start used to run verify_tor_kill_switch
anyway, printing a misleading "[FAIL]" report right after "NOT
enabling the kill switch" — reading as if something broke, when
actually the tool had correctly done nothing. full_start must check
enable_kill_switch's return value and skip verification when it's False.
"""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import environment as envmod, orchestrate, verify


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


def test_full_start_skips_verification_when_kill_switch_not_enabled(monkeypatch):
    env = make_env()
    monkeypatch.setattr(orchestrate.proxy_tor, "start_tor", lambda e: None)
    monkeypatch.setattr(orchestrate.core, "randomize_mac", lambda e, i: None)
    monkeypatch.setattr(orchestrate.core, "randomize_hostname", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_stealth_sysctls", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_portscan_protection", lambda e: None)
    monkeypatch.setattr(orchestrate.core, "enable_kill_switch", lambda e, bootstrap_timeout=45: False)

    with patch.object(verify, "verify_tor_kill_switch") as mock_verify:
        result = orchestrate.full_start(env)
        mock_verify.assert_not_called()
    assert result is False


def test_full_start_runs_verification_when_kill_switch_enabled(monkeypatch):
    env = make_env()
    monkeypatch.setattr(orchestrate.proxy_tor, "start_tor", lambda e: None)
    monkeypatch.setattr(orchestrate.core, "randomize_mac", lambda e, i: None)
    monkeypatch.setattr(orchestrate.core, "randomize_hostname", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_stealth_sysctls", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_portscan_protection", lambda e: None)
    monkeypatch.setattr(orchestrate.core, "enable_kill_switch", lambda e, bootstrap_timeout=45: True)
    monkeypatch.setattr(orchestrate.time, "sleep", lambda s: None)

    with patch.object(verify, "verify_tor_kill_switch") as mock_verify:
        result = orchestrate.full_start(env)
        mock_verify.assert_called_once_with(env)
    assert result is True


def test_full_start_passes_through_bootstrap_timeout(monkeypatch):
    env = make_env()
    monkeypatch.setattr(orchestrate.proxy_tor, "start_tor", lambda e: None)
    monkeypatch.setattr(orchestrate.core, "randomize_mac", lambda e, i: None)
    monkeypatch.setattr(orchestrate.core, "randomize_hostname", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_stealth_sysctls", lambda e: None)
    monkeypatch.setattr(orchestrate.anti_recon, "enable_portscan_protection", lambda e: None)

    seen = {}

    def fake_enable(e, bootstrap_timeout=45):
        seen["timeout"] = bootstrap_timeout
        return False

    monkeypatch.setattr(orchestrate.core, "enable_kill_switch", fake_enable)
    orchestrate.full_start(env, bootstrap_timeout=90)
    assert seen["timeout"] == 90
