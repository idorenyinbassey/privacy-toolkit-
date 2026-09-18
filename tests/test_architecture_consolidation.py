"""
Tests for the architecture-consolidation pass: the shared
firewall_backup.apply_ruleset() helper (replacing three near-identical
backup/apply/rollback loops in core.py, proxy_only.py, and gateway.py),
the DNS-resolver-parsing dedup, and the single verify.verify_active()
entry point (replacing two copy-pasted dispatch blocks in main.py, one
of which silently skipped the IPv6 check the other one always ran).
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import environment as envmod, state as statemod, firewall_backup, core, dns_check, verify


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


# ----------------------------------------------------------------
# firewall_backup.apply_ruleset
# ----------------------------------------------------------------

def test_apply_ruleset_backs_up_before_applying(tmp_path, monkeypatch):
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n", stderr="")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        ok, backups = firewall_backup.apply_ruleset(env, [["iptables", "-F"]], label="test")
        assert ok is True
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert calls[0] == ["iptables-save"], "backup must happen before any rule is applied"
        assert backups["ipv4"] is not None


def test_apply_ruleset_applies_every_rule_in_order(tmp_path, monkeypatch):
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n", stderr="")
    rules = [["iptables", "-A", "OUTPUT", "-j", "ACCEPT"], ["iptables", "-A", "OUTPUT", "-j", "DROP"]]
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        ok, _ = firewall_backup.apply_ruleset(env, rules, label="test")
        assert ok is True
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert rules[0] in calls and rules[1] in calls


def test_apply_ruleset_rolls_back_on_failure(tmp_path, monkeypatch):
    """The actual property this exists to preserve: a partially-applied
    ruleset must never be left in place — on any hard failure, restore
    the pre-existing rules rather than leaving a half-applied firewall."""
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()

    def fake_run(cmd, **kwargs):
        if cmd == ["iptables-save"]:
            return MagicMock(returncode=0, stdout="# original rules\n", stderr="")
        if cmd == ["iptables", "-A", "OUTPUT", "-j", "BOGUS"]:
            return MagicMock(returncode=1, stdout="", stderr="iptables: No chain/target/match by that name.")
        return MagicMock(returncode=0, stdout="", stderr="")

    rules = [["iptables", "-A", "OUTPUT", "-j", "ACCEPT"], ["iptables", "-A", "OUTPUT", "-j", "BOGUS"]]
    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        ok, _ = firewall_backup.apply_ruleset(env, rules, label="test")
        assert ok is False
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["iptables-restore"] in calls, "must restore the backup after a failed rule"


def test_apply_ruleset_continues_through_remaining_rules_after_a_failure(tmp_path, monkeypatch):
    """Matches the prior per-module behavior: don't abort mid-loop, so
    every rule gets a chance to report its own error before rollback."""
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()

    def fake_run(cmd, **kwargs):
        if cmd == ["iptables-save"]:
            return MagicMock(returncode=0, stdout="# original\n", stderr="")
        if cmd == ["iptables", "-A", "OUTPUT", "-j", "BOGUS"]:
            return MagicMock(returncode=1, stdout="", stderr="bad target")
        return MagicMock(returncode=0, stdout="", stderr="")

    rules = [["iptables", "-A", "OUTPUT", "-j", "BOGUS"], ["iptables", "-A", "OUTPUT", "-j", "DROP"]]
    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        firewall_backup.apply_ruleset(env, rules, label="test")
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["iptables", "-A", "OUTPUT", "-j", "DROP"] in calls, \
            "the rule after the failing one must still be attempted"


def test_apply_ruleset_tolerates_listed_stderr_as_idempotent_noop(tmp_path, monkeypatch):
    """proxy_only.py's PG_REDSOCKS chain creation is idempotent: '-N'
    failing because the chain already exists is not a real failure."""
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()

    def fake_run(cmd, **kwargs):
        if cmd == ["iptables-save"]:
            return MagicMock(returncode=0, stdout="# original\n", stderr="")
        if "-N" in cmd:
            return MagicMock(returncode=1, stdout="", stderr="iptables: Chain already exists.")
        return MagicMock(returncode=0, stdout="", stderr="")

    rules = [["iptables", "-t", "nat", "-N", "PG_REDSOCKS"], ["iptables", "-A", "OUTPUT", "-j", "ACCEPT"]]
    with patch("subprocess.run", side_effect=fake_run):
        ok, _ = firewall_backup.apply_ruleset(env, rules, label="test", tolerate=("Chain already exists",))
        assert ok is True, "a tolerated failure must not trigger rollback or a False return"


# ----------------------------------------------------------------
# DNS resolver parsing dedup
# ----------------------------------------------------------------

def test_get_dns_servers_delegates_to_dns_check(monkeypatch):
    monkeypatch.setattr(dns_check, "configured_resolvers", lambda: ["127.0.0.1", "9.9.9.9"])
    assert core.get_dns_servers() == ["127.0.0.1", "9.9.9.9"]


# ----------------------------------------------------------------
# verify.verify_active — single dispatch entry point
# ----------------------------------------------------------------

def test_verify_active_checks_tor_kill_switch_when_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(tor_kill_switch=True)
    env = make_env()
    with patch.object(verify, "verify_tor_kill_switch") as mock_verify, \
         patch.object(verify, "verify_proxy_kill_switch") as mock_proxy_verify:
        verify.verify_active(env)
        mock_verify.assert_called_once_with(env)
        mock_proxy_verify.assert_not_called()


def test_verify_active_checks_proxy_kill_switch_when_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(proxy_only_kill_switch=True, active_proxy="socks5://203.0.113.9:1080")
    env = make_env()
    with patch.object(verify, "verify_proxy_kill_switch") as mock_verify:
        verify.verify_active(env)
        mock_verify.assert_called_once_with(env, "203.0.113.9")


def test_verify_active_noop_when_nothing_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    with patch.object(verify, "verify_tor_kill_switch") as mock_tor, \
         patch.object(verify, "verify_proxy_kill_switch") as mock_proxy:
        verify.verify_active(env)
        mock_tor.assert_not_called()
        mock_proxy.assert_not_called()


def test_verify_active_also_checks_ipv6_when_blocked(tmp_path, monkeypatch):
    """The actual gap this closes: the --verify CLI flag used to skip
    this check even though menu option 24 always ran it, because the
    dispatch logic had been copy-pasted into main.py twice."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(tor_kill_switch=True, ipv6_blocked=True)
    env = make_env()
    with patch.object(verify, "verify_tor_kill_switch", return_value={"passed": True}), \
         patch.object(verify, "verify_ipv6_blocked") as mock_ipv6:
        verify.verify_active(env)
        mock_ipv6.assert_called_once_with(env)


def test_verify_active_skips_ipv6_when_not_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(tor_kill_switch=True, ipv6_blocked=False)
    env = make_env()
    with patch.object(verify, "verify_tor_kill_switch", return_value={"passed": True}), \
         patch.object(verify, "verify_ipv6_blocked") as mock_ipv6:
        verify.verify_active(env)
        mock_ipv6.assert_not_called()
