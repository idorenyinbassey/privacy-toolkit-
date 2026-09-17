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

from privacyguard import core, proxy_only, environment as envmod, state as statemod


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
    monkeypatch.setattr(core, "_ensure_transparent_proxy_torrc", lambda *a, **kw: False)
    monkeypatch.setattr(core, "_wait_for_tor_bootstrap", lambda *a, **kw: True)
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


def test_enable_kill_switch_refuses_without_tor_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env(has_tor=False)
    with patch("subprocess.run") as mock_run:
        core.enable_kill_switch(env)
        mock_run.assert_not_called()


def test_enable_kill_switch_refuses_when_tor_never_bootstraps(tmp_path, monkeypatch):
    """The actual bug this was written to catch: enabling the kill
    switch when Tor never comes up used to still apply the DROP-all
    firewall, killing all internet access with no working path out.
    It must now refuse instead, and report that refusal via its
    return value so callers (orchestrate.full_start) can act on it."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(core, "_ensure_transparent_proxy_torrc", lambda *a, **kw: False)
    monkeypatch.setattr(core, "_wait_for_tor_bootstrap", lambda *a, **kw: False)
    env = make_env()
    with patch("subprocess.run") as mock_run:
        result = core.enable_kill_switch(env)
        mock_run.assert_not_called()
        assert result is False, "must report failure via return value, not just print a warning"


def test_enable_kill_switch_returns_true_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(core, "_ensure_transparent_proxy_torrc", lambda *a, **kw: False)
    monkeypatch.setattr(core, "_wait_for_tor_bootstrap", lambda *a, **kw: True)
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n")
    with patch("subprocess.run", return_value=mock_result):
        result = core.enable_kill_switch(env)
    assert result is True


def test_enable_kill_switch_returns_false_without_root():
    env = make_env(root=False)
    assert core.enable_kill_switch(env) is False


def test_enable_kill_switch_returns_false_without_tor(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env(has_tor=False)
    assert core.enable_kill_switch(env) is False


def test_ensure_transparent_proxy_torrc_writes_fresh_file(tmp_path):
    torrc = tmp_path / "torrc"
    changed = core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    assert changed is True
    content = torrc.read_text()
    assert "TransPort 127.0.0.1:9040" in content
    assert "DNSPort 127.0.0.1:5353" in content


def test_ensure_transparent_proxy_torrc_idempotent_no_change(tmp_path):
    torrc = tmp_path / "torrc"
    core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    changed_again = core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    assert changed_again is False  # already correct, no rewrite/restart needed


def test_ensure_transparent_proxy_torrc_preserves_other_content(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text("SocksPort 9050\nLog notice file /var/log/tor/notices.log\n")
    core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    content = torrc.read_text()
    assert "SocksPort 9050" in content
    assert "TransPort 127.0.0.1:9040" in content


def test_ensure_transparent_proxy_torrc_removes_conflicting_manual_lines(tmp_path):
    """The actual bug this fixes: this tool's own earlier README told
    people to manually add TransPort/DNSPort to torrc before
    auto-config existed. If that line is still there, having BOTH it
    and our managed block means two directives fighting over the same
    port — Tor refuses to bind and crash-loops instead of bootstrapping,
    which looks identical to a slow/blocked network from the outside."""
    torrc = tmp_path / "torrc"
    torrc.write_text(
        "VirtualAddrNetwork 10.192.0.0/10\n"
        "AutomapHostsOnResolve 1\n"
        "TransPort 9040\n"
        "SocksPort 9050\n"
        "DNSPort 53\n"
        "RunAsDaemon 1\n"
    )
    changed = core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    assert changed is True
    content = torrc.read_text()
    # exactly one TransPort and one DNSPort line, both ours
    transport_lines = [l for l in content.splitlines() if l.strip().startswith("TransPort")]
    dnsport_lines = [l for l in content.splitlines() if l.strip().startswith("DNSPort")]
    assert transport_lines == ["TransPort 127.0.0.1:9040"]
    assert dnsport_lines == ["DNSPort 127.0.0.1:5353"]
    # unrelated lines survive
    assert "SocksPort 9050" in content
    assert "RunAsDaemon 1" in content


def test_ensure_transparent_proxy_torrc_cleans_up_even_when_marker_already_present(tmp_path):
    """The exact scenario reported: our own managed block was already
    written in an earlier run (marker present), but a manual/leftover
    TransPort line elsewhere in the file was never cleaned up because
    the old logic only checked 'is my marker here', not 'is anything
    ELSE also claiming this port'."""
    torrc = tmp_path / "torrc"
    torrc.write_text(
        "TransPort 9040\n"
        "DNSPort 53\n"
        "SocksPort 9050\n"
        "\n"
        "# --- PrivacyGuard kill switch (managed block) ---\n"
        "TransPort 127.0.0.1:9040\n"
        "DNSPort 127.0.0.1:5353\n"
        "AutomapHostsOnResolve 1\n"
        "# --- end PrivacyGuard kill switch ---\n"
    )
    changed = core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    assert changed is True, "must detect and fix the conflict even though its own marker was present"
    content = torrc.read_text()
    transport_lines = [l for l in content.splitlines() if l.strip().startswith("TransPort")]
    dnsport_lines = [l for l in content.splitlines() if l.strip().startswith("DNSPort")]
    assert transport_lines == ["TransPort 127.0.0.1:9040"]
    assert dnsport_lines == ["DNSPort 127.0.0.1:5353"]


def test_ensure_transparent_proxy_torrc_stable_after_cleanup(tmp_path):
    """Once cleaned up, a second call must report no further change —
    otherwise every kill-switch enable would restart tor unnecessarily."""
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9040\nDNSPort 53\nSocksPort 9050\n")
    core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    changed_again = core._ensure_transparent_proxy_torrc(torrc_path=torrc)
    assert changed_again is False


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


def test_proxy_only_refuses_when_proxy_unreachable(tmp_path, monkeypatch):
    """Same failure mode as the Tor kill switch: redirecting to an
    unreachable proxy used to still apply the firewall, dropping all
    internet access. Must refuse instead."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    with patch.object(envmod, "have", return_value=True), \
         patch.object(proxy_only, "_proxy_reachable", return_value=False), \
         patch("subprocess.run") as mock_run:
        proxy_only.enable_proxy_kill_switch(env, "203.0.113.9", 1080)
        mock_run.assert_not_called()


def test_proxy_only_proceeds_when_proxy_reachable(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    from privacyguard import firewall_backup
    monkeypatch.setattr(firewall_backup, "BACKUP_DIR", tmp_path / "backups")
    env = make_env()
    mock_result = MagicMock(returncode=0, stdout="# fake\n")
    with patch.object(envmod, "have", return_value=True), \
         patch.object(proxy_only, "_proxy_reachable", return_value=True), \
         patch.object(proxy_only, "generate_redsocks_conf"), \
         patch("subprocess.run", return_value=mock_result) as mock_run:
        proxy_only.enable_proxy_kill_switch(env, "203.0.113.9", 1080)
        assert mock_run.called  # proceeded past the reachability check
    assert statemod.get("proxy_only_kill_switch") is True
