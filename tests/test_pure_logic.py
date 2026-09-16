"""
Pure-logic tests — no root, no network, no real iptables/tor needed.
These cover the parts of the codebase that were previously entirely
unverified: config-file generation, MAC/hostname format, and state
persistence.

Run with: pytest tests/
"""
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import core, environment as envmod, state as statemod, proxy_tor, proxy_only, dns_check


# ----------------------------------------------------------------
# core.py — MAC/hostname generation
# ----------------------------------------------------------------

def test_random_mac_format():
    mac = core.random_mac()
    assert re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)


def test_random_mac_is_locally_administered_unicast():
    # First octet's low bit must be 0 (unicast) and bit 1 must be 1 (locally administered)
    for _ in range(50):
        mac = core.random_mac()
        first_octet = int(mac.split(":")[0], 16)
        assert first_octet & 0x01 == 0, "MAC must be unicast (LSB of first octet = 0)"
        assert first_octet & 0x02 == 0x02, "MAC must be locally administered"


def test_random_hostname_format():
    for _ in range(20):
        host = core.random_hostname()
        assert re.match(r"^[a-z]+-[a-z]+-\d{3}$", host)


def test_randomize_mac_attempts_dhcp_renewal_via_nmcli(monkeypatch):
    """The actual fix for 'changed MAC, lost internet on a bridged VM':
    the router's lease/ARP table still points at the old MAC until
    something forces a fresh DHCP negotiation."""
    env = envmod.detect_environment()
    env = env.__class__(**{**env.__dict__, "termux": False, "root": True, "has_macchanger": False})
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        result = MagicMock(returncode=0, stderr="")
        return result

    with patch("subprocess.run", side_effect=fake_run), patch.object(envmod, "have", return_value=True):
        core.randomize_mac(env, "eth0")
    assert ["nmcli", "device", "connect", "eth0"] in calls


def test_randomize_mac_skips_renewal_when_disabled(monkeypatch):
    env = envmod.detect_environment()
    env = env.__class__(**{**env.__dict__, "termux": False, "root": True, "has_macchanger": False})
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return MagicMock(returncode=0, stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        core.randomize_mac(env, "eth0", renew_dhcp=False)
    assert not any("nmcli" in c for c in calls)


# ----------------------------------------------------------------
# proxy_tor.py — proxychains config generation
# ----------------------------------------------------------------

def test_proxychains_conf_dynamic_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_tor, "proxychains_conf_path", lambda env: tmp_path / "proxychains.conf")
    env = envmod.detect_environment()
    path = proxy_tor.generate_proxychains_conf(env, ["socks5 203.0.113.5 1080"], chain_mode="dynamic",
                                                include_tor=True)
    content = path.read_text()
    assert "dynamic_chain" in content
    assert "socks5 127.0.0.1 9050" in content  # Tor included
    assert "socks5 203.0.113.5 1080" in content


def test_proxychains_conf_no_tor(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_tor, "proxychains_conf_path", lambda env: tmp_path / "proxychains.conf")
    env = envmod.detect_environment()
    path = proxy_tor.generate_proxychains_conf(env, ["socks5 203.0.113.5 1080"], chain_mode="random",
                                                include_tor=False)
    content = path.read_text()
    assert "random_chain" in content
    assert "9050" not in content  # no Tor hop


def test_proxychains_conf_strict_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_tor, "proxychains_conf_path", lambda env: tmp_path / "proxychains.conf")
    env = envmod.detect_environment()
    path = proxy_tor.generate_proxychains_conf(env, [], chain_mode="strict", include_tor=True)
    assert "strict_chain" in path.read_text()


# ----------------------------------------------------------------
# proxy_only.py — redsocks config generation, incl. auth
# ----------------------------------------------------------------

def test_redsocks_conf_no_auth(tmp_path, monkeypatch):
    conf_path = tmp_path / "redsocks.conf"
    monkeypatch.setattr(proxy_only, "REDSOCKS_CONF", conf_path)
    proxy_only.generate_redsocks_conf("203.0.113.9", 1080, "socks5")
    content = conf_path.read_text()
    assert "ip = 203.0.113.9;" in content
    assert "port = 1080;" in content
    assert "login" not in content


def test_redsocks_conf_with_auth(tmp_path, monkeypatch):
    conf_path = tmp_path / "redsocks.conf"
    monkeypatch.setattr(proxy_only, "REDSOCKS_CONF", conf_path)
    proxy_only.generate_redsocks_conf("203.0.113.9", 1080, "socks5", username="alice", password="s3cret")
    content = conf_path.read_text()
    assert 'login = "alice";' in content
    assert 'password = "s3cret";' in content


def test_redsocks_conf_invalid_type_falls_back_to_socks5(tmp_path, monkeypatch):
    conf_path = tmp_path / "redsocks.conf"
    monkeypatch.setattr(proxy_only, "REDSOCKS_CONF", conf_path)
    proxy_only.generate_redsocks_conf("203.0.113.9", 1080, "not-a-real-type")
    assert "type = socks5;" in conf_path.read_text()


# ----------------------------------------------------------------
# state.py — persistence and idempotency support
# ----------------------------------------------------------------

def test_state_roundtrip(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(statemod, "STATE_FILE", state_file)
    statemod.update(tor_kill_switch=True, active_proxy="socks5://1.2.3.4:1080")
    loaded = statemod.load()
    assert loaded["tor_kill_switch"] is True
    assert loaded["active_proxy"] == "socks5://1.2.3.4:1080"
    assert loaded["proxy_only_kill_switch"] is False  # default preserved


def test_state_defaults_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "nonexistent.json")
    loaded = statemod.load()
    assert loaded == statemod.DEFAULT_STATE


def test_state_survives_corrupt_file(tmp_path, monkeypatch):
    bad_file = tmp_path / "state.json"
    bad_file.write_text("{not valid json")
    monkeypatch.setattr(statemod, "STATE_FILE", bad_file)
    loaded = statemod.load()  # should not raise
    assert loaded["tor_kill_switch"] is False


# ----------------------------------------------------------------
# dns_check.py — resolver parsing logic
# ----------------------------------------------------------------

def test_configured_resolvers_parsing(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.1\nnameserver 8.8.8.8\n# comment\n")
    monkeypatch.setattr(dns_check, "Path", lambda p: resolv if p == "/etc/resolv.conf" else Path(p))
    servers = dns_check.configured_resolvers()
    assert "127.0.0.1" in servers
    assert "8.8.8.8" in servers


def test_dns_leak_verdict_flags_non_local_when_tunnel_expected(monkeypatch):
    monkeypatch.setattr(dns_check, "configured_resolvers", lambda: ["8.8.8.8"])
    monkeypatch.setattr(dns_check, "resolver_identifying_ip", lambda: None)
    monkeypatch.setattr(dns_check.proxy_tor, "check_tor_active", lambda: {"error": "n/a"})
    env = envmod.detect_environment()
    report = dns_check.dns_leak_check(env, expect_local_only=True)
    assert "LIKELY LEAKING" in report["leak_verdict"]


def test_dns_leak_verdict_ok_when_all_local(monkeypatch):
    monkeypatch.setattr(dns_check, "configured_resolvers", lambda: ["127.0.0.1"])
    monkeypatch.setattr(dns_check, "resolver_identifying_ip", lambda: None)
    monkeypatch.setattr(dns_check.proxy_tor, "check_tor_active", lambda: {"error": "n/a"})
    env = envmod.detect_environment()
    report = dns_check.dns_leak_check(env, expect_local_only=True)
    assert "LIKELY LEAKING" not in report["leak_verdict"]
