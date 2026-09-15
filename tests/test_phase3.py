"""
Tests for the Phase 3 additions: vpn.py, profiles.py, monitor.py.
Same approach as the rest of the suite — mock subprocess/network so
these run without root, without a real VPN, without real internet.
"""
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import environment as envmod, state as statemod, vpn, profiles, monitor


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
# vpn.py
# ----------------------------------------------------------------

def test_start_openvpn_refuses_without_root():
    env = make_env(root=False)
    with patch("subprocess.run") as mock_run:
        result = vpn.start_openvpn(env, "/some/config.ovpn")
        assert result is False
        mock_run.assert_not_called()


def test_start_openvpn_refuses_missing_config(tmp_path):
    env = make_env()
    with patch.object(envmod, "have", return_value=True):
        result = vpn.start_openvpn(env, str(tmp_path / "does-not-exist.ovpn"))
        assert result is False


def test_start_openvpn_refuses_when_already_active(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(vpn_active="openvpn:/other/config.ovpn")
    cfg = tmp_path / "test.ovpn"
    cfg.write_text("# fake config")
    env = make_env()
    with patch.object(envmod, "have", return_value=True), patch("subprocess.run") as mock_run:
        result = vpn.start_openvpn(env, str(cfg))
        assert result is False
        mock_run.assert_not_called()


def test_start_wireguard_sets_state_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0)
    with patch.object(envmod, "have", return_value=True), patch("subprocess.run", return_value=mock_result):
        result = vpn.start_wireguard(env, "wg0")
        assert result is True
    assert statemod.get("vpn_active") == "wireguard:wg0"


def test_vpn_status_reflects_state(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    assert vpn.vpn_status() == "none"
    statemod.update(vpn_active="wireguard:wg0")
    assert vpn.vpn_status() == "wireguard:wg0"


# ----------------------------------------------------------------
# profiles.py
# ----------------------------------------------------------------

def test_profile_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILE_DIR", tmp_path)
    data = {"proxies": ["socks5 1.2.3.4 1080"], "bridges": ["obfs4 5.6.7.8:443 FP cert=x"]}
    profiles.save_profile("myprofile", data, "correct-horse-battery-staple")
    loaded = profiles.load_profile("myprofile", "correct-horse-battery-staple")
    assert loaded == data


def test_profile_load_wrong_passphrase_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILE_DIR", tmp_path)
    profiles.save_profile("myprofile", {"proxies": []}, "right-password")
    try:
        profiles.load_profile("myprofile", "wrong-password")
        assert False, "should have raised on wrong passphrase"
    except Exception:
        pass  # Fernet raises InvalidToken — any exception here is correct behavior


def test_profile_load_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILE_DIR", tmp_path)
    try:
        profiles.load_profile("does-not-exist", "whatever")
        assert False, "should have raised FileNotFoundError"
    except FileNotFoundError:
        pass


def test_profile_list_and_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILE_DIR", tmp_path)
    profiles.save_profile("one", {"proxies": []}, "pw")
    profiles.save_profile("two", {"proxies": []}, "pw")
    names = profiles.list_profiles()
    assert set(names) == {"one", "two"}
    assert profiles.delete_profile("one") is True
    assert profiles.list_profiles() == ["two"]
    assert profiles.delete_profile("nonexistent") is False


# ----------------------------------------------------------------
# monitor.py
# ----------------------------------------------------------------

def test_leak_monitor_first_check_establishes_baseline_no_alert():
    env = make_env()
    alerts = []
    mon = monitor.LeakMonitor(env, interval=1, on_alert=alerts.append, expect_tunnel=False)
    with patch("privacyguard.monitor.core.get_public_ip", return_value="1.2.3.4"):
        mon._check_once()
    assert alerts == []
    assert mon._baseline_ip == "1.2.3.4"


def test_leak_monitor_alerts_on_ip_change():
    env = make_env()
    alerts = []
    mon = monitor.LeakMonitor(env, interval=1, on_alert=alerts.append, expect_tunnel=False)
    mon._baseline_ip = "1.2.3.4"
    with patch("privacyguard.monitor.core.get_public_ip", return_value="5.6.7.8"):
        mon._check_once()
    assert any("5.6.7.8" in a for a in alerts)


def test_leak_monitor_handles_ip_fetch_error_gracefully():
    env = make_env()
    alerts = []
    mon = monitor.LeakMonitor(env, interval=1, on_alert=alerts.append, expect_tunnel=False)
    with patch("privacyguard.monitor.core.get_public_ip", return_value="error: timeout"):
        mon._check_once()  # must not raise
    assert any("Could not fetch" in a for a in alerts)


def test_leak_monitor_start_stop_lifecycle():
    env = make_env()
    mon = monitor.LeakMonitor(env, interval=1, on_alert=lambda m: None, expect_tunnel=False)
    with patch("privacyguard.monitor.core.get_public_ip", return_value="1.2.3.4"):
        assert mon.is_running() is False
        mon.start()
        time.sleep(0.1)
        assert mon.is_running() is True
        mon.stop()
        assert mon.is_running() is False


def test_leak_monitor_double_start_is_safe():
    env = make_env()
    mon = monitor.LeakMonitor(env, interval=1, on_alert=lambda m: None, expect_tunnel=False)
    with patch("privacyguard.monitor.core.get_public_ip", return_value="1.2.3.4"):
        mon.start()
        mon.start()  # should just print "already running", not crash or double-spawn
        time.sleep(0.1)
        assert mon.is_running() is True
        mon.stop()
