"""
Tests for _resolve_tor_systemd_unit(): the real-world bug where
Debian/Kali's multi-instance tor packaging makes 'tor.service' a stub
master unit (often ExecStart=/bin/true, existing only for ordering)
while the actual daemon runs under 'tor@default.service'. Every
start/stop/restart call that hardcoded "tor" was silently controlling
the harmless stub, never the real running process.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import proxy_tor, environment as envmod


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


def _reset_cache(monkeypatch):
    """The resolved unit is cached at module level (one systemctl
    query per process is enough) — tests must reset it or an earlier
    test's result leaks into a later one."""
    monkeypatch.setattr(proxy_tor, "_TOR_UNIT_CACHE", None)


def test_resolves_to_tor_default_when_multi_instance_unit_exists(monkeypatch):
    _reset_cache(monkeypatch)
    mock_result = MagicMock(returncode=0, stdout="UNIT FILE            STATE\ntor@default.service  static\n")
    with patch("subprocess.run", return_value=mock_result):
        assert proxy_tor._resolve_tor_systemd_unit() == "tor@default"


def test_resolves_to_plain_tor_when_no_multi_instance_unit(monkeypatch):
    _reset_cache(monkeypatch)
    mock_result = MagicMock(returncode=1, stdout="")
    with patch("subprocess.run", return_value=mock_result):
        assert proxy_tor._resolve_tor_systemd_unit() == "tor"


def test_resolves_to_plain_tor_on_systemctl_error(monkeypatch):
    _reset_cache(monkeypatch)
    with patch("subprocess.run", side_effect=Exception("systemctl not found")):
        assert proxy_tor._resolve_tor_systemd_unit() == "tor"


def test_resolution_is_cached_not_requeried(monkeypatch):
    _reset_cache(monkeypatch)
    mock_result = MagicMock(returncode=0, stdout="tor@default.service  static\n")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        first = proxy_tor._resolve_tor_systemd_unit()
        second = proxy_tor._resolve_tor_systemd_unit()
        assert first == second == "tor@default"
        assert mock_run.call_count == 1, "should only query systemctl once per process, not every call"


def test_start_tor_uses_resolved_unit_not_hardcoded_tor(monkeypatch):
    _reset_cache(monkeypatch)
    env = make_env()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "list-unit-files"]:
            return MagicMock(returncode=0, stdout="tor@default.service  static\n")
        return MagicMock(returncode=0, stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        proxy_tor.start_tor(env)
    assert ["systemctl", "start", "tor@default"] in calls
    assert ["systemctl", "start", "tor"] not in calls, \
        "must target the real per-instance unit, not the stub master unit"


def test_stop_tor_uses_resolved_unit_not_hardcoded_tor(monkeypatch):
    _reset_cache(monkeypatch)
    env = make_env()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "list-unit-files"]:
            return MagicMock(returncode=0, stdout="tor@default.service  static\n")
        return MagicMock(returncode=0, stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        proxy_tor.stop_tor(env)
    assert ["systemctl", "stop", "tor@default"] in calls
