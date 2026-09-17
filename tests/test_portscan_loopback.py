"""
Tests for the portscan-protection loopback-exclusion fix.

The actual bug this catches: the INPUT rule tracking "new connections
from one source" had no loopback exclusion, even though loopback
traffic genuinely traverses the INPUT chain on Linux. This tool's own
repeated local connectivity checks (polling Tor's SocksPort while
waiting for it to bootstrap, once every ~2s) counted toward that same
threshold and could trip the rule against themselves — the kill
switch's own bootstrap-wait loop silently defeated by the anti-recon
feature running alongside it.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import anti_recon, environment as envmod, state as statemod


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


def test_enable_portscan_protection_excludes_loopback(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0, stderr="")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        anti_recon.enable_portscan_protection(env)
        calls = [c.args[0] for c in mock_run.call_args_list]
        input_insert = next(c for c in calls if c[:3] == ["iptables", "-I", "INPUT"])
        assert "!" in input_insert and "lo" in input_insert, \
            "the tracking rule must exclude loopback, or the tool's own local " \
            "connectivity checks can trip it against themselves"
        lo_index = input_insert.index("lo")
        assert input_insert[lo_index - 1] == "-i" and input_insert[lo_index - 2] == "!", \
            "must be the exact '! -i lo' exclusion pattern"


def test_disable_portscan_protection_matches_the_exact_enabled_rule(tmp_path, monkeypatch):
    """iptables -D requires an exact spec match to find and remove a
    rule — if enable's rule spec changes, disable's -D calls must
    change identically or the rule is left orphaned forever."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update(portscan_protection=True, portscan_params={"hitcount": 15, "seconds": 60})
    env = make_env()
    mock_result = MagicMock(returncode=0, stderr="")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        anti_recon.disable_portscan_protection(env)
        calls = [c.args[0] for c in mock_run.call_args_list]
        delete_calls = [c for c in calls if c[:2] == ["iptables", "-D"]]
        assert any("!" in c and "lo" in c for c in delete_calls), \
            "disable must target the same '! -i lo' rule spec enable actually inserted"


def test_portscan_protection_state_survives_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    env = make_env()
    mock_result = MagicMock(returncode=0, stderr="")
    with patch("subprocess.run", return_value=mock_result):
        anti_recon.enable_portscan_protection(env, hitcount=20, seconds=30)
    assert statemod.get("portscan_protection") is True
    assert statemod.get("portscan_params") == {"hitcount": 20, "seconds": 30}
