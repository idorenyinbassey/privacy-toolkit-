"""
Tests for verify.py's corrected verification logic.

The actual bug this fixes: the original _direct_tcp_probe() opened a
plain TCP connection to test whether the kill switch blocks direct
traffic — but the kill switch's own iptables rule redirects EVERY new
TCP SYN through Tor regardless of destination, so a "direct" TCP probe
gets swept into that same redirect and can genuinely succeed via Tor
even when the kill switch works perfectly. That made the test report
a false failure for a working kill switch. ICMP isn't covered by any
ACCEPT/REDIRECT rule, so it's the correct thing to test instead.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import verify


def test_direct_traffic_blocked_true_when_ping_fails():
    """Ping getting no reply (non-zero exit) means the traffic was
    correctly blocked — this is the PASS case."""
    with patch("subprocess.run", return_value=MagicMock(returncode=1)):
        assert verify._direct_traffic_blocked() is True


def test_direct_traffic_blocked_false_when_ping_succeeds():
    """Ping getting a reply (exit 0) means non-redirected traffic is
    leaking out — this is the FAIL case, a real leak."""
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        assert verify._direct_traffic_blocked() is False


def test_direct_traffic_blocked_treats_missing_ping_binary_as_blocked():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert verify._direct_traffic_blocked() is True


def test_verify_tor_kill_switch_retries_tor_check_before_failing(monkeypatch):
    """The actual second fix: applying the kill switch flushes
    iptables, which can briefly disrupt a Tor circuit built moments
    earlier — a single immediate check shouldn't be the final word."""
    from privacyguard import environment as envmod, dns_check

    env = envmod.detect_environment()
    monkeypatch.setattr(verify, "_direct_traffic_blocked", lambda: True)
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    monkeypatch.setattr(dns_check, "dns_leak_check", lambda e, expect_local_only: {"leak_verdict": "fine"})

    call_count = {"n": 0}

    def flaky_check_tor_active():
        call_count["n"] += 1
        if call_count["n"] < 3:
            return {"error": "circuit not ready yet"}
        return {"IsTor": True, "IP": "1.2.3.4"}

    monkeypatch.setattr(verify.proxy_tor, "check_tor_active", flaky_check_tor_active)
    report = verify.verify_tor_kill_switch(env)
    assert call_count["n"] == 3, "should retry rather than fail on the first check"
    tor_check_result = [ok for desc, ok in report["checks"] if "routing through Tor" in desc][0]
    assert tor_check_result is True


def test_verify_tor_kill_switch_fails_after_exhausting_retries(monkeypatch):
    from privacyguard import environment as envmod, dns_check

    env = envmod.detect_environment()
    monkeypatch.setattr(verify, "_direct_traffic_blocked", lambda: True)
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    monkeypatch.setattr(dns_check, "dns_leak_check", lambda e, expect_local_only: {"leak_verdict": "fine"})
    monkeypatch.setattr(verify.proxy_tor, "check_tor_active", lambda: {"error": "never ready"})

    report = verify.verify_tor_kill_switch(env)
    assert report["passed"] is False
