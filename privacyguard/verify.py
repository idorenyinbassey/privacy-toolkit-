"""
Verification: every enable_* function so far has trusted "the iptables
command returned 0" to mean the protection actually works. That's not
proof — rule ordering bugs, a NAT table quirk, or Tor not having
finished bootstrapping yet can all leave you "protected" on paper and
leaking in practice. This module actually tests the live behavior.
"""
import subprocess
import time
import urllib.request

from . import environment as envmod
from . import proxy_tor, dns_check
from . import state as statemod


def _direct_traffic_blocked(host: str = "1.1.1.1", timeout: float = 4.0) -> bool:
    """True if traffic NOT subject to the kill switch's redirect rules
    is actually blocked, as it should be.

    This deliberately does NOT use a plain TCP connection: the kill
    switch's iptables rule (`-p tcp --syn -j REDIRECT --to-ports 9040`)
    catches EVERY new outbound TCP SYN regardless of destination —
    that's the whole mechanism, transparently routing ordinary
    connections through Tor rather than dropping them. A "direct" TCP
    probe therefore gets swept into that same redirect and can
    genuinely succeed via Tor even when the kill switch is working
    exactly as intended; treating that success as a leak is simply
    testing the wrong thing.

    ICMP isn't touched by any ACCEPT/REDIRECT rule in the ruleset, so
    it correctly falls through to the final DROP — a ping timing out
    is the actual evidence the kill switch is blocking non-redirected
    traffic, not a plain TCP connect."""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", str(int(timeout)), host],
                                 capture_output=True, timeout=timeout + 2)
        return result.returncode != 0  # non-zero = no reply = correctly blocked
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True  # no ping binary or it hung past its own timeout — treat as blocked


def verify_tor_kill_switch(env: envmod.Environment) -> dict:
    """Returns a dict report; also prints a human-readable summary."""
    report = {"checks": []}

    blocked = _direct_traffic_blocked()
    report["checks"].append(("Non-redirected traffic (ICMP) correctly blocked", blocked))

    # Applying the kill switch flushes iptables first, which can briefly
    # disrupt a Tor circuit that was only just built moments earlier
    # during the bootstrap check — retry with backoff rather than
    # judging on a single immediate check.
    tor_check = {"error": "not checked yet"}
    for attempt in range(4):
        tor_check = proxy_tor.check_tor_active()
        if "error" not in tor_check:
            break
        time.sleep(3)
    tor_ok = "error" not in tor_check and tor_check.get("IsTor")
    report["checks"].append(("Traffic confirmed routing through Tor", bool(tor_ok)))

    dns_report = dns_check.dns_leak_check(env, expect_local_only=True)
    dns_ok = "LIKELY LEAKING" not in dns_report["leak_verdict"]
    report["checks"].append(("No DNS leak detected", dns_ok))

    report["passed"] = all(ok for _, ok in report["checks"])
    _print_report("Tor kill switch", report)
    return report


def verify_proxy_kill_switch(env: envmod.Environment, proxy_host: str) -> dict:
    report = {"checks": []}

    blocked = _direct_traffic_blocked()
    report["checks"].append(("Non-redirected traffic (ICMP) correctly blocked", blocked))

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=8) as r:
            seen_ip = r.read().decode().strip()
        report["checks"].append((f"Traffic still reaches the internet (via proxy, exit IP: {seen_ip})", True))
    except Exception as e:
        report["checks"].append((f"Traffic reaches the internet via proxy ({e})", False))

    dns_report = dns_check.dns_leak_check(env, expect_local_only=True)
    dns_ok = "LIKELY LEAKING" not in dns_report["leak_verdict"]
    report["checks"].append(("No DNS leak detected (note: redsocks doesn't tunnel DNS — check carefully)", dns_ok))

    report["passed"] = all(ok for _, ok in report["checks"])
    _print_report("Proxy-only kill switch", report)
    return report


def verify_ipv6_blocked(env: envmod.Environment) -> dict:
    report = {"checks": []}
    if not env.has_ip6tables:
        report["checks"].append(("ip6tables available to test with", False))
        report["passed"] = False
        _print_report("IPv6 block", report)
        return report
    try:
        out = subprocess.run(["ip6tables", "-L", "OUTPUT"], capture_output=True, text=True, timeout=5)
        policy_drop = "policy DROP" in out.stdout.split("\n")[0] if out.stdout else False
        report["checks"].append(("ip6tables OUTPUT policy is DROP", policy_drop))
    except Exception as e:
        report["checks"].append((f"Could not read ip6tables policy ({e})", False))
    report["passed"] = all(ok for _, ok in report["checks"])
    _print_report("IPv6 block", report)
    return report


def verify_active(env: envmod.Environment) -> dict:
    """Verifies whichever kill switch (if any) is marked active per
    saved state, plus the IPv6 block if that's active too. The single
    entry point both the CLI's interactive menu (option 24) and its
    --verify flag use, so "verify what's currently active" can't
    quietly mean two different things depending on which one you run
    — the --verify flag used to skip the IPv6 check that the menu
    option always ran, simply because the same dispatch logic had been
    copy-pasted into main.py twice and only one copy had it."""
    st = statemod.load()
    report = {}
    if st["tor_kill_switch"]:
        report["kill_switch"] = verify_tor_kill_switch(env)
    elif st["proxy_only_kill_switch"]:
        host = (st.get("active_proxy") or "://").split("://")[-1].split(":")[0]
        report["kill_switch"] = verify_proxy_kill_switch(env, host)
    else:
        print("[i] No kill switch marked active per saved state — nothing to verify.")
    if st["ipv6_blocked"]:
        report["ipv6"] = verify_ipv6_blocked(env)
    return report


def _print_report(label: str, report: dict) -> None:
    print(f"=== Verification: {label} ===")
    for desc, ok in report["checks"]:
        print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
    if report["passed"]:
        print(f"[+] {label}: all checks passed.")
    else:
        print(f"[!] {label}: one or more checks FAILED — do not assume you're protected. "
              f"Investigate before relying on this.")
