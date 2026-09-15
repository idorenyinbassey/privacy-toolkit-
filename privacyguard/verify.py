"""
Verification: every enable_* function so far has trusted "the iptables
command returned 0" to mean the protection actually works. That's not
proof — rule ordering bugs, a NAT table quirk, or Tor not having
finished bootstrapping yet can all leave you "protected" on paper and
leaking in practice. This module actually tests the live behavior.
"""
import socket
import subprocess
import urllib.request

from . import environment as envmod
from . import proxy_tor, dns_check


def _direct_tcp_probe(host: str = "1.1.1.1", port: int = 80, timeout: float = 4.0) -> bool:
    """True if a direct (non-tunneled) TCP connection succeeds. Used to
    prove a kill switch is actually blocking direct traffic — if this
    succeeds while a kill switch claims to be active, that's a leak."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def verify_tor_kill_switch(env: envmod.Environment) -> dict:
    """Returns a dict report; also prints a human-readable summary."""
    report = {"checks": []}

    direct_ok = _direct_tcp_probe()
    report["checks"].append(("Direct (non-Tor) TCP connection blocked", not direct_ok))

    tor_check = proxy_tor.check_tor_active()
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

    direct_ok = _direct_tcp_probe()
    report["checks"].append(("Direct (non-proxy) TCP connection blocked", not direct_ok))

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


def _print_report(label: str, report: dict) -> None:
    print(f"=== Verification: {label} ===")
    for desc, ok in report["checks"]:
        print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
    if report["passed"]:
        print(f"[+] {label}: all checks passed.")
    else:
        print(f"[!] {label}: one or more checks FAILED — do not assume you're protected. "
              f"Investigate before relying on this.")
