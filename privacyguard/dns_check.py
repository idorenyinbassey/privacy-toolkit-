"""
DNS leak detection.

A "DNS leak" means your DNS queries go out through your normal ISP
resolver (revealing what you're looking up, and confirming your real
IP to whoever runs that resolver) even though your actual traffic is
going through Tor/a proxy/VPN.

Two checks are combined here:
1. Are any *non-local* resolvers configured in /etc/resolv.conf while
   a tunnel is supposed to be active? (should be 127.0.0.1 / a local
   stub only)
2. A live check using Google's CHAOS-class TXT trick
   (o-o.myaddr.l.google.com) which reveals the IP of whichever
   resolver actually asked Google's authoritative server on your
   behalf — this exposes leaks even through NAT/local stub resolvers
   that forward elsewhere.
"""
import shutil
import subprocess
from pathlib import Path

from . import environment as envmod
from . import proxy_tor


def configured_resolvers() -> list:
    servers = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        try:
            for line in resolv.read_text().splitlines():
                if line.strip().startswith("nameserver"):
                    servers.append(line.split()[1])
        except Exception:
            pass
    return servers


def _dig(args: list, timeout: int = 8):
    if not shutil.which("dig"):
        return None
    try:
        out = subprocess.run(["dig", "+short", "+time=5"] + args, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip() or None
    except Exception:
        return None


def resolver_identifying_ip():
    result = _dig(["-c", "CHAOS", "-t", "TXT", "o-o.myaddr.l.google.com"])
    if result:
        return result.strip('"')
    return None


def dns_leak_check(env: envmod.Environment, expect_local_only: bool = False) -> dict:
    """expect_local_only=True when a tunnel (Tor kill switch or
    proxy-only kill switch) is supposed to be active — any non-local
    resolver in that case is flagged as a likely leak."""
    report = {}
    resolvers = configured_resolvers()
    report["configured_resolvers"] = resolvers

    non_local = [r for r in resolvers if not r.startswith("127.") and r != "::1"]
    report["non_local_resolvers"] = non_local

    if expect_local_only and non_local:
        report["leak_verdict"] = ("LIKELY LEAKING — non-local resolver(s) configured while a tunnel "
                                   "is supposed to be active.")
    elif non_local:
        report["leak_verdict"] = "No tunnel claimed active — resolvers going direct (expected)."
    else:
        report["leak_verdict"] = ("All configured resolvers are local/loopback (good — assuming the "
                                   "local stub genuinely forwards through your tunnel).")

    resolver_ip = resolver_identifying_ip()
    report["resolver_identifying_ip"] = resolver_ip or "unavailable (install `dig`, or query was blocked)"

    tor_check = proxy_tor.check_tor_active()
    if "error" not in tor_check:
        report["tor_exit_ip"] = tor_check.get("IP")
        if resolver_ip and tor_check.get("IsTor") and resolver_ip != tor_check.get("IP"):
            report["tor_dns_note"] = ("Resolver-identifying IP differs from your Tor exit IP — this is "
                                       "normal (DNS-over-Tor is often answered via a different relay than "
                                       "your traffic circuit), not proof of a leak by itself.")
    return report


def print_dns_leak_report(env: envmod.Environment, expect_local_only: bool = False) -> None:
    r = dns_leak_check(env, expect_local_only=expect_local_only)
    print("=== DNS Leak Check ===")
    print(f"Configured resolvers : {', '.join(r['configured_resolvers']) or 'none readable'}")
    print(f"Non-local resolvers  : {', '.join(r['non_local_resolvers']) or 'none'}")
    print(f"Resolver-identifying IP (Google CHAOS TXT): {r['resolver_identifying_ip']}")
    if "tor_exit_ip" in r:
        print(f"Tor exit IP          : {r['tor_exit_ip']}")
    if "tor_dns_note" in r:
        print(f"Note                 : {r['tor_dns_note']}")
    print(f"Verdict              : {r['leak_verdict']}")
    if not shutil.which("dig"):
        print("[i] Install `dig` (dnsutils on Debian, dnsutils/bind-tools on Termux) for the live check.")
