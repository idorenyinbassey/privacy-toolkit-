"""
Workstation VM configuration — run this INSIDE the workstation VM (the
one with a single NIC, wired by gateway_topology.py to the internal
network only).

There's deliberately not much to configure here: point this VM's
default route and DNS at the gateway's internal IP. The actual
security property — no path to the internet except through the
gateway — comes from the network topology (one interface, no other
route exists), not from anything this module enforces in software.
That's the whole point: a compromised workstation can't route around
software-level restrictions that were never the thing providing the
isolation in the first place.

verify_isolation() checks that reality matches that assumption: one
interface, one route, DNS pointed only at the gateway.
"""
import subprocess
from pathlib import Path

from . import environment as envmod
from . import state as statemod


def configure_networking(env: envmod.Environment, iface: str, static_ip: str, gateway_ip: str,
                          cidr_prefix: int = 24) -> None:
    if env.termux:
        print("[!] Workstation network config needs root + full Linux — unavailable in Termux.")
        return
    if not env.root:
        print("[!] Requires root.")
        return
    try:
        subprocess.run(["ip", "addr", "flush", "dev", iface], check=True)
        subprocess.run(["ip", "addr", "add", f"{static_ip}/{cidr_prefix}", "dev", iface], check=True)
        subprocess.run(["ip", "link", "set", "dev", iface, "up"], check=True)
        subprocess.run(["ip", "route", "add", "default", "via", gateway_ip], check=True)
        Path("/etc/resolv.conf").write_text(f"nameserver {gateway_ip}\n")
        print(f"[+] {iface} set to {static_ip}/{cidr_prefix}, default route + DNS -> {gateway_ip}")
        statemod.update(workstation_configured=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to configure workstation networking: {e}")


def verify_isolation(env: envmod.Environment, expected_gateway_ip: str = None) -> dict:
    """Confirms the topology actually gives this VM no path to the
    internet except via the gateway — checks interface count, default
    route, and DNS configuration."""
    report = {"checks": []}

    try:
        out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True)
        non_lo = [l for l in out.stdout.splitlines() if ": lo:" not in l and l.strip()]
        report["interfaces"] = len(non_lo)
        report["checks"].append((f"Exactly one non-loopback interface (found {len(non_lo)})",
                                  len(non_lo) == 1))
    except Exception as e:
        report["checks"].append((f"Could not enumerate interfaces ({e})", False))

    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=True)
        routes = out.stdout.strip().splitlines()
        report["default_routes"] = routes
        one_route = len(routes) == 1
        report["checks"].append((f"Exactly one default route (found {len(routes)})", one_route))
        if expected_gateway_ip and routes:
            matches = expected_gateway_ip in routes[0]
            report["checks"].append((f"Default route points at expected gateway {expected_gateway_ip}", matches))
    except Exception as e:
        report["checks"].append((f"Could not read default route ({e})", False))

    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        servers = [l.split()[1] for l in resolv.read_text().splitlines() if l.strip().startswith("nameserver")]
        report["dns_servers"] = servers
        single_dns = len(set(servers)) <= 1
        report["checks"].append((f"DNS points at a single resolver only (found {set(servers)})", single_dns))
        if expected_gateway_ip:
            report["checks"].append((f"DNS resolver is the expected gateway {expected_gateway_ip}",
                                      servers == [expected_gateway_ip]))

    report["passed"] = all(ok for _, ok in report["checks"])
    print("=== Workstation isolation check ===")
    for desc, ok in report["checks"]:
        print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
    if report["passed"]:
        print("[+] Topology looks correctly isolated — no apparent path to the internet except the gateway.")
    else:
        print("[!] One or more checks failed. A second interface or an extra route/resolver would be a "
              "real gap — go recheck the VM's network adapter settings on the HOST before trusting this.")
    return report
