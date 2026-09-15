"""
Gateway VM configuration — run this INSIDE the Tor gateway VM (the one
with two NICs: one to the internet, one internal to the workstation).

What this sets up is a transparent Tor router for the internal
network: any TCP SYN or DNS query arriving from the workstation on the
internal interface gets REDIRECTed to this VM's local Tor TransPort/
DNSPort — the same mechanism as the single-machine kill switch in
core.py, just applied to traffic arriving from another machine instead
of traffic leaving this one.

The property that makes this safe is an ABSENCE, not a rule: there is
no MASQUERADE/FORWARD-ACCEPT rule sending workstation traffic straight
to the external interface. The FORWARD chain's default policy is DROP.
So workstation traffic either gets caught by the REDIRECT rules and
goes through Tor, or it hits the FORWARD DROP and goes nowhere — there
is no third path where it reaches the internet unencrypted/unrouted
through Tor. Same fail-closed philosophy as everything else in this
toolkit.

Idempotent and backed up the same way as core.py's kill switch —
enabling twice is a no-op, disabling restores the pre-existing
ruleset rather than guessing.
"""
import subprocess
from pathlib import Path

from . import environment as envmod
from . import state as statemod
from . import firewall_backup
from . import core as coremod

TRANS_PORT = 9040
DNS_PORT = 5353


def _write_gateway_torrc_snippet(internal_ip: str, torrc_path: Path = None) -> None:
    """Appends (or updates) the lines needed for Tor to accept
    transparent-proxy traffic on the internal interface, not just
    loopback. Idempotent — replaces its own prior block if present."""
    path = torrc_path or Path("/etc/tor/torrc")
    marker_start = "# --- PrivacyGuard gateway mode (managed block) ---"
    marker_end = "# --- end PrivacyGuard gateway mode ---"
    block = (
        f"{marker_start}\n"
        f"TransPort 127.0.0.1:{TRANS_PORT}\n"
        f"TransPort {internal_ip}:{TRANS_PORT}\n"
        f"DNSPort 127.0.0.1:{DNS_PORT}\n"
        f"DNSPort {internal_ip}:{DNS_PORT}\n"
        f"AutomapHostsOnResolve 1\n"
        f"{marker_end}\n"
    )
    existing = path.read_text() if path.exists() else ""
    if marker_start in existing:
        pre = existing.split(marker_start)[0]
        post = existing.split(marker_end)[-1]
        new_content = pre + block + post
    else:
        new_content = existing.rstrip("\n") + "\n\n" + block
    path.write_text(new_content)
    print(f"[+] Updated {path} with gateway TransPort/DNSPort bindings on {internal_ip}.")
    print("    Restart tor for this to take effect: sudo systemctl restart tor")


def enable_gateway(env: envmod.Environment, internal_iface: str, internal_ip: str,
                    external_iface: str = None, force: bool = False) -> None:
    if env.termux:
        print("[!] Gateway mode needs root/netfilter — unavailable in Termux.")
        return
    if not env.root or not env.has_iptables:
        print("[!] Gateway mode requires root + iptables.")
        return
    if not env.has_tor:
        print("[!] Tor not installed on this VM — it must run Tor to act as the gateway.")
        return

    st = statemod.load()
    if st["gateway_mode_active"] and not force:
        print("[i] Gateway mode already active (per saved state). Disable it first, "
              "or call with force=True to re-apply.")
        return
    if st["tor_kill_switch"] or st["proxy_only_kill_switch"]:
        print("[!] A single-machine kill switch is active on this VM — disable it first. "
              "Gateway mode manages its own OUTPUT rules for this VM's own traffic.")
        return

    _write_gateway_torrc_snippet(internal_ip)

    backups = firewall_backup.backup_rules(env, label="pre-gateway-mode")

    rules = [
        # This VM's OWN traffic also goes through Tor only (reuses the
        # same fail-closed OUTPUT policy as the single-machine kill switch).
        ["iptables", "-F"], ["iptables", "-t", "nat", "-F"], ["iptables", "-F", "FORWARD"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", coremod.TOR_UID_PLACEHOLDER, "-j", "ACCEPT"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", str(TRANS_PORT)],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT)],
        ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(TRANS_PORT), "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-j", "DROP"],

        # The workstation's traffic, arriving on the internal interface:
        # redirect to this VM's own Tor ports (PREROUTING REDIRECT makes
        # it locally-destined, so it never reaches the FORWARD chain).
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", internal_iface, "-p", "tcp",
         "--syn", "-j", "REDIRECT", "--to-ports", str(TRANS_PORT)],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", internal_iface, "-p", "udp",
         "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT)],

        # The absence that matters: NO MASQUERADE/FORWARD-ACCEPT rule
        # exists anywhere here. Default-DROP the FORWARD chain so
        # anything that isn't caught by the REDIRECT rules above (e.g.
        # a non-TCP, non-DNS-53 protocol) goes nowhere instead of
        # reaching the external interface directly.
        ["iptables", "-P", "FORWARD", "DROP"],
        ["iptables", "-A", "FORWARD", "-j", "DROP"],

        # Accept the workstation's redirected connections on INPUT
        # (they're now locally-destined after the REDIRECT).
        ["iptables", "-A", "INPUT", "-i", internal_iface, "-p", "tcp", "--dport", str(TRANS_PORT), "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT", "-i", internal_iface, "-p", "udp", "--dport", str(DNS_PORT), "-j", "ACCEPT"],
    ]
    print(f"[*] Configuring gateway mode: internal={internal_iface} ({internal_ip}), "
          f"external={external_iface or '(unspecified — only need it for reference, not for these rules)'}")
    ok = True
    for rule in rules:
        try:
            subprocess.run(rule, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Rule failed: {' '.join(rule)} -> {e}")
            ok = False
    if not ok:
        print("[!] Gateway rule application had errors — restoring pre-existing rules.")
        firewall_backup.restore_rules(env, backups["ipv4"], backups["ipv6"])
        return

    # IPv6: block forwarding entirely rather than try to transparently
    # proxy it (Tor's transparent-proxy support here is IPv4-focused).
    ip6_ok = True
    if env.has_ip6tables:
        for r in (["ip6tables", "-P", "FORWARD", "DROP"], ["ip6tables", "-F", "FORWARD"]):
            res = subprocess.run(r, capture_output=True, text=True)
            if res.returncode != 0:
                ip6_ok = False
        if not ip6_ok:
            print("[!] Could not fully lock down ip6tables FORWARD — check manually before trusting IPv6 isolation.")

    print("[+] Gateway mode active. Workstation traffic on the internal interface is redirected "
          "into Tor; nothing is forwarded directly to the external interface.")
    statemod.update(gateway_mode_active=True, gateway_iptables_backup=backups["ipv4"],
                     gateway_ip6tables_backup=backups["ipv6"],
                     gateway_config={"internal_iface": internal_iface, "internal_ip": internal_ip,
                                     "external_iface": external_iface})
    coremod.block_ipv6(env)


def disable_gateway(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    st = statemod.load()
    if not st["gateway_mode_active"]:
        print("[i] Gateway mode not marked active (per saved state) — nothing to disable.")
        return
    firewall_backup.restore_rules(env, st.get("gateway_iptables_backup"), st.get("gateway_ip6tables_backup"))
    statemod.update(gateway_mode_active=False, ipv6_blocked=False, gateway_iptables_backup=None,
                     gateway_ip6tables_backup=None, gateway_config=None)
    print("[+] Gateway mode disabled, prior firewall state restored.")


def gateway_status() -> dict:
    return statemod.load().get("gateway_config") or {}
