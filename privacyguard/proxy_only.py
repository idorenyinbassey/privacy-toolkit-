"""
Route traffic through a plain SOCKS5/HTTP proxy WITHOUT Tor — useful
when a target network or host actively blocks/drops Tor traffic.

Two levels:
1. App-level, works everywhere, no root: proxychains with no Tor entry
   — see proxy_tor.generate_proxychains_conf(..., include_tor=False).
2. System-wide, full Linux + root only: redsocks transparently
   redirects all outbound TCP through your proxy at the kernel level.

Limitation (same as the Tor kill switch): TCP only. UDP/DNS is NOT
tunneled by redsocks alone — always run a DNS leak check after
enabling this.

Production hardening: idempotent (checks state before re-applying),
backs up the nat table before flushing it and restores that exact
backup on disable, and supports proxy authentication (redsocks'
login/password fields for socks5 and http-connect).
"""
import socket
import subprocess
from pathlib import Path

from . import environment as envmod
from . import core as coremod
from . import state as statemod
from . import firewall_backup

REDSOCKS_CONF = Path("/etc/redsocks.conf")
REDSOCKS_LOCAL_PORT = 12345


def generate_redsocks_conf(proxy_host: str, proxy_port: int, proxy_type: str = "socks5",
                            username: str = None, password: str = None) -> None:
    if proxy_type not in ("socks5", "socks4", "http-connect", "http-relay"):
        proxy_type = "socks5"
    auth_lines = ""
    if username and password:
        auth_lines = f'    login = "{username}";\n    password = "{password}";\n'
    elif username or password:
        print("[!] Both username and password are needed for proxy auth — ignoring the partial value given.")

    conf = f"""base {{
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    redirector = iptables;
}}

redsocks {{
    local_ip = 127.0.0.1;
    local_port = {REDSOCKS_LOCAL_PORT};
    ip = {proxy_host};
    port = {proxy_port};
    type = {proxy_type};
{auth_lines}}}
"""
    REDSOCKS_CONF.write_text(conf)
    auth_note = " (authenticated)" if username and password else ""
    print(f"[+] Wrote {REDSOCKS_CONF} -> {proxy_host}:{proxy_port} ({proxy_type}){auth_note}")


def _proxy_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def enable_proxy_kill_switch(env: envmod.Environment, proxy_host: str, proxy_port: int,
                              proxy_type: str = "socks5", username: str = None, password: str = None,
                              force: bool = False) -> bool:
    """Returns True only if the kill switch was actually applied."""
    if env.termux:
        print("[!] System-wide proxy routing needs root/netfilter — unavailable in Termux.")
        print("    Use proxychains (include_tor=False) to wrap individual commands instead.")
        return False
    if not env.root or not env.has_iptables:
        print("[!] Needs root + iptables.")
        return False
    if not envmod.have("redsocks"):
        print("[!] redsocks not installed. sudo apt install redsocks")
        return False

    # Fix the same failure mode as the Tor kill switch: redirecting all
    # traffic to a proxy that isn't actually reachable = total internet
    # loss with no path out. Verify BEFORE touching iptables.
    if not _proxy_reachable(proxy_host, proxy_port):
        print(f"[!] Could not reach {proxy_host}:{proxy_port} — NOT enabling the kill switch. "
              f"Doing so now would drop all internet access with no working proxy path to replace it.")
        print("    Double-check the host/port/credentials and that the proxy is actually up.")
        return False

    st = statemod.load()
    if st["proxy_only_kill_switch"] and not force:
        print("[i] Proxy-only kill switch already active (per saved state). Disable it first, "
              "or call with force=True to re-apply.")
        return True  # already genuinely active, not a failure
    if st["tor_kill_switch"]:
        print("[!] Tor kill switch is currently active — disable that first "
              "(both rewrite the same OUTPUT chain and will conflict).")
        return False

    backups = firewall_backup.backup_rules(env, label="pre-proxy-killswitch")

    generate_redsocks_conf(proxy_host, proxy_port, proxy_type, username, password)
    started = subprocess.run(["systemctl", "restart", "redsocks"], capture_output=True)
    if started.returncode != 0:
        subprocess.Popen(["redsocks", "-c", str(REDSOCKS_CONF)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    rules = [
        ["iptables", "-t", "nat", "-N", "PG_REDSOCKS"],
        ["iptables", "-t", "nat", "-A", "PG_REDSOCKS", "-d", "127.0.0.0/8", "-j", "RETURN"],
        ["iptables", "-t", "nat", "-A", "PG_REDSOCKS", "-p", "tcp", "-j", "REDIRECT",
         "--to-ports", str(REDSOCKS_LOCAL_PORT)],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PG_REDSOCKS"],
    ]
    ok = True
    for r in rules:
        res = subprocess.run(r, capture_output=True, text=True)
        if res.returncode != 0 and "Chain already exists" not in res.stderr:
            print(f"[!] {' '.join(r)} -> {res.stderr.strip()}")
            ok = False
    if ok:
        print(f"[+] All outbound TCP now routed through {proxy_host}:{proxy_port} — no Tor in the path.")
        print("[!] UDP/DNS is NOT covered by this. Run the DNS leak check next.")
        statemod.update(proxy_only_kill_switch=True, nat_iptables_backup=backups["ipv4"],
                         ip6tables_backup=backups["ipv6"], active_proxy=f"{proxy_type}://{proxy_host}:{proxy_port}")
    else:
        print("[!] Rule application had errors — restoring pre-existing rules.")
        firewall_backup.restore_rules(env, backups["ipv4"], backups["ipv6"])
        return False
    coremod.block_ipv6(env)
    return True


def disable_proxy_kill_switch(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    st = statemod.load()
    if not st["proxy_only_kill_switch"]:
        print("[i] Proxy-only kill switch not marked active (per saved state) — nothing to disable.")
        return
    firewall_backup.restore_rules(env, st.get("nat_iptables_backup"), st.get("ip6tables_backup"))
    subprocess.run(["systemctl", "stop", "redsocks"], capture_output=True)
    statemod.update(proxy_only_kill_switch=False, ipv6_blocked=False, nat_iptables_backup=None,
                     ip6tables_backup=None, active_proxy=None)
    print("[+] Proxy-only kill switch disabled, prior firewall state restored.")
