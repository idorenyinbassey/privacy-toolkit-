"""
Route traffic through a plain SOCKS5/HTTP proxy WITHOUT Tor — useful
when a target network or host actively blocks/drops Tor traffic
(Tor's TLS fingerprint and known relay IPs are commonly blocklisted,
even when ordinary proxy traffic isn't).

Two levels:

1. App-level, works everywhere, no root: wrap a single command with
   proxychains using a config that has NO Tor entry — see
   proxy_tor.generate_proxychains_conf(..., include_tor=False).

2. System-wide, full Linux + root only: redsocks transparently
   redirects all outbound TCP through your proxy at the kernel level
   — the non-Tor equivalent of the Tor kill switch.

Limitation (same as the Tor kill switch, worth repeating): this only
covers TCP. UDP/DNS is NOT tunneled by redsocks alone — always run a
DNS leak check after enabling this, and either point resolv.conf at a
resolver reachable through the proxy or accept that gap knowingly.
"""
import subprocess
from pathlib import Path

from . import environment as envmod
from . import core as coremod

REDSOCKS_CONF = Path("/etc/redsocks.conf")
REDSOCKS_LOCAL_PORT = 12345


def generate_redsocks_conf(proxy_host: str, proxy_port: int, proxy_type: str = "socks5") -> None:
    if proxy_type not in ("socks5", "socks4", "http-connect", "http-relay"):
        proxy_type = "socks5"
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
}}
"""
    REDSOCKS_CONF.write_text(conf)
    print(f"[+] Wrote {REDSOCKS_CONF} -> {proxy_host}:{proxy_port} ({proxy_type})")


def enable_proxy_kill_switch(env: envmod.Environment, proxy_host: str, proxy_port: int,
                              proxy_type: str = "socks5") -> None:
    if env.termux:
        print("[!] System-wide proxy routing needs root/netfilter — unavailable in Termux.")
        print("    Use proxychains (include_tor=False) to wrap individual commands instead.")
        return
    if not env.root or not env.has_iptables:
        print("[!] Needs root + iptables.")
        return
    if not envmod.have("redsocks"):
        print("[!] redsocks not installed. sudo apt install redsocks")
        return

    generate_redsocks_conf(proxy_host, proxy_port, proxy_type)
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
    coremod.block_ipv6(env)


def disable_proxy_kill_switch(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    subprocess.run(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "PG_REDSOCKS"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F", "PG_REDSOCKS"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-X", "PG_REDSOCKS"], capture_output=True)
    subprocess.run(["systemctl", "stop", "redsocks"], capture_output=True)
    coremod.unblock_ipv6(env)
    print("[+] Proxy-only kill switch disabled.")
