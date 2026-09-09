"""
Defensive countermeasures against active recon/scanning tools aimed AT
this machine (nmap, nikto, generic curl/HTTP probing, Metasploit's
network-level scanning modules).

Honest scope: there's no way to "block Metasploit" as a product — an
exploit module just sends traffic like any client. What actually works,
and what this module implements, is generic and effective against all
of them:
  1. Reduce your fingerprint surface (silence ICMP, disable TCP
     timestamps that leak uptime, drop banner-revealing behavior).
  2. Detect scan-shaped traffic (many ports/paths hit by one source in
     a short window) and auto rate-limit/block that source.
Both require root + iptables on full Linux. Termux has neither root
nor netfilter, so on Termux this module can only do *application-layer*
log watching (e.g. for a Flask app you're running) and alerting — it
cannot firewall anything.
"""
import re
import subprocess
import time
from collections import defaultdict, deque

from . import environment as envmod


# --------------------------------------------------------------------
# Fingerprint reduction (full Linux, root)
# --------------------------------------------------------------------

STEALTH_SYSCTLS = {
    "net.ipv4.icmp_echo_ignore_all": "1",       # don't answer ping
    "net.ipv4.tcp_timestamps": "0",              # hides uptime, aids OS fingerprint evasion
    "net.ipv4.conf.all.log_martians": "1",       # log spoofed/weird packets aimed at you
    "net.ipv4.conf.all.rp_filter": "1",          # reverse-path filtering
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
}


def enable_stealth_sysctls(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_sysctl:
        print("[!] Sysctl fingerprint hardening needs root + full Linux — skipped.")
        return
    for key, val in STEALTH_SYSCTLS.items():
        try:
            subprocess.run(["sysctl", "-w", f"{key}={val}"], check=True, capture_output=True)
            print(f"[+] {key} = {val}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to set {key}: {e}")


def disable_stealth_sysctls(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_sysctl:
        return
    defaults = {
        "net.ipv4.icmp_echo_ignore_all": "0",
        "net.ipv4.tcp_timestamps": "1",
        "net.ipv4.conf.all.log_martians": "0",
    }
    for key, val in defaults.items():
        subprocess.run(["sysctl", "-w", f"{key}={val}"], check=False, capture_output=True)
    print("[+] Reverted fingerprint-hardening sysctls to typical defaults.")


# --------------------------------------------------------------------
# iptables portscan detection/auto-block (full Linux, root)
# Classic "recent module" ruleset: if a source sends more than
# --hitcount SYNs within --seconds, it gets logged then dropped.
# --------------------------------------------------------------------

def enable_portscan_protection(env: envmod.Environment, hitcount: int = 15, seconds: int = 60) -> None:
    if env.termux:
        print("[!] No netfilter in Termux — can't block at the firewall level.")
        print("    Use the log-watch option instead for your Termux-hosted services.")
        return
    if not env.root or not env.has_iptables:
        print("[!] Portscan protection needs root + iptables.")
        return
    cmds = [
        ["iptables", "-N", "PG_PORTSCAN"],
        ["iptables", "-F", "PG_PORTSCAN"],
        ["iptables", "-A", "PG_PORTSCAN", "-m", "recent", "--name", "pg_scan", "--set",
         "-j", "LOG", "--log-prefix", "PrivacyGuard-SCAN-BLOCK: "],
        ["iptables", "-A", "PG_PORTSCAN", "-j", "DROP"],
        ["iptables", "-I", "INPUT", "-p", "tcp", "--syn", "-m", "recent", "--name", "pg_scan",
         "--update", "--seconds", str(seconds), "--hitcount", str(hitcount), "-j", "PG_PORTSCAN"],
        ["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "recent", "--name", "pg_scan", "--set", "-j", "ACCEPT"],
    ]
    ok = True
    for c in cmds:
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0 and "Chain already exists" not in r.stderr:
            print(f"[!] {' '.join(c)} -> {r.stderr.strip()}")
            ok = False
    if ok:
        print(f"[+] Portscan protection active: > {hitcount} new connections from one source "
              f"within {seconds}s gets logged + dropped.")
        print("    Tune hitcount/seconds if legitimate traffic trips it.")


def disable_portscan_protection(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--syn", "-m", "recent", "--name", "pg_scan",
                     "--update", "--seconds", "60", "--hitcount", "15", "-j", "PG_PORTSCAN"], capture_output=True)
    subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--syn", "-m", "recent", "--name", "pg_scan",
                     "--set", "-j", "ACCEPT"], capture_output=True)
    subprocess.run(["iptables", "-F", "PG_PORTSCAN"], capture_output=True)
    subprocess.run(["iptables", "-X", "PG_PORTSCAN"], capture_output=True)
    print("[+] Portscan protection rules removed.")


# --------------------------------------------------------------------
# Optional live packet-based scan detector (scapy) — full Linux, root.
# Flags a source IP once it touches > port_threshold distinct ports
# within window_seconds, then optionally auto-blocks it via iptables.
# --------------------------------------------------------------------

def live_scan_watch(env: envmod.Environment, port_threshold: int = 8, window_seconds: int = 10,
                     auto_block: bool = False, duration: int = 120) -> None:
    if env.termux:
        print("[!] Live packet sniffing needs root/netfilter — not available in Termux.")
        return
    if not env.has_scapy:
        print("[!] scapy not installed. pip install scapy --break-system-packages")
        return
    if not env.root:
        print("[!] Packet sniffing needs root.")
        return

    from scapy.all import sniff, TCP, IP  # type: ignore

    hits = defaultdict(lambda: deque())  # src_ip -> deque[(ts, port)]
    blocked = set()

    def block(ip: str) -> None:
        if ip in blocked or not env.has_iptables:
            return
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        blocked.add(ip)
        print(f"[BLOCK] {ip} — port-scan pattern detected, dropped.")

    def handle(pkt):
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dport = pkt[TCP].dport
            now = time.time()
            dq = hits[src]
            dq.append((now, dport))
            while dq and now - dq[0][0] > window_seconds:
                dq.popleft()
            distinct_ports = {p for _, p in dq}
            if len(distinct_ports) >= port_threshold:
                print(f"[ALERT] {src} touched {len(distinct_ports)} distinct ports in "
                      f"{window_seconds}s — looks like a scan (nmap/nikto-style).")
                if auto_block:
                    block(src)
                dq.clear()

    print(f"[*] Watching traffic for {duration}s (threshold={port_threshold} ports/{window_seconds}s, "
          f"auto_block={auto_block})... Ctrl+C to stop early.")
    try:
        sniff(prn=handle, store=False, timeout=duration)
    except PermissionError:
        print("[!] Sniffing needs root.")
    except KeyboardInterrupt:
        pass
    print("[*] Scan watch finished.")


# --------------------------------------------------------------------
# Application-layer watch for Termux-hosted services (e.g. your Flask
# OSINT tracker) — no blocking capability, alert-only, no root needed.
# --------------------------------------------------------------------

NIKTO_SIGNS = [r"nikto", r"\.\./", r"/etc/passwd", r"/wp-login", r"sqlmap", r"nmap scripting engine"]


def watch_http_access_log(log_path: str, window_seconds: int = 10, burst_threshold: int = 20,
                           stop_event=None) -> None:
    """Tail an access log (Flask/nginx style) and flag scan-like bursts
    or known scanner signatures. Alert-only — no auto-block, since
    Termux has no firewall to enforce one. Pass a threading.Event as
    stop_event to allow a GUI/caller to stop the loop cleanly."""
    import os
    pattern = re.compile("|".join(NIKTO_SIGNS), re.IGNORECASE)
    hits = deque()
    print(f"[*] Watching {log_path} (Ctrl+C to stop)...")
    try:
        with open(log_path, "r") as f:
            f.seek(0, os.SEEK_END)
            while not (stop_event and stop_event.is_set()):
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                now = time.time()
                hits.append(now)
                while hits and now - hits[0] > window_seconds:
                    hits.popleft()
                if pattern.search(line):
                    print(f"[ALERT] Known scanner signature in request: {line.strip()[:200]}")
                if len(hits) >= burst_threshold:
                    print(f"[ALERT] {len(hits)} requests in {window_seconds}s — burst/scan-like traffic.")
                    hits.clear()
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
    except KeyboardInterrupt:
        print("\n[*] Stopped watching.")
