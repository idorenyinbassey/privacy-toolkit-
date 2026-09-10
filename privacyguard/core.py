"""Core anonymity actions: MAC/hostname randomization, Tor kill switch, trace cleanup."""
import random
import subprocess
from pathlib import Path

from . import environment as envmod

TOR_UID_PLACEHOLDER = "debian-tor"


def random_mac() -> str:
    first = random.choice([0x02, 0x06, 0x0A, 0x0E])
    rest = [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first] + rest)


def randomize_mac(env: envmod.Environment, iface: str) -> None:
    if env.termux:
        print("[!] MAC randomization needs root/netfilter — not available in Termux.")
        return
    if not env.root:
        print("[!] MAC randomization requires root.")
        return
    new_mac = random_mac()
    try:
        subprocess.run(["ip", "link", "set", "dev", iface, "down"], check=True)
        if env.has_macchanger:
            subprocess.run(["macchanger", "-m", new_mac, iface], check=True)
        else:
            subprocess.run(["ip", "link", "set", "dev", iface, "address", new_mac], check=True)
        subprocess.run(["ip", "link", "set", "dev", iface, "up"], check=True)
        print(f"[+] {iface} MAC set to {new_mac}")
    except subprocess.CalledProcessError as e:
        print(f"[!] MAC randomization failed on {iface}: {e}")


ADJECTIVES = ["quiet", "amber", "lunar", "cobalt", "hidden", "swift", "gray", "silent"]
NOUNS = ["desk", "station", "node", "host", "unit", "box", "term", "relay"]


def random_hostname() -> str:
    return f"{random.choice(ADJECTIVES)}-{random.choice(NOUNS)}-{random.randint(100, 999)}"


def randomize_hostname(env: envmod.Environment) -> None:
    if env.termux:
        print("[!] Hostname change has no effect in the Termux sandbox.")
        return
    if not env.root:
        print("[!] Hostname change requires root.")
        return
    new_host = random_hostname()
    try:
        subprocess.run(["hostnamectl", "set-hostname", new_host], check=True)
        print(f"[+] Hostname set to {new_host}")
    except subprocess.CalledProcessError:
        try:
            subprocess.run(["hostname", new_host], check=True)
            print(f"[+] Hostname set to {new_host} (session only)")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to set hostname: {e}")


def block_ipv6(env: envmod.Environment) -> None:
    """AnonSurf-style IPv6 leak protection: IPv6 has historically been
    able to leak around IPv4-only iptables kill switches, and can also
    carry a permanent MAC-derived address. Block it outright while a
    kill switch is active."""
    if env.termux or not env.root or not env.has_ip6tables:
        print("[!] IPv6 blocking needs root + ip6tables (full Linux only) — skipped.")
        return
    try:
        subprocess.run(["ip6tables", "-F"], check=True)
        subprocess.run(["ip6tables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "DROP"], check=True)
        subprocess.run(["ip6tables", "-P", "FORWARD", "DROP"], check=True)
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        print("[+] IPv6 blocked (prevents IPv6 traffic leaking around the IPv4-only kill switch).")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block IPv6: {e}")


def unblock_ipv6(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_ip6tables:
        return
    try:
        subprocess.run(["ip6tables", "-F"], check=True)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], check=True)
        print("[+] IPv6 traffic restored to normal.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to restore IPv6: {e}")


def enable_kill_switch(env: envmod.Environment) -> None:
    if env.termux:
        print("[!] Kill switch needs iptables — unavailable in Termux. Use Orbot VPN mode instead.")
        return
    if not env.root or not env.has_iptables:
        print("[!] Kill switch requires root + iptables.")
        return
    rules = [
        ["iptables", "-F"], ["iptables", "-t", "nat", "-F"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", TOR_UID_PLACEHOLDER, "-j", "ACCEPT"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", "9040"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"],
        ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "9040", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-j", "DROP"],
    ]
    print("[*] Applying kill-switch rules. Requires torrc: TransPort 9040 / DNSPort 5353.")
    ok = True
    for rule in rules:
        try:
            subprocess.run(rule, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Rule failed: {' '.join(rule)} -> {e}")
            ok = False
    if ok:
        print("[+] Kill switch active — only loopback + Tor traffic allowed out.")
    block_ipv6(env)


def disable_kill_switch(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    try:
        subprocess.run(["iptables", "-F"], check=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        print("[+] iptables flushed — normal routing restored.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to flush iptables: {e}")
    unblock_ipv6(env)


CLEANUP_TARGETS_LINUX = ["~/.bash_history", "~/.zsh_history", "~/.python_history", "~/.wget-hsts", "~/.lesshst"]
CLEANUP_TARGETS_TERMUX = ["~/.bash_history", "~/.python_history"]


def clean_traces(env: envmod.Environment, wipe_logs: bool = False) -> None:
    targets = CLEANUP_TARGETS_TERMUX if env.termux else CLEANUP_TARGETS_LINUX
    for t in targets:
        p = Path(t).expanduser()
        if p.exists():
            try:
                p.write_text("")
                print(f"[+] Cleared {p}")
            except Exception as e:
                print(f"[!] Could not clear {p}: {e}")
    if wipe_logs and not env.termux:
        if not env.root:
            print("[!] Wiping /var/log requires root — skipped.")
        else:
            for log in ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]:
                p = Path(log)
                if p.exists():
                    try:
                        subprocess.run(["truncate", "-s", "0", str(p)], check=True)
                        print(f"[+] Truncated {p}")
                    except Exception as e:
                        print(f"[!] Could not truncate {p}: {e}")
    print("[i] This session's live shell history may still be in memory — run `history -c` after.")


def get_public_ip() -> str:
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=8) as r:
            return r.read().decode().strip()
    except Exception as e:
        return f"error: {e}"


def get_dns_servers() -> list:
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
