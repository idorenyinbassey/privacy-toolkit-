"""Core anonymity actions: MAC/hostname randomization, Tor kill switch, trace cleanup."""
import random
import subprocess
import time
from pathlib import Path

from . import environment as envmod
from . import state as statemod
from . import firewall_backup

TOR_UID_PLACEHOLDER = "debian-tor"


def random_mac() -> str:
    first = random.choice([0x02, 0x06, 0x0A, 0x0E])
    rest = [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first] + rest)


def randomize_mac(env: envmod.Environment, iface: str, renew_dhcp: bool = True) -> None:
    """Changing the MAC while keeping the same IP breaks connectivity
    on many networks (especially bridged VMs sharing a home/office
    LAN) — the router's DHCP lease / ARP table still associates that
    IP with the OLD MAC until something forces a fresh negotiation.
    renew_dhcp=True (default) attempts that renewal automatically via
    NetworkManager; it's best-effort and never raises, since a failed
    renewal attempt shouldn't be treated as the MAC change itself
    failing — but it's the actual fix for the "changed MAC, lost
    internet" pattern, not just cosmetic."""
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
        return

    if not renew_dhcp:
        print(f"[i] Skipping DHCP renewal on {iface} — if you're bridged onto a LAN, you may lose "
              f"connectivity until the router/switch sees a fresh lease request from the new MAC.")
        return

    if envmod.have("nmcli"):
        print(f"[*] Requesting a fresh DHCP lease for {iface} (MAC changed, IP likely still stale)...")
        result = subprocess.run(["nmcli", "device", "connect", iface], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] {iface} reconnected via NetworkManager — should have a lease matching the new MAC now.")
        else:
            print(f"[!] Could not auto-renew via nmcli ({result.stderr.strip() or 'unknown error'}). "
                  f"If connectivity breaks, try: sudo nmcli device connect {iface}")
    else:
        print(f"[i] No NetworkManager (nmcli) found to auto-renew the DHCP lease. If connectivity "
              f"breaks on {iface} — especially on a bridged VM sharing a physical LAN — manually "
              f"renew it (e.g. `sudo dhclient -r {iface} && sudo dhclient {iface}`, or restart "
              f"networking) rather than assuming the interface itself is broken.")


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
    kill switch is active. Idempotent — a no-op if already blocked
    per saved state."""
    if env.termux or not env.root or not env.has_ip6tables:
        print("[!] IPv6 blocking needs root + ip6tables (full Linux only) — skipped.")
        return
    if statemod.get("ipv6_blocked"):
        print("[i] IPv6 already blocked (per saved state) — skipping.")
        return
    try:
        subprocess.run(["ip6tables", "-F"], check=True)
        subprocess.run(["ip6tables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "DROP"], check=True)
        subprocess.run(["ip6tables", "-P", "FORWARD", "DROP"], check=True)
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        print("[+] IPv6 blocked (prevents IPv6 traffic leaking around the IPv4-only kill switch).")
        statemod.update(ipv6_blocked=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block IPv6: {e}")


def unblock_ipv6(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_ip6tables:
        return
    if not statemod.get("ipv6_blocked"):
        return
    try:
        subprocess.run(["ip6tables", "-F"], check=True)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], check=True)
        subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], check=True)
        print("[+] IPv6 traffic restored to normal.")
        statemod.update(ipv6_blocked=False)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to restore IPv6: {e}")


def _ensure_transparent_proxy_torrc(torrc_path: Path = None) -> bool:
    """Ensures torrc has TransPort 9040 / DNSPort 5353 — the redirect
    rules below send traffic to these ports, and if nothing is
    listening there (the actual bug behind 'enabled kill switch, lost
    all internet'), every connection just fails silently. Idempotent:
    returns True only if it changed the file (caller should restart
    tor), False if it was already correctly configured."""
    path = torrc_path or Path("/etc/tor/torrc")
    marker_start = "# --- PrivacyGuard kill switch (managed block) ---"
    marker_end = "# --- end PrivacyGuard kill switch ---"
    block_body = "TransPort 127.0.0.1:9040\nDNSPort 127.0.0.1:5353\nAutomapHostsOnResolve 1"
    block = f"{marker_start}\n{block_body}\n{marker_end}\n"

    try:
        existing = path.read_text() if path.exists() else ""
    except PermissionError:
        print(f"[!] No permission to read {path}.")
        return False

    if marker_start in existing:
        current_body = existing.split(marker_start)[1].split(marker_end)[0].strip()
        if current_body == block_body:
            return False  # already correctly configured, no restart needed
        pre, post = existing.split(marker_start)[0], existing.split(marker_end)[-1]
        new_content = pre + block + post
    else:
        new_content = existing.rstrip("\n") + "\n\n" + block

    try:
        path.write_text(new_content)
    except PermissionError:
        print(f"[!] No permission to write {path}.")
        return False
    print(f"[+] Configured {path} with TransPort 9040 / DNSPort 5353 — required for the kill switch "
          f"to actually route anywhere instead of dropping everything.")
    return True


def _wait_for_tor_bootstrap(env: envmod.Environment, timeout: int = 30) -> bool:
    from . import proxy_tor as _proxy_tor
    check = _proxy_tor.check_tor_active()
    if "error" not in check:
        return True
    print(f"[*] Tor not yet reachable — starting it and waiting up to {timeout}s to bootstrap...")
    _proxy_tor.start_tor(env)
    waited = 0
    while waited < timeout:
        time.sleep(2)
        waited += 2
        check = _proxy_tor.check_tor_active()
        if "error" not in check:
            print(f"[+] Tor bootstrapped and reachable after {waited}s.")
            return True
    return False


def enable_kill_switch(env: envmod.Environment, force: bool = False, bootstrap_timeout: int = 45) -> bool:
    """Returns True only if the kill switch was actually applied.
    Callers (orchestrate.full_start, the CLI, the GUI) must check this
    before treating the system as protected — a False return means we
    correctly declined rather than a rule silently failing."""
    if env.termux:
        print("[!] Kill switch needs iptables — unavailable in Termux. Use Orbot VPN mode instead.")
        return False
    if not env.root or not env.has_iptables:
        print("[!] Kill switch requires root + iptables.")
        return False
    if not env.has_tor:
        print("[!] Tor isn't installed on this system. Install it first: sudo apt install tor")
        print("    Enabling the kill switch without Tor would drop all internet access — refusing.")
        return False
    st = statemod.load()
    if st["tor_kill_switch"] and not force:
        print("[i] Tor kill switch already active (per saved state). Disable it first, "
              "or call with force=True to re-apply.")
        return True  # already genuinely active, not a failure
    if st["proxy_only_kill_switch"]:
        print("[!] Proxy-only kill switch is currently active — disable that first "
              "(both rewrite the same OUTPUT chain and will conflict).")
        return False

    # Fix the actual root cause of "enabled kill switch, lost internet":
    # verify/auto-configure torrc, restart tor if changed, then confirm
    # Tor is genuinely bootstrapped BEFORE applying any firewall rule.
    # If it never comes up, we refuse to enable rather than leaving you
    # stuck with no path out at all.
    torrc_changed = _ensure_transparent_proxy_torrc()
    if torrc_changed and envmod.have("systemctl"):
        print("[*] Restarting tor to apply the updated torrc...")
        subprocess.run(["systemctl", "restart", "tor"], capture_output=True)
        time.sleep(2)

    if not _wait_for_tor_bootstrap(env, timeout=bootstrap_timeout):
        print(f"[!] Tor did not bootstrap within {bootstrap_timeout}s. NOT enabling the kill switch — "
              f"doing so now would drop all internet access with no working Tor path to replace it.")
        print("    Check: sudo systemctl status tor   /   sudo journalctl -u tor -n 50")
        print("    First bootstrap can genuinely take longer than 45s on a slow/filtered connection — "
              "retry with a longer bootstrap_timeout, or configure bridges (menu 11) if Tor looks "
              "stuck rather than just slow.")
        return False

    backups = firewall_backup.backup_rules(env, label="pre-tor-killswitch")

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
        statemod.update(tor_kill_switch=True, iptables_backup=backups["ipv4"], ip6tables_backup=backups["ipv6"])
    else:
        print("[!] Kill switch application had errors — restoring pre-existing rules rather than "
              "leaving a half-applied firewall.")
        firewall_backup.restore_rules(env, backups["ipv4"], backups["ipv6"])
        return False
    block_ipv6(env)
    return True


def disable_kill_switch(env: envmod.Environment) -> None:
    if env.termux or not env.root or not env.has_iptables:
        return
    st = statemod.load()
    if not st["tor_kill_switch"]:
        print("[i] Tor kill switch not marked active (per saved state) — nothing to disable.")
        return
    firewall_backup.restore_rules(env, st.get("iptables_backup"), st.get("ip6tables_backup"))
    statemod.update(tor_kill_switch=False, ipv6_blocked=False, iptables_backup=None, ip6tables_backup=None)
    print("[+] Kill switch disabled, prior firewall state restored.")


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
