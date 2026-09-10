"""
Two pieces ported over from AnonSurf's playbook that PrivacyGuard was
missing:

1. IPv6 blocking — AnonSurf disables IPv6 during anon mode because
   IPv6 traffic can slip past IPv4-only iptables rules (the Tor kill
   switch here only wrote `iptables` rules, not `ip6tables`), and an
   IPv6 address can embed your interface's permanent MAC (EUI-64),
   which defeats MAC randomization. Belt-and-suspenders: both a
   sysctl-level disable and an ip6tables DROP policy.

2. RAM-wipe-on-exit — some AnonSurf forks (Pandora) overwrite free RAM
   on shutdown using `sdmem` (from the `secure-delete` package) so
   live memory artifacts (keys, decrypted data, credentials still in
   RAM) don't survive a shutdown/reboot for physical/forensic access.
   This provides: a manual "wipe now" action, and an opt-in systemd
   shutdown hook that runs it automatically on every shutdown/reboot.

Both are full-Linux + root only — no netfilter/root in Termux, so
neither applies there.
"""
import subprocess
from pathlib import Path

from . import environment as envmod

SHUTDOWN_HOOK_PATH = Path("/usr/lib/systemd/system-shutdown/99-privacyguard-ramwipe.sh")


# --------------------------------------------------------------------
# IPv6 blocking
# --------------------------------------------------------------------

def enable_ipv6_block(env: envmod.Environment) -> None:
    if env.termux:
        print("[!] IPv6 blocking needs root/netfilter — unavailable in Termux.")
        return
    if not env.root:
        print("[!] IPv6 blocking requires root.")
        return

    if env.has_sysctl:
        for key in ("net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6",
                    "net.ipv6.conf.lo.disable_ipv6"):
            subprocess.run(["sysctl", "-w", f"{key}=1"], capture_output=True)
        print("[+] IPv6 disabled at the sysctl level.")

    if env.has_ip6tables:
        rules = [
            ["ip6tables", "-F"],
            ["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["ip6tables", "-P", "OUTPUT", "DROP"],
            ["ip6tables", "-P", "INPUT", "DROP"],
            ["ip6tables", "-P", "FORWARD", "DROP"],
        ]
        ok = True
        for r in rules:
            res = subprocess.run(r, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[!] {' '.join(r)} -> {res.stderr.strip()}")
                ok = False
        if ok:
            print("[+] ip6tables set to DROP all IPv6 traffic except loopback.")
    else:
        print("[!] ip6tables not found — sysctl disable alone is weaker (some drivers/containers "
              "ignore it). apt install iptables for the ip6tables layer too.")


def disable_ipv6_block(env: envmod.Environment) -> None:
    if env.termux or not env.root:
        return
    if env.has_sysctl:
        for key in ("net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6",
                    "net.ipv6.conf.lo.disable_ipv6"):
            subprocess.run(["sysctl", "-w", f"{key}=0"], capture_output=True)
    if env.has_ip6tables:
        subprocess.run(["ip6tables", "-F"], capture_output=True)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], capture_output=True)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], capture_output=True)
        subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    print("[+] IPv6 re-enabled (sysctl + ip6tables policy restored to ACCEPT).")


# --------------------------------------------------------------------
# RAM wipe
# --------------------------------------------------------------------

def wipe_ram_now(env: envmod.Environment) -> None:
    """Overwrite currently-free RAM pages so nothing recoverable is
    left sitting in unallocated memory. Does NOT touch memory actively
    in use by running processes — for that, close/kill the processes
    first, then wipe."""
    if env.termux:
        print("[!] RAM wiping needs root — unavailable in Termux.")
        return
    if not env.root:
        print("[!] RAM wiping requires root.")
        return
    if not env.has_sdmem:
        print("[!] sdmem not installed. sudo apt install secure-delete")
        return
    print("[*] Wiping free RAM with sdmem — this can take a while on large-RAM systems...")
    try:
        subprocess.run(["sdmem", "-f", "-v"], check=True)
        print("[+] Free RAM overwritten.")
    except subprocess.CalledProcessError as e:
        print(f"[!] sdmem failed: {e}")


SHUTDOWN_SCRIPT = """#!/bin/sh
# Installed by PrivacyGuard. Runs on every shutdown/reboot/halt via
# systemd's system-shutdown hook mechanism. Overwrites free RAM before
# the system goes down. Remove via PrivacyGuard's
# hardening.remove_ram_wipe_on_shutdown() or delete this file directly.
case "$1" in
  poweroff|halt|reboot|kexec)
    if command -v sdmem >/dev/null 2>&1; then
      sdmem -f
    fi
    ;;
esac
"""


def install_ram_wipe_on_shutdown(env: envmod.Environment) -> None:
    if env.termux:
        print("[!] Needs systemd/root — unavailable in Termux.")
        return
    if not env.root:
        print("[!] Installing the shutdown hook requires root.")
        return
    if not env.has_systemd:
        print("[!] systemd not detected — this hook mechanism (system-shutdown/) is systemd-specific.")
        return
    if not env.has_sdmem:
        print("[!] sdmem not installed yet. sudo apt install secure-delete")
        print("    (the hook will be installed, but will no-op until sdmem is present)")
    try:
        SHUTDOWN_HOOK_PATH.parent.mkdir(parents=True, exist_ok=True)
        SHUTDOWN_HOOK_PATH.write_text(SHUTDOWN_SCRIPT)
        SHUTDOWN_HOOK_PATH.chmod(0o755)
        print(f"[+] Installed shutdown hook at {SHUTDOWN_HOOK_PATH}")
        print("    It will run automatically on every shutdown/reboot from now on.")
    except PermissionError:
        print(f"[!] No permission to write {SHUTDOWN_HOOK_PATH}.")


def remove_ram_wipe_on_shutdown(env: envmod.Environment) -> None:
    if env.termux or not env.root:
        return
    if SHUTDOWN_HOOK_PATH.exists():
        try:
            SHUTDOWN_HOOK_PATH.unlink()
            print(f"[+] Removed {SHUTDOWN_HOOK_PATH}")
        except PermissionError:
            print(f"[!] No permission to remove {SHUTDOWN_HOOK_PATH}.")
    else:
        print("[i] No shutdown hook currently installed.")


def shutdown_hook_installed() -> bool:
    return SHUTDOWN_HOOK_PATH.exists()
