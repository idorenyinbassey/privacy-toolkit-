"""
Backup/restore for iptables/ip6tables rule sets.

Every kill switch in earlier versions did `iptables -F` unconditionally
before applying its own rules — silently discarding whatever firewall
you had running before, with no way back. This module fixes that:
back up the current rule set before any flush, and restore exactly
that (not a guessed-at "typical default") when the kill switch comes
back off.
"""
import subprocess
import time
from pathlib import Path

from . import environment as envmod

BACKUP_DIR = Path.home() / ".privacyguard_backups"


def backup_rules(env: envmod.Environment, label: str = "auto", tables: tuple = ("filter", "nat")) -> dict:
    """Returns {'ipv4': path_or_None, 'ipv6': path_or_None}. ipv4 backup
    always covers the full ruleset (all tables) via iptables-save; the
    `tables` arg is currently informational/future-use since
    iptables-save always dumps everything in one call."""
    if env.termux or not env.root:
        return {"ipv4": None, "ipv6": None}
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    result = {"ipv4": None, "ipv6": None}

    if env.has_iptables:
        path = BACKUP_DIR / f"iptables-{label}-{ts}.rules"
        try:
            out = subprocess.run(["iptables-save"], capture_output=True, text=True, check=True)
            path.write_text(out.stdout)
            result["ipv4"] = str(path)
            print(f"[+] Backed up current iptables rules to {path}")
        except Exception as e:
            print(f"[!] Could not back up iptables rules: {e}")

    if env.has_ip6tables:
        path6 = BACKUP_DIR / f"ip6tables-{label}-{ts}.rules"
        try:
            out = subprocess.run(["ip6tables-save"], capture_output=True, text=True, check=True)
            path6.write_text(out.stdout)
            result["ipv6"] = str(path6)
            print(f"[+] Backed up current ip6tables rules to {path6}")
        except Exception as e:
            print(f"[!] Could not back up ip6tables rules: {e}")

    return result


def restore_rules(env: envmod.Environment, ipv4_path: str = None, ipv6_path: str = None) -> None:
    """Restore from a specific backup if we have one; otherwise fall
    back to a known-safe open state rather than leaving whatever
    DROP-heavy rules the kill switch applied."""
    if env.termux or not env.root:
        return

    if ipv4_path and Path(ipv4_path).exists():
        try:
            subprocess.run(["iptables-restore"], input=Path(ipv4_path).read_text(), text=True, check=True)
            print(f"[+] Restored iptables rules from {ipv4_path}")
        except Exception as e:
            print(f"[!] Failed to restore iptables from {ipv4_path}: {e} — flushing to open default instead.")
            _open_default_v4()
    else:
        print("[i] No prior iptables backup on record — flushing to an open default instead of guessing.")
        _open_default_v4()

    if ipv6_path and Path(ipv6_path).exists():
        try:
            subprocess.run(["ip6tables-restore"], input=Path(ipv6_path).read_text(), text=True, check=True)
            print(f"[+] Restored ip6tables rules from {ipv6_path}")
        except Exception as e:
            print(f"[!] Failed to restore ip6tables from {ipv6_path}: {e} — flushing to open default instead.")
            _open_default_v6(env)
    elif env.has_ip6tables:
        _open_default_v6(env)


def apply_ruleset(env: envmod.Environment, rules: list, label: str, tolerate: tuple = ()) -> tuple:
    """Shared by every kill switch (Tor, proxy-only, gateway): back up
    the current rules, then apply each rule in `rules` (a list of
    iptables/ip6tables argv lists) in order, continuing through the
    whole list even if one fails so every rule gets a chance to report
    its own error before any rollback decision is made — matching the
    per-module behavior this replaces.

    A rule that fails with stderr containing one of `tolerate` (e.g.
    "Chain already exists", for an idempotent `-N` chain-creation step)
    is treated as a harmless no-op, not a failure. Any other failure
    means the whole ruleset gets rolled back to the pre-existing backup
    once every rule has been attempted, rather than leaving a
    half-applied firewall — the caller should NOT call restore_rules
    again on a False return, that's already been done here.

    Returns (ok, backups); backups is always the {'ipv4':, 'ipv6':}
    dict from backup_rules regardless of ok, so a caller on the
    success path can record it in state.py without a second backup."""
    backups = backup_rules(env, label=label)
    ok = True
    for rule in rules:
        result = subprocess.run(rule, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if tolerate and any(marker in stderr for marker in tolerate):
                continue
            print(f"[!] Rule failed: {' '.join(rule)} -> {stderr or result.returncode}")
            ok = False
    if not ok:
        print("[!] Rule application had errors — restoring pre-existing rules rather than "
              "leaving a half-applied firewall.")
        restore_rules(env, backups["ipv4"], backups["ipv6"])
    return ok, backups


def _open_default_v4():
    subprocess.run(["iptables", "-F"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
    subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True)
    subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], capture_output=True)
    subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)


def _open_default_v6(env: envmod.Environment):
    if not env.has_ip6tables:
        return
    subprocess.run(["ip6tables", "-F"], capture_output=True)
    subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], capture_output=True)
    subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], capture_output=True)
    subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
