"""
Persistent state tracking.

Every prior version of this tool assumed "the command returned exit
code 0" meant success, and had no memory of what was already active
between runs. That meant: running enable twice could duplicate
iptables rules, a crash mid-operation left no record of what state
the firewall was actually in, and disable operations restored a
*guessed* default rather than what was actually there before.

This module is the fix: a single JSON file recording exactly what
PrivacyGuard has turned on, plus enough detail (backup paths, the
exact parameters used) to reverse each action precisely rather than
approximately.
"""
import json
import time
from pathlib import Path

STATE_FILE = Path.home() / ".privacyguard_state.json"

DEFAULT_STATE = {
    "tor_kill_switch": False,
    "proxy_only_kill_switch": False,
    "ipv6_blocked": False,
    "portscan_protection": False,
    "portscan_params": None,        # {"hitcount": int, "seconds": int}
    "stealth_sysctls": False,
    "stealth_sysctls_backup": None,  # {key: previous_value}
    "ram_wipe_hook": False,
    "iptables_backup": None,
    "ip6tables_backup": None,
    "nat_iptables_backup": None,
    "active_proxy": None,
    "vpn_active": None,
    "gateway_mode_active": False,
    "gateway_iptables_backup": None,
    "gateway_ip6tables_backup": None,
    "gateway_config": None,          # {"internal_iface": ..., "internal_ip": ..., "external_iface": ...}
    "workstation_configured": False,
    "last_updated": None,
}


def load() -> dict:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            merged = dict(DEFAULT_STATE)
            merged.update(data)
            return merged
        except Exception:
            pass
    return dict(DEFAULT_STATE)


def save(state: dict) -> None:
    state["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    STATE_FILE.write_text(json.dumps(state, indent=2))


def update(**kwargs) -> dict:
    state = load()
    state.update(kwargs)
    save(state)
    return state


def get(key, default=None):
    return load().get(key, default)


def summary() -> str:
    s = load()
    lines = [
        f"Tor kill switch        : {'ON' if s['tor_kill_switch'] else 'off'}",
        f"Proxy-only kill switch : {'ON' if s['proxy_only_kill_switch'] else 'off'}",
        f"IPv6 blocked           : {'ON' if s['ipv6_blocked'] else 'off'}",
        f"Portscan protection    : {'ON' if s['portscan_protection'] else 'off'}",
        f"Stealth sysctls        : {'ON' if s['stealth_sysctls'] else 'off'}",
        f"RAM-wipe shutdown hook : {'installed' if s['ram_wipe_hook'] else 'not installed'}",
        f"Active proxy           : {s['active_proxy'] or 'none'}",
        f"VPN                    : {s['vpn_active'] or 'none'}",
        f"Gateway mode (this VM) : {'ACTIVE — this is the Tor gateway VM' if s['gateway_mode_active'] else 'off'}",
        f"Workstation isolation  : {'configured' if s['workstation_configured'] else 'not configured'}",
        f"Last updated           : {s['last_updated'] or 'never'}",
    ]
    return "\n".join(lines)
