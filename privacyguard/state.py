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

The GUI runs every button's action in its own background thread
(gui.py's _run_bg), so two enable/disable actions triggered close
together can genuinely race on this file from within the same
process — e.g. enabling the kill switch and enabling portscan
protection at nearly the same time are two independent
load-modify-save cycles on the same JSON file. A plain read-then-write
with no lock can lose one of the two updates (last writer wins,
silently dropping the other thread's field changes) — exactly the
"no memory of what was already active" failure mode this module
exists to prevent, just triggered by concurrency instead of a crash.
A module-level lock serializes load/update/save within this process;
writing via a temp file + os.replace() makes each save atomic, so a
concurrent reader (in this process or another) never sees a
half-written file either.
"""
import json
import os
import threading
import time
from pathlib import Path

STATE_FILE = Path.home() / ".privacyguard_state.json"
_LOCK = threading.Lock()

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


def _load_unlocked() -> dict:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            merged = dict(DEFAULT_STATE)
            merged.update(data)
            return merged
        except Exception:
            pass
    return dict(DEFAULT_STATE)


def _save_unlocked(state: dict) -> None:
    state["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    # Write to a temp file in the same directory, then rename over the
    # real one — os.replace() is atomic on POSIX, so a concurrent
    # reader (this process or another) always sees either the old
    # complete file or the new one, never a partially-written one.
    tmp_path = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, indent=2))
    os.replace(tmp_path, STATE_FILE)


def load() -> dict:
    with _LOCK:
        return _load_unlocked()


def save(state: dict) -> None:
    with _LOCK:
        _save_unlocked(state)


def update(**kwargs) -> dict:
    """Read-modify-write under a single lock acquisition — calling
    load() and save() separately here would reopen the exact race this
    function exists to close, since another thread could update() in
    between the two calls."""
    with _LOCK:
        state = _load_unlocked()
        state.update(kwargs)
        _save_unlocked(state)
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
