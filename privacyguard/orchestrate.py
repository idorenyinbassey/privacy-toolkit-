"""High-level orchestration shared by the CLI (main.py) and the GUI (gui.py)."""
import time

from . import environment as envmod
from . import core, proxy_tor, anti_recon, ram_wipe, verify


def leak_report(env: envmod.Environment) -> None:
    print(f"  Public IP : {core.get_public_ip()}")
    print(f"  DNS       : {', '.join(core.get_dns_servers()) or 'not readable'}")
    tc = proxy_tor.check_tor_active()
    if "error" in tc:
        print(f"  Tor check : unavailable ({tc['error']})")
    else:
        print(f"  Via Tor   : {tc.get('IsTor', 'unknown')}  (exit IP: {tc.get('IP', '?')})")


def full_start(env: envmod.Environment, run_verification: bool = True, bootstrap_timeout: int = 45,
               randomize_identity: bool = True) -> bool:
    """Full anonymity mode via the Tor path. For networks that block
    Tor outright, use proxy_only.enable_proxy_kill_switch() instead —
    see the GUI's Proxy tab or the CLI's proxy-only menu option.
    Returns True only if the kill switch actually ended up active —
    check this before assuming anything downstream is protected.

    randomize_identity=False skips MAC/hostname randomization — worth
    doing on a bridged VM sharing a physical LAN, where changing the
    MAC while keeping the same IP can break connectivity until the
    router/switch sees a fresh DHCP negotiation (randomize_mac()
    attempts that renewal automatically, but some networks are
    stubborn about accepting a new MAC quickly regardless)."""
    print("=== Starting anonymity mode (Tor path) ===")
    proxy_tor.start_tor(env)
    kill_switch_active = False
    if not env.termux:
        if randomize_identity:
            for iface in env.interfaces:
                core.randomize_mac(env, iface)
            core.randomize_hostname(env)
        else:
            print("[i] Skipping MAC/hostname randomization (randomize_identity=False).")
        if not anti_recon.enable_stealth_sysctls(env):
            print("[i] Fingerprint-hardening sysctls did not fully apply (see reason above) — "
                  "continuing anyway, this is best-effort hardening, not a gate on the kill switch.")
        if not anti_recon.enable_portscan_protection(env):
            print("[i] Portscan protection did not apply (see reason above) — "
                  "continuing anyway, this is best-effort hardening, not a gate on the kill switch.")
        kill_switch_active = core.enable_kill_switch(env, bootstrap_timeout=bootstrap_timeout)
        if not kill_switch_active:
            print("[!] Kill switch was NOT enabled (see reason above) — skipping verification, "
                  "since there's nothing active to verify. You are running WITHOUT a kill switch right now.")
        elif run_verification:
            print("[*] Waiting 8s before verifying...")
            time.sleep(8)
            verify.verify_tor_kill_switch(env)
    else:
        print("[i] Termux: wrap traffic with `torsocks <command>` or a no-Tor proxychains config.")
    print("=== Done. ===")
    return kill_switch_active


def full_stop(env: envmod.Environment, kill_risky_apps: bool = False, wipe_ram: bool = False,
              ram_wipe_mode: str = "fast") -> None:
    print("=== Stopping anonymity mode ===")
    if not env.termux:
        core.disable_kill_switch(env)
        anti_recon.disable_portscan_protection(env)
        anti_recon.disable_stealth_sysctls(env)
    proxy_tor.stop_tor(env)
    if kill_risky_apps:
        ram_wipe.kill_risky_apps(env)
    if wipe_ram:
        ram_wipe.wipe_free_ram(env, mode=ram_wipe_mode)
    print("=== Reverted to normal networking. ===")
