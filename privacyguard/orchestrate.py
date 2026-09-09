"""High-level orchestration shared by the CLI (main.py) and the GUI (gui.py)."""
from . import environment as envmod
from . import core, proxy_tor, anti_recon, dns_check


def leak_report(env: envmod.Environment) -> None:
    print(f"  Public IP : {core.get_public_ip()}")
    print(f"  DNS       : {', '.join(core.get_dns_servers()) or 'not readable'}")
    tc = proxy_tor.check_tor_active()
    if "error" in tc:
        print(f"  Tor check : unavailable ({tc['error']})")
    else:
        print(f"  Via Tor   : {tc.get('IsTor', 'unknown')}  (exit IP: {tc.get('IP', '?')})")


def full_start(env: envmod.Environment) -> None:
    """Full anonymity mode via the Tor path. For networks that block
    Tor outright, use proxy_only.enable_proxy_kill_switch() instead —
    see the GUI's Proxy tab or the CLI's proxy-only menu option."""
    print("=== Starting anonymity mode (Tor path) ===")
    proxy_tor.start_tor(env)
    if not env.termux:
        for iface in env.interfaces:
            core.randomize_mac(env, iface)
        core.randomize_hostname(env)
        anti_recon.enable_stealth_sysctls(env)
        anti_recon.enable_portscan_protection(env)
        core.enable_kill_switch(env)
    else:
        print("[i] Termux: wrap traffic with `torsocks <command>` or a no-Tor proxychains config.")
    print("=== Done. Run a leak report + DNS leak check to verify. ===")


def full_stop(env: envmod.Environment) -> None:
    print("=== Stopping anonymity mode ===")
    if not env.termux:
        core.disable_kill_switch(env)
        anti_recon.disable_portscan_protection(env)
        anti_recon.disable_stealth_sysctls(env)
    proxy_tor.stop_tor(env)
    print("=== Reverted to normal networking. ===")
