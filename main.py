#!/usr/bin/env python3
"""
PrivacyGuard v2 — environment-aware privacy/anonymity + anti-recon
automation for authorized pentesting on Kali (or any Linux), VMs, or
Termux. Legitimate use only. See README.md for the full feature/
limitation matrix and the reasoning behind what's deliberately NOT
implemented (raw IP spoofing).
"""
import argparse

from privacyguard import __version__
from privacyguard import environment as envmod
from privacyguard import (core, proxy_tor, proxy_only, anti_recon, vm_snapshot, crypto_log,
                           dns_check, orchestrate, ram_wipe, state as statemod, verify, vpn, profiles, monitor)

LOGGER = crypto_log.EncryptedLogger()
_monitor_handle = {"instance": None}


def menu(env: envmod.Environment) -> None:
    while True:
        print("\n=== PrivacyGuard v2 ===")
        print(f"Env: {'Termux' if env.termux else env.distro} | root={env.root}")
        print(" 1) Environment + leak report")
        print(" 2) DNS leak check")
        print(" 3) Start / Stop Tor")
        print(" 4) Rotate Tor circuit (new exit IP)")
        print(" 5) Randomize MAC / hostname")
        print(" 6) Enable / disable Tor kill switch")
        print(" 7) Anti-recon: fingerprint hardening (sysctls)")
        print(" 8) Anti-recon: portscan auto-block (iptables)")
        print(" 9) Anti-recon: live scan watch (scapy, full Linux)")
        print("10) Anti-recon: watch HTTP access log (Termux-friendly)")
        print("11) Configure Tor bridges (Tor blocked on this network)")
        print("12) Generate/test proxychains config (Tor optional, auth supported)")
        print("13) Proxy-only system-wide kill switch, NO Tor (redsocks, auth supported)")
        print("14) VM snapshot reset (VirtualBox/virsh, run from host)")
        print("15) Clean local traces")
        print("16) Save / decrypt encrypted session log")
        print("17) Start FULL anonymity mode (Tor path, self-verifying)")
        print("18) Stop FULL anonymity mode")
        print("19) Launch GUI")
        print("20) Kill risky apps now (browsers/chat clients)")
        print("21) Wipe free RAM now (sdmem)")
        print("22) Install / remove automatic RAM-wipe-on-shutdown hook")
        print("23) Show current state (what's actually active right now)")
        print("24) Verify active kill switch (real test, not just 'command succeeded')")
        print("25) VPN: start/stop OpenVPN or WireGuard")
        print("26) Save / load / list encrypted profile (proxy list, bridges, etc.)")
        print("27) Start / stop continuous leak monitor")
        print(" 0) Exit")
        c = input("> ").strip()

        if c == "1":
            print(env.summary())
            orchestrate.leak_report(env)
        elif c == "2":
            expect_tunnel = input("Is a tunnel (kill switch) supposed to be active right now? [y/N]: ").strip().lower() == "y"
            dns_check.print_dns_leak_report(env, expect_local_only=expect_tunnel)
        elif c == "3":
            (proxy_tor.start_tor if input("start or stop? [start/stop]: ").strip() == "start"
             else proxy_tor.stop_tor)(env)
        elif c == "4":
            proxy_tor.rotate_tor_circuit(env)
        elif c == "5":
            if env.interfaces:
                iface = env.interfaces[0] if len(env.interfaces) == 1 else input(f"Interface {env.interfaces}: ")
                core.randomize_mac(env, iface)
            core.randomize_hostname(env)
        elif c == "6":
            (core.enable_kill_switch if input("enable or disable? [enable/disable]: ").strip() == "enable"
             else core.disable_kill_switch)(env)
        elif c == "7":
            (anti_recon.enable_stealth_sysctls if input("enable/disable: ").strip() == "enable"
             else anti_recon.disable_stealth_sysctls)(env)
        elif c == "8":
            (anti_recon.enable_portscan_protection if input("enable/disable: ").strip() == "enable"
             else anti_recon.disable_portscan_protection)(env)
        elif c == "9":
            secs = input("watch duration seconds [120]: ").strip()
            auto = input("auto-block detected scanners? [y/N]: ").strip().lower() == "y"
            anti_recon.live_scan_watch(env, duration=int(secs) if secs else 120, auto_block=auto)
        elif c == "10":
            path = input("path to access log: ").strip()
            anti_recon.watch_http_access_log(path)
        elif c == "11":
            print("Paste bridge lines (from https://bridges.torproject.org), empty line to finish:")
            lines = []
            while True:
                l = input()
                if not l:
                    break
                lines.append(l)
            proxy_tor.configure_bridges(env, lines)
        elif c == "12":
            proxies = []
            print("Paste proxy lines (e.g. 'socks5 203.0.113.5 1080' or 'socks5 203.0.113.5 1080 user pass'),")
            print("empty line to finish:")
            while True:
                l = input()
                if not l:
                    break
                proxies.append(l)
            mode = input("chain mode [dynamic/strict/random] (default dynamic): ").strip() or "dynamic"
            include_tor = input("include Tor in the chain? [y/N] (N = proxy-only, better against Tor-blocking hosts): ").strip().lower() == "y"
            proxy_tor.generate_proxychains_conf(env, proxies, chain_mode=mode, include_tor=include_tor)
            if input("test it now? [y/N]: ").strip().lower() == "y":
                proxy_tor.test_proxychains(env)
        elif c == "13":
            action = input("enable or disable? [enable/disable]: ").strip()
            if action == "enable":
                host = input("proxy host/IP: ").strip()
                port = int(input("proxy port: ").strip())
                ptype = input("proxy type [socks5/socks4/http-connect] (default socks5): ").strip() or "socks5"
                user = input("username (leave blank if none): ").strip() or None
                pw = input("password (leave blank if none): ").strip() or None
                proxy_only.enable_proxy_kill_switch(env, host, port, ptype, username=user, password=pw)
                if input("run verification now? [Y/n]: ").strip().lower() != "n":
                    verify.verify_proxy_kill_switch(env, host)
            else:
                proxy_only.disable_proxy_kill_switch(env)
        elif c == "14":
            hv = input("hypervisor [vbox/virsh]: ").strip().lower()
            name = input("VM/domain name: ").strip()
            snap = input("snapshot name: ").strip()
            if hv == "vbox":
                vm_snapshot.reset_vbox_snapshot(name, snap)
            elif hv == "virsh":
                vm_snapshot.reset_virsh_snapshot(name, snap)
            else:
                print("Unknown hypervisor.")
        elif c == "15":
            wipe = input("also wipe system logs (needs root)? [y/N]: ").strip().lower() == "y"
            core.clean_traces(env, wipe_logs=wipe)
        elif c == "16":
            sub = input("save or decrypt? [save/decrypt]: ").strip()
            if sub == "save":
                pw = input("passphrase for encrypted log: ")
                LOGGER.save(pw)
            else:
                path = input("path to .enc file: ").strip()
                pw = input("passphrase: ")
                try:
                    for e in crypto_log.EncryptedLogger.decrypt(path, pw):
                        print(f"  [{e['ts']}] {e['msg']}")
                except Exception as e:
                    print(f"[!] Decrypt failed: {e}")
        elif c == "17":
            orchestrate.full_start(env)
        elif c == "18":
            kill_apps = input("also kill risky apps (browsers/chat clients)? [y/N]: ").strip().lower() == "y"
            wipe = input("also wipe free RAM now? [y/N]: ").strip().lower() == "y"
            mode = "fast"
            if wipe:
                mode = input("wipe mode [fast/thorough] (default fast): ").strip() or "fast"
            orchestrate.full_stop(env, kill_risky_apps=kill_apps, wipe_ram=wipe, ram_wipe_mode=mode)
        elif c == "19":
            launch_gui()
        elif c == "20":
            ram_wipe.kill_risky_apps(env)
        elif c == "21":
            mode = input("wipe mode [fast/thorough] (default fast): ").strip() or "fast"
            ram_wipe.wipe_free_ram(env, mode=mode)
        elif c == "22":
            action = input("install or remove the automatic shutdown hook? [install/remove]: ").strip()
            if action == "install":
                mode = input("wipe mode [fast/thorough] (default fast): ").strip() or "fast"
                ram_wipe.install_shutdown_hook(env, mode=mode)
            else:
                ram_wipe.remove_shutdown_hook(env)
        elif c == "23":
            print(statemod.summary())
        elif c == "24":
            st = statemod.load()
            if st["tor_kill_switch"]:
                verify.verify_tor_kill_switch(env)
            elif st["proxy_only_kill_switch"]:
                host = (st.get("active_proxy") or "://").split("://")[-1].split(":")[0]
                verify.verify_proxy_kill_switch(env, host)
            else:
                print("[i] No kill switch marked active per saved state — nothing to verify.")
            if st["ipv6_blocked"]:
                verify.verify_ipv6_blocked(env)
        elif c == "25":
            kind = input("openvpn or wireguard? [openvpn/wireguard]: ").strip().lower()
            action = input("start or stop? [start/stop]: ").strip().lower()
            if kind == "openvpn":
                if action == "start":
                    cfg = input("path to .ovpn config: ").strip()
                    auth = input("path to auth-user-pass file (blank if none): ").strip() or None
                    vpn.start_openvpn(env, cfg, auth_file=auth)
                else:
                    vpn.stop_openvpn(env)
            elif kind == "wireguard":
                iface = input("interface name [wg0]: ").strip() or "wg0"
                (vpn.start_wireguard if action == "start" else vpn.stop_wireguard)(env, iface)
            else:
                print("Unknown VPN kind.")
        elif c == "26":
            sub = input("save, load, or list? [save/load/list]: ").strip().lower()
            if sub == "list":
                names = profiles.list_profiles()
                print("Saved profiles: " + (", ".join(names) if names else "(none)"))
            elif sub == "save":
                name = input("profile name: ").strip()
                proxies = []
                print("Proxy lines (empty line to finish):")
                while True:
                    l = input()
                    if not l:
                        break
                    proxies.append(l)
                bridges = []
                print("Bridge lines (empty line to finish):")
                while True:
                    l = input()
                    if not l:
                        break
                    bridges.append(l)
                pw = input("passphrase to encrypt this profile: ")
                profiles.save_profile(name, {"proxies": proxies, "bridges": bridges}, pw)
            elif sub == "load":
                name = input("profile name: ").strip()
                pw = input("passphrase: ")
                try:
                    data = profiles.load_profile(name, pw)
                    print(f"Proxies: {data.get('proxies', [])}")
                    print(f"Bridges: {data.get('bridges', [])}")
                except Exception as e:
                    print(f"[!] Load failed: {e}")
        elif c == "27":
            action = input("start or stop? [start/stop]: ").strip().lower()
            if action == "start":
                interval = input("check interval seconds [30]: ").strip()
                mon = monitor.LeakMonitor(env, interval=int(interval) if interval else 30)
                _monitor_handle["instance"] = mon
                mon.start()
            else:
                if _monitor_handle["instance"]:
                    _monitor_handle["instance"].stop()
                else:
                    print("[i] No monitor running in this session.")
        elif c == "0":
            break
        else:
            print("Unrecognized option.")


def launch_gui():
    try:
        import gui
        gui.launch()
    except ImportError as e:
        print(f"[!] GUI unavailable: {e}")
        print("    Needs tkinter (usually `sudo apt install python3-tk` on Debian/Kali).")
        print("    GUI is intended for a full Linux desktop (VM or standalone) — not Termux's CLI-only environment.")


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard v2")
    parser.add_argument("--version", action="version", version=f"PrivacyGuard {__version__}")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--dns-leak-check", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--rotate-ip", action="store_true", help="Rotate Tor circuit (new exit IP)")
    parser.add_argument("--gui", action="store_true", help="Launch the desktop GUI (full Linux VM/standalone only)")
    parser.add_argument("--kill-risky-apps", action="store_true", help="Kill running browsers/chat clients")
    parser.add_argument("--wipe-ram", action="store_true", help="Overwrite free RAM now (sdmem if installed)")
    parser.add_argument("--wipe-ram-mode", choices=["fast", "thorough"], default="fast")
    parser.add_argument("--install-ram-wipe-hook", action="store_true",
                         help="Register a systemd hook to wipe RAM on every shutdown/reboot")
    parser.add_argument("--remove-ram-wipe-hook", action="store_true")
    parser.add_argument("--state", action="store_true", help="Print what's actually active right now")
    parser.add_argument("--verify", action="store_true", help="Verify the currently active kill switch actually works")
    args = parser.parse_args()

    env = envmod.detect_environment()

    if args.gui:
        launch_gui()
    elif args.status:
        print(env.summary())
        orchestrate.leak_report(env)
    elif args.dns_leak_check:
        dns_check.print_dns_leak_report(env)
    elif args.state:
        print(statemod.summary())
    elif args.verify:
        st = statemod.load()
        if st["tor_kill_switch"]:
            verify.verify_tor_kill_switch(env)
        elif st["proxy_only_kill_switch"]:
            host = (st.get("active_proxy") or "://").split("://")[-1].split(":")[0]
            verify.verify_proxy_kill_switch(env, host)
        else:
            print("[i] No kill switch marked active per saved state — nothing to verify.")
    elif args.start:
        orchestrate.full_start(env)
    elif args.stop:
        orchestrate.full_stop(env)
    elif args.clean:
        core.clean_traces(env)
    elif args.rotate_ip:
        proxy_tor.rotate_tor_circuit(env)
    elif args.kill_risky_apps:
        ram_wipe.kill_risky_apps(env)
    elif args.wipe_ram:
        ram_wipe.wipe_free_ram(env, mode=args.wipe_ram_mode)
    elif args.install_ram_wipe_hook:
        ram_wipe.install_shutdown_hook(env, mode=args.wipe_ram_mode)
    elif args.remove_ram_wipe_hook:
        ram_wipe.remove_shutdown_hook(env)
    else:
        menu(env)


if __name__ == "__main__":
    main()
