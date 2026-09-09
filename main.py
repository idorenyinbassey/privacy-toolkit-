#!/usr/bin/env python3
"""
PrivacyGuard v2 — environment-aware privacy/anonymity + anti-recon
automation for authorized pentesting on Kali (or any Linux), VMs, or
Termux. Legitimate use only. See README.md for the full feature/
limitation matrix and the reasoning behind what's deliberately NOT
implemented (raw IP spoofing).
"""
import argparse

from privacyguard import environment as envmod
from privacyguard import core, proxy_tor, proxy_only, anti_recon, vm_snapshot, crypto_log, dns_check, orchestrate

LOGGER = crypto_log.EncryptedLogger()


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
        print("12) Generate/test proxychains config (Tor optional)")
        print("13) Proxy-only system-wide kill switch, NO Tor (redsocks)")
        print("14) VM snapshot reset (VirtualBox/virsh, run from host)")
        print("15) Clean local traces")
        print("16) Save / decrypt encrypted session log")
        print("17) Start FULL anonymity mode (Tor path)")
        print("18) Stop FULL anonymity mode")
        print("19) Launch GUI")
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
            print("Paste proxy lines (e.g. 'socks5 203.0.113.5 1080'), empty line to finish:")
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
                proxy_only.enable_proxy_kill_switch(env, host, port, ptype)
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
            orchestrate.full_stop(env)
        elif c == "19":
            launch_gui()
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
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--dns-leak-check", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--rotate-ip", action="store_true", help="Rotate Tor circuit (new exit IP)")
    parser.add_argument("--gui", action="store_true", help="Launch the desktop GUI (full Linux VM/standalone only)")
    args = parser.parse_args()

    env = envmod.detect_environment()

    if args.gui:
        launch_gui()
    elif args.status:
        print(env.summary())
        orchestrate.leak_report(env)
    elif args.dns_leak_check:
        dns_check.print_dns_leak_report(env)
    elif args.start:
        orchestrate.full_start(env)
    elif args.stop:
        orchestrate.full_stop(env)
    elif args.clean:
        core.clean_traces(env)
    elif args.rotate_ip:
        proxy_tor.rotate_tor_circuit(env)
    else:
        menu(env)


if __name__ == "__main__":
    main()
