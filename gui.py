#!/usr/bin/env python3
"""
PrivacyGuard desktop GUI — for a full Linux desktop environment (a VM
or standalone install with a display). Not for Termux, which has no
GUI/X server by default.

Built with Tkinter (stdlib) so it needs no extra framework — just
`python3-tk` if your distro splits it out (Debian/Kali: apt install
python3-tk).

Run: python3 gui.py   (or `python3 main.py --gui`)
"""
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from privacyguard import environment as envmod
from privacyguard import (core, proxy_tor, proxy_only, anti_recon, vm_snapshot, crypto_log, dns_check,
                           orchestrate, ram_wipe, state as statemod, verify, vpn, profiles, monitor)


class ConsoleRedirector:
    """Captures print() output from worker threads into a thread-safe
    queue that the Tk main loop drains into the console widget."""

    def __init__(self, q: queue.Queue):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)

    def flush(self):
        pass


class PrivacyGuardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PrivacyGuard v2")
        self.geometry("900x700")

        self.env = envmod.detect_environment()
        self.log_q = queue.Queue()
        self.logger = crypto_log.EncryptedLogger()
        self.watch_stop_event = threading.Event()
        self.leak_monitor = None

        self._build_status_bar()
        self._build_layout()
        self._refresh_env()
        self.after(150, self._drain_log_queue)
        self.after(2000, self._refresh_status_bar)

    def _build_status_bar(self):
        bar = ttk.Frame(self, relief="sunken", borderwidth=1)
        bar.pack(fill="x", side="top", padx=4, pady=2)
        self.status_var = tk.StringVar(value="Loading state...")
        ttk.Label(bar, textvariable=self.status_var, font=("Courier", 9)).pack(side="left", padx=6)

    def _refresh_status_bar(self):
        s = statemod.load()

        def dot(active):
            return "●" if active else "○"
        text = (f"Tor kill switch {dot(s['tor_kill_switch'])}  |  "
                f"Proxy-only kill switch {dot(s['proxy_only_kill_switch'])}  |  "
                f"IPv6 blocked {dot(s['ipv6_blocked'])}  |  "
                f"Portscan protection {dot(s['portscan_protection'])}  |  "
                f"VPN: {s['vpn_active'] or 'none'}")
        self.status_var.set(text)
        self.after(2000, self._refresh_status_bar)

    # ------------------------------------------------------------
    def _build_layout(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_status = ttk.Frame(nb)
        self.tab_tor = ttk.Frame(nb)
        self.tab_proxy = ttk.Frame(nb)
        self.tab_recon = ttk.Frame(nb)
        self.tab_vm = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)
        self.tab_vpn = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_monitor = ttk.Frame(nb)

        for tab, label in [(self.tab_status, "Status"), (self.tab_tor, "Tor"),
                            (self.tab_proxy, "Proxy"), (self.tab_recon, "Anti-Recon"),
                            (self.tab_vm, "VM Snapshots"), (self.tab_logs, "Cleanup / Logs"),
                            (self.tab_vpn, "VPN"), (self.tab_profiles, "Profiles"),
                            (self.tab_monitor, "Monitor")]:
            nb.add(tab, text=label)

        self._build_status_tab()
        self._build_tor_tab()
        self._build_proxy_tab()
        self._build_recon_tab()
        self._build_vm_tab()
        self._build_logs_tab()
        self._build_vpn_tab()
        self._build_profiles_tab()
        self._build_monitor_tab()

        console_frame = ttk.LabelFrame(self, text="Console output")
        console_frame.pack(fill="both", expand=False, padx=8, pady=(0, 8))
        self.console = tk.Text(console_frame, height=14, bg="black", fg="#33ff33", font=("Courier", 9))
        self.console.pack(fill="both", expand=True)

    def _run_bg(self, func, *args, **kwargs):
        def target():
            old_stdout = sys.stdout
            sys.stdout = ConsoleRedirector(self.log_q)
            try:
                func(*args, **kwargs)
            except Exception as e:
                self.log_q.put(f"[!] Exception: {e}\n")
            finally:
                sys.stdout = old_stdout
        threading.Thread(target=target, daemon=True).start()

    def _drain_log_queue(self):
        try:
            while True:
                text = self.log_q.get_nowait()
                self.console.insert("end", text if text.endswith("\n") else text + "\n")
                self.console.see("end")
        except queue.Empty:
            pass
        self.after(150, self._drain_log_queue)

    # ------------------------------------------------------------
    def _build_status_tab(self):
        f = self.tab_status
        self.env_text = tk.Text(f, height=16, wrap="none")
        self.env_text.pack(fill="both", expand=True, padx=8, pady=8)
        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Refresh Environment", command=self._refresh_env).pack(side="left")
        ttk.Button(btns, text="Leak Report", command=lambda: self._run_bg(orchestrate.leak_report, self.env)).pack(side="left", padx=6)
        ttk.Button(btns, text="Show Full State", command=lambda: self._run_bg(lambda: print(statemod.summary()))).pack(side="left", padx=6)

        dns_frame = ttk.Frame(f)
        dns_frame.pack(fill="x", padx=8, pady=(0, 8))
        self.dns_tunnel_var = tk.BooleanVar()
        ttk.Checkbutton(dns_frame, text="A kill switch/tunnel is active right now",
                         variable=self.dns_tunnel_var).pack(side="left")
        ttk.Button(dns_frame, text="Run DNS Leak Check",
                   command=lambda: self._run_bg(dns_check.print_dns_leak_report, self.env,
                                                 self.dns_tunnel_var.get())).pack(side="left", padx=6)

    def _refresh_env(self):
        self.env = envmod.detect_environment()
        self.env_text.delete("1.0", "end")
        self.env_text.insert("end", self.env.summary())

    # ------------------------------------------------------------
    def _build_tor_tab(self):
        f = self.tab_tor
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=8)
        ttk.Button(row, text="Start Tor", command=lambda: self._run_bg(proxy_tor.start_tor, self.env)).pack(side="left")
        ttk.Button(row, text="Stop Tor", command=lambda: self._run_bg(proxy_tor.stop_tor, self.env)).pack(side="left", padx=6)
        ttk.Button(row, text="Rotate Circuit (new exit IP)",
                   command=lambda: self._run_bg(proxy_tor.rotate_tor_circuit, self.env)).pack(side="left", padx=6)
        ttk.Button(row, text="Check Tor Active", command=lambda: self._run_bg(self._check_tor)).pack(side="left", padx=6)

        ttk.Label(f, text="Tor kill switch (all traffic forced through Tor, full Linux + root):").pack(anchor="w", padx=8, pady=(12, 0))
        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=4)
        ttk.Button(row2, text="Enable Kill Switch", command=lambda: self._run_bg(core.enable_kill_switch, self.env)).pack(side="left")
        ttk.Button(row2, text="Disable Kill Switch", command=lambda: self._run_bg(core.disable_kill_switch, self.env)).pack(side="left", padx=6)
        ttk.Button(row2, text="Verify (actually test it)", command=lambda: self._run_bg(verify.verify_tor_kill_switch, self.env)).pack(side="left", padx=6)

        ttk.Label(f, text="Bridges (paste lines from https://bridges.torproject.org, one per line):").pack(anchor="w", padx=8, pady=(12, 0))
        self.bridges_text = tk.Text(f, height=6)
        self.bridges_text.pack(fill="x", padx=8, pady=4)
        ttk.Button(f, text="Configure Bridges", command=self._configure_bridges).pack(anchor="w", padx=8, pady=(0, 8))

        ttk.Separator(f).pack(fill="x", padx=8, pady=8)
        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=4)
        ttk.Button(row3, text="Start FULL anonymity mode (Tor path)",
                   command=lambda: self._run_bg(orchestrate.full_start, self.env)).pack(side="left")
        ttk.Button(row3, text="Stop FULL anonymity mode",
                   command=lambda: self._run_bg(orchestrate.full_stop, self.env)).pack(side="left", padx=6)

    def _check_tor(self):
        r = proxy_tor.check_tor_active()
        print(r)

    def _configure_bridges(self):
        lines = [l for l in self.bridges_text.get("1.0", "end").splitlines() if l.strip()]
        self._run_bg(proxy_tor.configure_bridges, self.env, lines)

    # ------------------------------------------------------------
    def _build_proxy_tab(self):
        f = self.tab_proxy
        ttk.Label(f, text="Proxychains config (app-level, works on Termux too — wrap a command with proxychains4):").pack(anchor="w", padx=8, pady=(8, 0))
        ttk.Label(f, text="Proxy lines, e.g. 'socks5 203.0.113.5 1080' (one per line):").pack(anchor="w", padx=8)
        self.proxy_list_text = tk.Text(f, height=5)
        self.proxy_list_text.pack(fill="x", padx=8, pady=4)

        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text="Chain mode:").pack(side="left")
        self.chain_mode_var = tk.StringVar(value="dynamic")
        ttk.Combobox(row, textvariable=self.chain_mode_var, values=["dynamic", "strict", "random"],
                     width=10, state="readonly").pack(side="left", padx=6)
        self.include_tor_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Include Tor in chain (leave OFF if the target blocks Tor)",
                         variable=self.include_tor_var).pack(side="left", padx=12)

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=4)
        ttk.Button(row2, text="Generate proxychains.conf", command=self._gen_proxychains).pack(side="left")
        ttk.Button(row2, text="Test proxychains (show exit IP)",
                   command=lambda: self._run_bg(proxy_tor.test_proxychains, self.env)).pack(side="left", padx=6)

        ttk.Separator(f).pack(fill="x", padx=8, pady=10)
        ttk.Label(f, text="Proxy-only SYSTEM-WIDE kill switch — no Tor at all (full Linux + root, needs redsocks):").pack(anchor="w", padx=8)
        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=4)
        ttk.Label(row3, text="Host:").pack(side="left")
        self.px_host = ttk.Entry(row3, width=18); self.px_host.pack(side="left", padx=4)
        ttk.Label(row3, text="Port:").pack(side="left")
        self.px_port = ttk.Entry(row3, width=8); self.px_port.pack(side="left", padx=4)
        ttk.Label(row3, text="Type:").pack(side="left")
        self.px_type = tk.StringVar(value="socks5")
        ttk.Combobox(row3, textvariable=self.px_type, values=["socks5", "socks4", "http-connect"],
                     width=12, state="readonly").pack(side="left", padx=4)

        row3b = ttk.Frame(f); row3b.pack(fill="x", padx=8, pady=4)
        ttk.Label(row3b, text="Username (optional):").pack(side="left")
        self.px_user = ttk.Entry(row3b, width=14); self.px_user.pack(side="left", padx=4)
        ttk.Label(row3b, text="Password (optional):").pack(side="left")
        self.px_pass = ttk.Entry(row3b, width=14, show="*"); self.px_pass.pack(side="left", padx=4)

        row4 = ttk.Frame(f); row4.pack(fill="x", padx=8, pady=4)
        ttk.Button(row4, text="Enable proxy-only kill switch", command=self._enable_proxy_only).pack(side="left")
        ttk.Button(row4, text="Disable proxy-only kill switch",
                   command=lambda: self._run_bg(proxy_only.disable_proxy_kill_switch, self.env)).pack(side="left", padx=6)
        ttk.Button(row4, text="Verify (actually test it)", command=self._verify_proxy_only).pack(side="left", padx=6)
        ttk.Label(f, text="Note: TCP only — UDP/DNS isn't tunneled by this. Run a DNS leak check after enabling.",
                  foreground="#a05a00").pack(anchor="w", padx=8, pady=(2, 8))

    def _gen_proxychains(self):
        proxies = [l for l in self.proxy_list_text.get("1.0", "end").splitlines() if l.strip()]
        self._run_bg(proxy_tor.generate_proxychains_conf, self.env, proxies,
                     self.chain_mode_var.get(), self.include_tor_var.get())

    def _enable_proxy_only(self):
        try:
            port = int(self.px_port.get().strip())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return
        host = self.px_host.get().strip()
        if not host:
            messagebox.showerror("Missing host", "Enter a proxy host/IP.")
            return
        user = self.px_user.get().strip() or None
        pw = self.px_pass.get().strip() or None
        self._run_bg(proxy_only.enable_proxy_kill_switch, self.env, host, port, self.px_type.get(), user, pw)

    def _verify_proxy_only(self):
        host = self.px_host.get().strip()
        if not host:
            messagebox.showerror("Missing host", "Enter the proxy host/IP to verify against.")
            return
        self._run_bg(verify.verify_proxy_kill_switch, self.env, host)

    # ------------------------------------------------------------
    def _build_recon_tab(self):
        f = self.tab_recon
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=8)
        ttk.Button(row, text="Enable fingerprint hardening", command=lambda: self._run_bg(anti_recon.enable_stealth_sysctls, self.env)).pack(side="left")
        ttk.Button(row, text="Disable fingerprint hardening", command=lambda: self._run_bg(anti_recon.disable_stealth_sysctls, self.env)).pack(side="left", padx=6)

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=8)
        ttk.Button(row2, text="Enable portscan auto-block", command=lambda: self._run_bg(anti_recon.enable_portscan_protection, self.env)).pack(side="left")
        ttk.Button(row2, text="Disable portscan auto-block", command=lambda: self._run_bg(anti_recon.disable_portscan_protection, self.env)).pack(side="left", padx=6)

        ttk.Separator(f).pack(fill="x", padx=8, pady=8)
        ttk.Label(f, text="Live scan watch (scapy, full Linux + root, bounded duration):").pack(anchor="w", padx=8)
        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=4)
        ttk.Label(row3, text="Duration (s):").pack(side="left")
        self.scan_duration = ttk.Entry(row3, width=6); self.scan_duration.insert(0, "120"); self.scan_duration.pack(side="left", padx=4)
        self.scan_autoblock = tk.BooleanVar()
        ttk.Checkbutton(row3, text="Auto-block detected scanners", variable=self.scan_autoblock).pack(side="left", padx=8)
        ttk.Button(row3, text="Start Watch", command=self._start_scan_watch).pack(side="left", padx=6)

        ttk.Separator(f).pack(fill="x", padx=8, pady=8)
        ttk.Label(f, text="Watch an HTTP access log (Termux-friendly, alert-only):").pack(anchor="w", padx=8)
        row4 = ttk.Frame(f); row4.pack(fill="x", padx=8, pady=4)
        self.log_path_var = tk.StringVar()
        ttk.Entry(row4, textvariable=self.log_path_var, width=50).pack(side="left", padx=4)
        ttk.Button(row4, text="Browse", command=self._browse_log).pack(side="left")
        ttk.Button(row4, text="Start", command=self._start_log_watch).pack(side="left", padx=6)
        ttk.Button(row4, text="Stop", command=lambda: self.watch_stop_event.set()).pack(side="left")

    def _start_scan_watch(self):
        try:
            dur = int(self.scan_duration.get().strip())
        except ValueError:
            dur = 120
        self._run_bg(anti_recon.live_scan_watch, self.env, 8, 10, self.scan_autoblock.get(), dur)

    def _browse_log(self):
        path = filedialog.askopenfilename(title="Select access log")
        if path:
            self.log_path_var.set(path)

    def _start_log_watch(self):
        path = self.log_path_var.get().strip()
        if not path:
            messagebox.showerror("Missing path", "Choose a log file first.")
            return
        self.watch_stop_event.clear()
        self._run_bg(anti_recon.watch_http_access_log, path, 10, 20, self.watch_stop_event)

    # ------------------------------------------------------------
    def _build_vm_tab(self):
        f = self.tab_vm
        ttk.Label(f, text="Reset a pentest VM to a clean snapshot (run from the HOST — has no effect inside a guest).").pack(anchor="w", padx=8, pady=8)
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text="Hypervisor:").pack(side="left")
        self.hv_var = tk.StringVar(value="vbox")
        ttk.Combobox(row, textvariable=self.hv_var, values=["vbox", "virsh"], width=10, state="readonly").pack(side="left", padx=6)
        ttk.Label(row, text="VM/domain name:").pack(side="left")
        self.vm_name = ttk.Entry(row, width=20); self.vm_name.pack(side="left", padx=6)
        ttk.Label(row, text="Snapshot:").pack(side="left")
        self.vm_snap = ttk.Entry(row, width=20); self.vm_snap.pack(side="left", padx=6)
        ttk.Button(f, text="Reset to Snapshot", command=self._reset_vm).pack(anchor="w", padx=8, pady=8)

    def _reset_vm(self):
        name, snap, hv = self.vm_name.get().strip(), self.vm_snap.get().strip(), self.hv_var.get()
        if not name or not snap:
            messagebox.showerror("Missing info", "Enter both VM/domain name and snapshot name.")
            return
        fn = vm_snapshot.reset_vbox_snapshot if hv == "vbox" else vm_snapshot.reset_virsh_snapshot
        self._run_bg(fn, name, snap)

    # ------------------------------------------------------------
    def _build_logs_tab(self):
        f = self.tab_logs
        ttk.Label(f, text="Clean local traces (shell history, optionally system logs with root):").pack(anchor="w", padx=8, pady=8)
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        self.wipe_logs_var = tk.BooleanVar()
        ttk.Checkbutton(row, text="Also wipe /var/log (root required, irreversible)", variable=self.wipe_logs_var).pack(side="left")
        ttk.Button(row, text="Clean Traces", command=lambda: self._run_bg(core.clean_traces, self.env, self.wipe_logs_var.get())).pack(side="left", padx=6)

        ttk.Separator(f).pack(fill="x", padx=8, pady=10)
        ttk.Label(f, text="Private encrypted session log (your own record; system traces are still wiped above):").pack(anchor="w", padx=8)
        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=4)
        ttk.Label(row2, text="Passphrase:").pack(side="left")
        self.save_pass = ttk.Entry(row2, show="*", width=20); self.save_pass.pack(side="left", padx=4)
        ttk.Button(row2, text="Save Encrypted Log", command=self._save_log).pack(side="left", padx=6)

        row3 = ttk.Frame(f); row3.pack(fill="x", padx=8, pady=8)
        self.decrypt_path_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self.decrypt_path_var, width=40).pack(side="left", padx=4)
        ttk.Button(row3, text="Browse", command=self._browse_enc).pack(side="left")
        ttk.Label(row3, text="Passphrase:").pack(side="left", padx=(10, 0))
        self.decrypt_pass = ttk.Entry(row3, show="*", width=20); self.decrypt_pass.pack(side="left", padx=4)
        ttk.Button(row3, text="Decrypt & Show", command=self._decrypt_log).pack(side="left", padx=6)

        ttk.Separator(f).pack(fill="x", padx=8, pady=10)
        ttk.Label(f, text="RAM/app hygiene (ported from AnonSurf's Pandora):").pack(anchor="w", padx=8)
        row4 = ttk.Frame(f); row4.pack(fill="x", padx=8, pady=4)
        ttk.Button(row4, text="Kill risky apps now (browsers/chat clients)",
                   command=lambda: self._run_bg(ram_wipe.kill_risky_apps, self.env)).pack(side="left")

        row5 = ttk.Frame(f); row5.pack(fill="x", padx=8, pady=4)
        ttk.Label(row5, text="RAM wipe mode:").pack(side="left")
        self.ram_mode_var = tk.StringVar(value="fast")
        ttk.Combobox(row5, textvariable=self.ram_mode_var, values=["fast", "thorough"],
                     width=10, state="readonly").pack(side="left", padx=4)
        ttk.Button(row5, text="Wipe Free RAM Now",
                   command=lambda: self._run_bg(ram_wipe.wipe_free_ram, self.env, self.ram_mode_var.get())).pack(side="left", padx=6)
        ttk.Button(row5, text="Install Shutdown Hook",
                   command=lambda: self._run_bg(ram_wipe.install_shutdown_hook, self.env, self.ram_mode_var.get())).pack(side="left", padx=6)
        ttk.Button(row5, text="Remove Shutdown Hook",
                   command=lambda: self._run_bg(ram_wipe.remove_shutdown_hook, self.env)).pack(side="left")
        ttk.Label(f, text="Needs `secure-delete` (sdmem) installed for a real overwrite — otherwise this only drops caches.",
                  foreground="#a05a00").pack(anchor="w", padx=8, pady=(2, 8))

    def _save_log(self):
        pw = self.save_pass.get()
        if not pw:
            messagebox.showerror("Missing passphrase", "Enter a passphrase to encrypt the log.")
            return
        self._run_bg(self.logger.save, pw)

    def _browse_enc(self):
        path = filedialog.askopenfilename(title="Select .enc log", filetypes=[("Encrypted log", "*.enc")])
        if path:
            self.decrypt_path_var.set(path)

    def _decrypt_log(self):
        path, pw = self.decrypt_path_var.get().strip(), self.decrypt_pass.get()
        if not path or not pw:
            messagebox.showerror("Missing info", "Choose a file and enter its passphrase.")
            return

        def do():
            try:
                for e in crypto_log.EncryptedLogger.decrypt(path, pw):
                    print(f"  [{e['ts']}] {e['msg']}")
            except Exception as e:
                print(f"[!] Decrypt failed: {e}")
        self._run_bg(do)

    # ------------------------------------------------------------
    def _build_vpn_tab(self):
        f = self.tab_vpn
        ttk.Label(f, text="Chain a VPN under Tor/proxy: start the VPN first, then enable a kill switch — "
                          "it rides on top automatically.").pack(anchor="w", padx=8, pady=8)

        ttk.Label(f, text="OpenVPN:").pack(anchor="w", padx=8)
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        self.ovpn_config_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ovpn_config_var, width=40).pack(side="left", padx=4)
        ttk.Button(row, text="Browse .ovpn", command=self._browse_ovpn).pack(side="left")
        row1b = ttk.Frame(f); row1b.pack(fill="x", padx=8, pady=4)
        ttk.Label(row1b, text="Auth file (optional):").pack(side="left")
        self.ovpn_auth_var = tk.StringVar()
        ttk.Entry(row1b, textvariable=self.ovpn_auth_var, width=30).pack(side="left", padx=4)
        ttk.Button(row1b, text="Start OpenVPN", command=self._start_openvpn).pack(side="left", padx=6)
        ttk.Button(row1b, text="Stop OpenVPN", command=lambda: self._run_bg(vpn.stop_openvpn, self.env)).pack(side="left")

        ttk.Separator(f).pack(fill="x", padx=8, pady=10)
        ttk.Label(f, text="WireGuard:").pack(anchor="w", padx=8)
        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=4)
        ttk.Label(row2, text="Interface:").pack(side="left")
        self.wg_iface_var = tk.StringVar(value="wg0")
        ttk.Entry(row2, textvariable=self.wg_iface_var, width=10).pack(side="left", padx=4)
        ttk.Button(row2, text="Start WireGuard",
                   command=lambda: self._run_bg(vpn.start_wireguard, self.env, self.wg_iface_var.get())).pack(side="left", padx=6)
        ttk.Button(row2, text="Stop WireGuard",
                   command=lambda: self._run_bg(vpn.stop_wireguard, self.env, self.wg_iface_var.get())).pack(side="left")
        ttk.Label(f, text="Both need root + full Linux — no Termux VPN client support.",
                  foreground="#a05a00").pack(anchor="w", padx=8, pady=(8, 0))

    def _browse_ovpn(self):
        path = filedialog.askopenfilename(title="Select .ovpn config", filetypes=[("OpenVPN config", "*.ovpn")])
        if path:
            self.ovpn_config_var.set(path)

    def _start_openvpn(self):
        cfg = self.ovpn_config_var.get().strip()
        if not cfg:
            messagebox.showerror("Missing config", "Choose a .ovpn config file first.")
            return
        auth = self.ovpn_auth_var.get().strip() or None
        self._run_bg(vpn.start_openvpn, self.env, cfg, auth)

    # ------------------------------------------------------------
    def _build_profiles_tab(self):
        f = self.tab_profiles
        ttk.Label(f, text="Encrypted saved profiles (proxy list + bridges) so you're not retyping them every session.").pack(anchor="w", padx=8, pady=8)

        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text="Profile name:").pack(side="left")
        self.profile_name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.profile_name_var, width=20).pack(side="left", padx=4)
        ttk.Label(row, text="Passphrase:").pack(side="left")
        self.profile_pass_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.profile_pass_var, show="*", width=16).pack(side="left", padx=4)

        ttk.Label(f, text="Proxy lines (one per line):").pack(anchor="w", padx=8)
        self.profile_proxies_text = tk.Text(f, height=4)
        self.profile_proxies_text.pack(fill="x", padx=8, pady=2)
        ttk.Label(f, text="Bridge lines (one per line):").pack(anchor="w", padx=8)
        self.profile_bridges_text = tk.Text(f, height=4)
        self.profile_bridges_text.pack(fill="x", padx=8, pady=2)

        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=6)
        ttk.Button(row2, text="Save Profile", command=self._save_profile).pack(side="left")
        ttk.Button(row2, text="Load Profile", command=self._load_profile).pack(side="left", padx=6)
        ttk.Button(row2, text="List Profiles", command=lambda: self._run_bg(self._list_profiles)).pack(side="left")

    def _list_profiles(self):
        names = profiles.list_profiles()
        print("Saved profiles: " + (", ".join(names) if names else "(none)"))

    def _save_profile(self):
        name, pw = self.profile_name_var.get().strip(), self.profile_pass_var.get()
        if not name or not pw:
            messagebox.showerror("Missing info", "Enter a profile name and passphrase.")
            return
        data = {
            "proxies": [l for l in self.profile_proxies_text.get("1.0", "end").splitlines() if l.strip()],
            "bridges": [l for l in self.profile_bridges_text.get("1.0", "end").splitlines() if l.strip()],
        }
        self._run_bg(profiles.save_profile, name, data, pw)

    def _load_profile(self):
        name, pw = self.profile_name_var.get().strip(), self.profile_pass_var.get()
        if not name or not pw:
            messagebox.showerror("Missing info", "Enter a profile name and passphrase.")
            return

        def do():
            try:
                data = profiles.load_profile(name, pw)
                self.profile_proxies_text.delete("1.0", "end")
                self.profile_proxies_text.insert("end", "\n".join(data.get("proxies", [])))
                self.profile_bridges_text.delete("1.0", "end")
                self.profile_bridges_text.insert("end", "\n".join(data.get("bridges", [])))
                print(f"[+] Loaded profile '{name}'.")
            except Exception as e:
                print(f"[!] Load failed: {e}")
        self._run_bg(do)

    # ------------------------------------------------------------
    def _build_monitor_tab(self):
        f = self.tab_monitor
        ttk.Label(f, text="Continuous leak monitoring — periodically re-checks Tor/DNS/IP during a "
                          "session and alerts here if something changes unexpectedly.").pack(anchor="w", padx=8, pady=8)
        row = ttk.Frame(f); row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text="Check interval (s):").pack(side="left")
        self.monitor_interval_var = tk.StringVar(value="30")
        ttk.Entry(row, textvariable=self.monitor_interval_var, width=6).pack(side="left", padx=4)
        self.monitor_expect_tunnel_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Expect a tunnel active (flag DNS/Tor leaks)",
                         variable=self.monitor_expect_tunnel_var).pack(side="left", padx=8)
        row2 = ttk.Frame(f); row2.pack(fill="x", padx=8, pady=4)
        ttk.Button(row2, text="Start Monitor", command=self._start_monitor).pack(side="left")
        ttk.Button(row2, text="Stop Monitor", command=self._stop_monitor).pack(side="left", padx=6)
        self.monitor_status_var = tk.StringVar(value="Monitor: stopped")
        ttk.Label(f, textvariable=self.monitor_status_var).pack(anchor="w", padx=8, pady=(8, 0))

    def _monitor_alert(self, msg):
        self.log_q.put(f"[MONITOR ALERT] {msg}\n")

    def _start_monitor(self):
        if self.leak_monitor and self.leak_monitor.is_running():
            messagebox.showinfo("Already running", "The leak monitor is already running.")
            return
        try:
            interval = int(self.monitor_interval_var.get().strip())
        except ValueError:
            interval = 30
        self.leak_monitor = monitor.LeakMonitor(self.env, interval=interval, on_alert=self._monitor_alert,
                                                  expect_tunnel=self.monitor_expect_tunnel_var.get())
        self.leak_monitor.start()
        self.monitor_status_var.set(f"Monitor: running (every {interval}s)")

    def _stop_monitor(self):
        if self.leak_monitor:
            self.leak_monitor.stop()
        self.monitor_status_var.set("Monitor: stopped")


def launch():
    app = PrivacyGuardGUI()
    app.mainloop()


if __name__ == "__main__":
    launch()
