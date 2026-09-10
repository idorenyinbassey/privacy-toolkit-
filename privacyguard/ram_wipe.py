"""
RAM/cache hygiene — ported from AnonSurf's companion tool Pandora,
which kills apps likely to hold sensitive data in memory and
overwrites free RAM (defending against cold-boot/RAM-remnant
forensic attacks), including automatically on shutdown.

Two independent pieces:

1. kill_risky_apps() — closes common browsers/chat apps that tend to
   hold open tabs, session tokens, or chat history in memory. Same
   idea as AnonSurf's "kill dangerous applications" step, just run
   on-demand instead of forced at every start.

2. wipe_free_ram() — uses `sdmem` (from the `secure-delete` package)
   to allocate and overwrite unused RAM. This is the actual security
   measure; without `sdmem` this falls back to a plain cache drop,
   which is NOT a secure overwrite and is labeled as such.

install_shutdown_hook() registers a systemd unit so the wipe runs
automatically on every shutdown/reboot — the same automatic behavior
Pandora provides, opt-in here rather than forced.
"""
import subprocess
from pathlib import Path

from . import environment as envmod

RISKY_APPS = [
    "firefox", "firefox-esr", "chromium", "chromium-browser", "google-chrome",
    "thunderbird", "skype", "telegram-desktop", "discord", "signal-desktop",
    "slack", "zoom",
]

SHUTDOWN_SCRIPT_PATH = Path("/usr/local/bin/privacyguard-ramwipe.sh")
SYSTEMD_UNIT_PATH = Path("/etc/systemd/system/privacyguard-ramwipe.service")
SYSTEMD_UNIT_NAME = "privacyguard-ramwipe.service"


def kill_risky_apps(env: envmod.Environment, extra: list = None) -> None:
    apps = RISKY_APPS + (extra or [])
    killed = []
    for app in apps:
        result = subprocess.run(["pkill", "-9", "-x", app], capture_output=True)
        if result.returncode == 0:
            killed.append(app)
    if killed:
        print(f"[+] Killed running: {', '.join(killed)}")
    else:
        print("[i] None of the watched risky apps were running.")


def wipe_free_ram(env: envmod.Environment, mode: str = "fast") -> None:
    """mode: 'fast' (single low-priority pass, seconds) or 'thorough'
    (sdmem's default multi-pass overwrite, much slower on large RAM)."""
    if env.termux:
        print("[!] No RAM-wipe tooling available in Termux (needs root + sdmem on full Linux).")
        return
    if not env.root:
        print("[!] Needs root to overwrite free RAM.")
        return
    if env.has_sdmem:
        args = ["sdmem", "-f", "-v"]
        if mode == "fast":
            args.append("-l")
        try:
            subprocess.run(args, check=True)
            print(f"[+] Free RAM overwritten ({'fast/single-pass' if mode == 'fast' else 'thorough/multi-pass'}).")
        except subprocess.CalledProcessError as e:
            print(f"[!] sdmem failed: {e}")
    else:
        print("[!] sdmem not installed — falling back to a cache drop only.")
        print("    This frees clean cache pages but does NOT securely overwrite RAM contents.")
        print("    For a real wipe: sudo apt install secure-delete")
        try:
            subprocess.run("sync", shell=True, check=True)
            Path("/proc/sys/vm/drop_caches").write_text("3")
            print("[+] Page cache/dentries/inodes dropped.")
        except Exception as e:
            print(f"[!] Cache drop failed: {e}")


def install_shutdown_hook(env: envmod.Environment, mode: str = "fast") -> None:
    """Registers a systemd unit that runs the RAM wipe automatically
    on every shutdown/reboot/halt — Pandora's automatic behavior,
    opt-in here."""
    if env.termux or not env.root:
        print("[!] Needs root + systemd (full Linux only) — skipped.")
        return
    if not env.has_systemctl:
        print("[!] systemd not found — can't install an automatic shutdown hook here.")
        return

    if env.has_sdmem:
        sdmem_cmd = f"sdmem -f -v{' -l' if mode == 'fast' else ''}"
    else:
        sdmem_cmd = "sync; echo 3 > /proc/sys/vm/drop_caches  # sdmem not installed — cache drop only, not a real wipe"

    script = f"""#!/bin/sh
# Installed by PrivacyGuard — overwrites free RAM on shutdown.
{sdmem_cmd}
"""
    SHUTDOWN_SCRIPT_PATH.write_text(script)
    SHUTDOWN_SCRIPT_PATH.chmod(0o755)

    unit = f"""[Unit]
Description=PrivacyGuard RAM wipe on shutdown
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target

[Service]
Type=oneshot
ExecStart=/bin/true
ExecStop={SHUTDOWN_SCRIPT_PATH}
RemainAfterExit=yes
TimeoutStopSec=180

[Install]
WantedBy=shutdown.target reboot.target halt.target
"""
    SYSTEMD_UNIT_PATH.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", SYSTEMD_UNIT_NAME], check=False)
    print(f"[+] Shutdown hook installed ({mode} mode) — RAM overwrites automatically on shutdown/reboot.")
    print("    This adds delay to shutdown — thorough mode can take minutes on large RAM.")
    if not env.has_sdmem:
        print("    [!] sdmem isn't installed, so this hook currently only drops caches, not a real overwrite.")


def remove_shutdown_hook(env: envmod.Environment) -> None:
    if env.termux or not env.root:
        return
    subprocess.run(["systemctl", "disable", SYSTEMD_UNIT_NAME], capture_output=True)
    for p in (SYSTEMD_UNIT_PATH, SHUTDOWN_SCRIPT_PATH):
        if p.exists():
            p.unlink()
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("[+] Shutdown RAM-wipe hook removed.")
