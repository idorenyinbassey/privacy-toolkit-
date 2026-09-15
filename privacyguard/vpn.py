"""
VPN layer — OpenVPN and WireGuard, for chaining VPN -> Tor or VPN ->
proxy (start the VPN first, then any kill switch's default-route
redirect automatically rides on top of it). Full Linux + root only;
no Termux support (no VPN client tooling assumed there).
"""
import subprocess
import time
from pathlib import Path

from . import environment as envmod
from . import state as statemod

OPENVPN_PID_FILE = Path("/var/run/privacyguard-openvpn.pid")


# --------------------------------------------------------------------
# OpenVPN
# --------------------------------------------------------------------

def start_openvpn(env: envmod.Environment, config_path: str, auth_file: str = None) -> bool:
    if env.termux or not env.root:
        print("[!] OpenVPN control needs root + full Linux — skipped.")
        return False
    if not envmod.have("openvpn"):
        print("[!] openvpn not installed. sudo apt install openvpn")
        return False
    if not Path(config_path).exists():
        print(f"[!] Config not found: {config_path}")
        return False
    if statemod.get("vpn_active"):
        print(f"[i] A VPN is already marked active ({statemod.get('vpn_active')}) — stop it first.")
        return False

    cmd = ["openvpn", "--config", config_path, "--daemon", "privacyguard-openvpn",
           "--writepid", str(OPENVPN_PID_FILE)]
    if auth_file:
        cmd += ["--auth-user-pass", auth_file]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        time.sleep(3)
        if OPENVPN_PID_FILE.exists():
            print(f"[+] OpenVPN started with {config_path}")
            statemod.update(vpn_active=f"openvpn:{config_path}")
            return True
        print("[!] OpenVPN daemon didn't leave a PID file — it may have failed to start. Check `journalctl -u openvpn`.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to start OpenVPN: {e.stderr.decode() if e.stderr else e}")
        return False


def stop_openvpn(env: envmod.Environment) -> None:
    if env.termux or not env.root:
        return
    if OPENVPN_PID_FILE.exists():
        try:
            pid = OPENVPN_PID_FILE.read_text().strip()
            subprocess.run(["kill", pid], check=False)
            OPENVPN_PID_FILE.unlink()
            print("[+] OpenVPN stopped.")
        except Exception as e:
            print(f"[!] Could not stop OpenVPN cleanly: {e}")
    else:
        subprocess.run(["pkill", "-x", "openvpn"], capture_output=True)
        print("[+] Sent stop signal to any running openvpn process.")
    if (statemod.get("vpn_active") or "").startswith("openvpn:"):
        statemod.update(vpn_active=None)


# --------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------

def start_wireguard(env: envmod.Environment, interface: str = "wg0") -> bool:
    if env.termux or not env.root:
        print("[!] WireGuard control needs root + full Linux — skipped.")
        return False
    if not envmod.have("wg-quick"):
        print("[!] wg-quick not installed. sudo apt install wireguard")
        return False
    if statemod.get("vpn_active"):
        print(f"[i] A VPN is already marked active ({statemod.get('vpn_active')}) — stop it first.")
        return False
    try:
        subprocess.run(["wg-quick", "up", interface], check=True, capture_output=True, text=True)
        print(f"[+] WireGuard interface {interface} up.")
        statemod.update(vpn_active=f"wireguard:{interface}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to bring up WireGuard: {e.stderr or e}")
        return False


def stop_wireguard(env: envmod.Environment, interface: str = "wg0") -> None:
    if env.termux or not env.root:
        return
    try:
        subprocess.run(["wg-quick", "down", interface], check=True, capture_output=True, text=True)
        print(f"[+] WireGuard interface {interface} down.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to bring down WireGuard: {e.stderr or e}")
    if (statemod.get("vpn_active") or "").startswith("wireguard:"):
        statemod.update(vpn_active=None)


def vpn_status() -> str:
    return statemod.get("vpn_active") or "none"
