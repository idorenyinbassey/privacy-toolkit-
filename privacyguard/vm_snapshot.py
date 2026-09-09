"""
Reset a pentest VM back to a clean snapshot before/after an engagement,
so no artifacts (loot, history, tool output, changed configs) persist
between sessions. Run this from the HOST machine (it shells out to
VBoxManage or virsh) — it has no effect run from inside the guest.
"""
import subprocess

from . import environment as envmod


def list_vbox_vms() -> list:
    try:
        out = subprocess.run(["VBoxManage", "list", "vms"], capture_output=True, text=True, check=True)
        return [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except Exception as e:
        print(f"[!] Could not list VirtualBox VMs: {e}")
        return []


def list_vbox_snapshots(vm_name: str) -> list:
    try:
        out = subprocess.run(["VBoxManage", "snapshot", vm_name, "list"], capture_output=True, text=True, check=True)
        return out.stdout.splitlines()
    except Exception as e:
        print(f"[!] Could not list snapshots for {vm_name}: {e}")
        return []


def reset_vbox_snapshot(vm_name: str, snapshot_name: str, power_off_first: bool = True) -> None:
    if not envmod.have("VBoxManage"):
        print("[!] VBoxManage not found on this host.")
        return
    try:
        if power_off_first:
            subprocess.run(["VBoxManage", "controlvm", vm_name, "poweroff"], capture_output=True)
        subprocess.run(["VBoxManage", "snapshot", vm_name, "restore", snapshot_name], check=True)
        print(f"[+] {vm_name} restored to snapshot '{snapshot_name}'.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Snapshot restore failed: {e}")


def list_virsh_domains() -> list:
    try:
        out = subprocess.run(["virsh", "list", "--all"], capture_output=True, text=True, check=True)
        return out.stdout.splitlines()
    except Exception as e:
        print(f"[!] Could not list libvirt domains: {e}")
        return []


def list_virsh_snapshots(domain: str) -> list:
    try:
        out = subprocess.run(["virsh", "snapshot-list", domain], capture_output=True, text=True, check=True)
        return out.stdout.splitlines()
    except Exception as e:
        print(f"[!] Could not list snapshots for {domain}: {e}")
        return []


def reset_virsh_snapshot(domain: str, snapshot_name: str) -> None:
    if not envmod.have("virsh"):
        print("[!] virsh not found on this host.")
        return
    try:
        subprocess.run(["virsh", "snapshot-revert", domain, snapshot_name, "--running"], check=True)
        print(f"[+] {domain} reverted to snapshot '{snapshot_name}'.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Snapshot revert failed: {e}")
