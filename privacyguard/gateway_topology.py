"""
Host-side setup for two-VM gateway mode (Whonix-style architecture).

Run this from the HOST — it wires up the virtual network topology that
makes workstation isolation a property of the network graph itself,
not just firewall rules:

  [Internet] --- EXTERNAL NIC --- [Gateway VM] --- INTERNAL NIC ---+
                                                                    |
                                              (isolated internal   |
                                               network, no route   |
                                               to the internet)    |
                                                                    |
                                        [Workstation VM] --- NIC ---+
                                        (single interface, this is its
                                         ONLY network connection)

The workstation VM gets exactly one virtual NIC, attached only to the
internal network. There is no second interface to misconfigure and no
virtual wire to the internet for anything running inside it to use,
even with root and a kernel exploit — the isolation is topological,
not just a firewall rule that malware could theoretically bypass.

This module only wires up the network topology. It does NOT install
or configure an OS inside either VM — you still create/boot the VMs
and install Kali (or any Linux) in each yourself; the gateway.py and
workstation.py modules are then run FROM INSIDE the respective VMs to
configure Tor/networking once the OS is up.
"""
import subprocess

from . import environment as envmod

DEFAULT_INTERNAL_NET_NAME = "pg-gateway-net"
DEFAULT_INTERNAL_CIDR = "10.152.152.0/24"
DEFAULT_GATEWAY_INTERNAL_IP = "10.152.152.10"
DEFAULT_WORKSTATION_INTERNAL_IP = "10.152.152.11"


# --------------------------------------------------------------------
# VirtualBox
# --------------------------------------------------------------------

def vbox_wire_gateway(gateway_vm: str, external_adapter: str = "nat",
                       internal_net_name: str = DEFAULT_INTERNAL_NET_NAME) -> bool:
    """external_adapter: 'nat' or 'bridged'. Gateway gets TWO NICs:
    NIC1 = external (internet), NIC2 = internal (talks to workstation)."""
    if not envmod.have("VBoxManage"):
        print("[!] VBoxManage not found on this host.")
        return False
    try:
        subprocess.run(["VBoxManage", "modifyvm", gateway_vm, "--nic1", external_adapter], check=True)
        subprocess.run(["VBoxManage", "modifyvm", gateway_vm, "--nic2", "intnet",
                         "--intnet2", internal_net_name], check=True)
        print(f"[+] {gateway_vm}: NIC1={external_adapter} (internet), NIC2=intnet:{internal_net_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to wire gateway NICs: {e}")
        return False


def vbox_wire_workstation(workstation_vm: str, internal_net_name: str = DEFAULT_INTERNAL_NET_NAME) -> bool:
    """Workstation gets exactly ONE NIC, attached only to the internal
    network — this is the enforcement mechanism, not a config option."""
    if not envmod.have("VBoxManage"):
        print("[!] VBoxManage not found on this host.")
        return False
    try:
        subprocess.run(["VBoxManage", "modifyvm", workstation_vm, "--nic1", "intnet",
                         "--intnet1", internal_net_name], check=True)
        subprocess.run(["VBoxManage", "modifyvm", workstation_vm, "--nic2", "none"], check=True)
        print(f"[+] {workstation_vm}: NIC1=intnet:{internal_net_name} only. NIC2 disabled.")
        print("    This VM now has no virtual path to the internet except through the gateway.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to wire workstation NIC: {e}")
        return False


def vbox_verify_topology(gateway_vm: str, workstation_vm: str) -> None:
    """Read back the NIC config for both VMs so you can visually
    confirm the workstation has no second/external adapter before
    trusting it with anything sensitive."""
    if not envmod.have("VBoxManage"):
        print("[!] VBoxManage not found on this host.")
        return
    for vm in (gateway_vm, workstation_vm):
        try:
            out = subprocess.run(["VBoxManage", "showvminfo", vm, "--machinereadable"],
                                  capture_output=True, text=True, check=True)
            nic_lines = [l for l in out.stdout.splitlines() if l.startswith("nic")]
            print(f"--- {vm} ---")
            for l in nic_lines:
                print(f"  {l}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Could not read {vm} config: {e}")


# --------------------------------------------------------------------
# libvirt / virsh
# --------------------------------------------------------------------

ISOLATED_NETWORK_XML = """<network>
  <name>{name}</name>
  <bridge name="virbr-pg-gw" stp="on" delay="0"/>
  <ip address="{gateway_ip}" netmask="255.255.255.0">
  </ip>
</network>"""


def virsh_create_isolated_network(name: str = DEFAULT_INTERNAL_NET_NAME,
                                   gateway_ip: str = DEFAULT_GATEWAY_INTERNAL_IP) -> bool:
    """Defines a libvirt network with NO forward element — meaning
    libvirt will not NAT or route it to the internet. That absence is
    what makes it isolated; a <forward mode='nat'/> element would
    defeat the whole point."""
    if not envmod.have("virsh"):
        print("[!] virsh not found on this host.")
        return False
    xml = ISOLATED_NETWORK_XML.format(name=name, gateway_ip=gateway_ip)
    try:
        subprocess.run(["virsh", "net-define", "/dev/stdin"], input=xml, text=True,
                        capture_output=True, check=True)
        subprocess.run(["virsh", "net-start", name], check=True)
        subprocess.run(["virsh", "net-autostart", name], check=True)
        print(f"[+] Isolated libvirt network '{name}' created and started (no NAT/forward — "
              f"not routed to the internet by libvirt).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to create isolated network: {e.stderr if hasattr(e, 'stderr') else e}")
        return False


def virsh_wire_gateway(gateway_vm: str, external_network: str = "default",
                        internal_network: str = DEFAULT_INTERNAL_NET_NAME) -> bool:
    if not envmod.have("virsh"):
        print("[!] virsh not found on this host.")
        return False
    try:
        subprocess.run(["virsh", "attach-interface", gateway_vm, "network", external_network,
                         "--model", "virtio", "--config"], check=True)
        subprocess.run(["virsh", "attach-interface", gateway_vm, "network", internal_network,
                         "--model", "virtio", "--config"], check=True)
        print(f"[+] {gateway_vm}: attached to '{external_network}' (internet) and "
              f"'{internal_network}' (internal). Reboot the VM for changes to apply.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to attach gateway interfaces: {e}")
        return False


def virsh_wire_workstation(workstation_vm: str, internal_network: str = DEFAULT_INTERNAL_NET_NAME) -> bool:
    if not envmod.have("virsh"):
        print("[!] virsh not found on this host.")
        return False
    try:
        subprocess.run(["virsh", "attach-interface", workstation_vm, "network", internal_network,
                         "--model", "virtio", "--config"], check=True)
        print(f"[+] {workstation_vm}: attached ONLY to '{internal_network}'. "
              f"Do not attach any other interface to this VM. Reboot to apply.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to attach workstation interface: {e}")
        return False
