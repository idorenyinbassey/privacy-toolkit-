"""Environment detection: full Linux (root/non-root) vs Termux, tool availability."""
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


def is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or shutil.which("termux-info") is not None


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def have_module(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


@dataclass
class Environment:
    termux: bool
    root: bool
    distro: str
    has_iproute2: bool
    has_tor: bool
    has_obfs4proxy: bool
    has_proxychains: bool
    has_torsocks: bool
    has_macchanger: bool
    has_iptables: bool
    has_sysctl: bool
    has_vboxmanage: bool
    has_virsh: bool
    has_scapy: bool
    has_stem: bool
    has_cryptography: bool
    interfaces: list = field(default_factory=list)

    def summary(self) -> str:
        rows = [
            ("Platform", "Termux (Android)" if self.termux else platform.platform()),
            ("Distro", self.distro),
            ("Root/priv", "yes" if self.root else "no"),
            ("tor", "yes" if self.has_tor else "no"),
            ("obfs4proxy", "yes" if self.has_obfs4proxy else "no"),
            ("proxychains", "yes" if self.has_proxychains else "no"),
            ("torsocks", "yes" if self.has_torsocks else "no"),
            ("macchanger", "yes" if self.has_macchanger else "no"),
            ("iptables", "yes" if self.has_iptables else "no"),
            ("sysctl", "yes" if self.has_sysctl else "no"),
            ("VBoxManage", "yes" if self.has_vboxmanage else "no"),
            ("virsh (libvirt)", "yes" if self.has_virsh else "no"),
            ("scapy (python)", "yes" if self.has_scapy else "no"),
            ("stem (python)", "yes" if self.has_stem else "no"),
            ("cryptography (python)", "yes" if self.has_cryptography else "no"),
            ("Interfaces", ", ".join(self.interfaces) or "none detected"),
        ]
        width = max(len(r[0]) for r in rows)
        return "\n".join(f"{k.ljust(width)} : {v}" for k, v in rows)


def detect_environment() -> Environment:
    distro = "unknown"
    if Path("/etc/os-release").exists():
        try:
            text = Path("/etc/os-release").read_text()
            m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', text)
            if m:
                distro = m.group(1)
        except Exception:
            pass
    elif is_termux():
        distro = "Termux (Android userland)"

    interfaces = []
    if have("ip"):
        try:
            out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
            for line in out.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip().split("@")[0]
                    if name != "lo":
                        interfaces.append(name)
        except Exception:
            pass

    return Environment(
        termux=is_termux(),
        root=is_root(),
        distro=distro,
        has_iproute2=have("ip"),
        has_tor=have("tor"),
        has_obfs4proxy=have("obfs4proxy"),
        has_proxychains=have("proxychains") or have("proxychains4"),
        has_torsocks=have("torsocks"),
        has_macchanger=have("macchanger"),
        has_iptables=have("iptables"),
        has_sysctl=have("sysctl"),
        has_vboxmanage=have("VBoxManage"),
        has_virsh=have("virsh"),
        has_scapy=have_module("scapy"),
        has_stem=have_module("stem"),
        has_cryptography=have_module("cryptography"),
        interfaces=interfaces,
    )
