# Troubleshooting

## "I enabled the kill switch and lost internet access"

**Root cause (fixed in 2.2.1):** the kill switch redirects all traffic
to Tor's TransPort (9040) and DNSPort (5353).
If `/etc/tor/torrc` doesn't have those ports configured, or Tor never
actually finished bootstrapping, nothing is listening on those ports
— every connection just fails. Older versions applied the firewall
regardless and left you stuck with no working path out.

**Current versions auto-fix this**: `enable_kill_switch` now checks
Tor is installed, writes the required torrc lines itself if missing,
restarts Tor, waits up to 30s for it to actually bootstrap, and
**refuses to touch the firewall at all** if Tor never comes up —
instead of applying a firewall with no working exit.

**If you're on an affected version or still see this:**
```bash
# Immediate fix — restore internet access:
sudo privacyguard
> 6    enable or disable? disable
```
(or, if it won't respond because the CLI itself can't reach anything
either — that's fine, `iptables -F` doesn't need internet: run it
directly: `sudo iptables -F && sudo iptables -t nat -F && sudo iptables -P OUTPUT ACCEPT`)

Then check why Tor didn't come up:
```bash
sudo systemctl status tor
sudo journalctl -u tor -n 50
```
Common causes: Tor not installed (`sudo apt install tor`), a firewall
elsewhere blocking Tor's own outbound connections, or the VM's clock
being badly wrong (Tor refuses to bootstrap with a sufficiently
incorrect system time).

## "GUI buttons say 'requires root' / nothing happens"

The GUI must itself run as root for root-gated features (kill switch,
MAC randomization, sysctls, RAM wipe, gateway mode) — read-only
buttons (leak report, DNS check) work without it.
```bash
sudo privacyguard-gui
# or, if pipx-installed and sudo can't find it on PATH:
sudo $(which privacyguard-gui)
```

## "privacyguard-gui: ModuleNotFoundError: No module named 'tkinter'"

tkinter is a compiled extension tied to your system Python, not a pip
package — `pip`/`pipx inject` can't add it after the fact.
```bash
sudo apt install python3-tk
# if installed via pipx, then:
pipx reinstall privacyguard
```
Order matters: install `python3-tk` *before* the pipx install, or
reinstall afterward — a plain `pipx upgrade` won't pick up a
system-level change like this.

## "DNS leak check says I'm leaking, but I'm on a VirtualBox NAT network"

In VirtualBox's default NAT mode, your VM's "real" resolver is often
the hypervisor's internal proxy (e.g. `10.0.2.3`), not your actual
ISP's DNS — that's expected and not a leak by itself. What actually
matters: when a kill switch is active, is that non-loopback resolver
still the one *answering* queries, or has Tor's DNSPort taken over?
Run the check once with no kill switch active to see your NAT
baseline, so you can tell "normal NAT plumbing" apart from "actually
leaking" later.

## "Workstation isolation check (menu 30) fails with 2 interfaces found"

This means the workstation VM has more than one virtual NIC — the
whole point of gateway mode is that it should have exactly one. This
isn't fixable from inside the guest; go to the **host** and check the
VM's network adapter settings (VirtualBox: Settings → Network — only
Adapter 1 should be enabled, attached to the internal network created
in menu 28; every other adapter should be "Not attached").

## "VBoxManage not found" inside a Kali VM

Expected, not a bug — `VBoxManage` is a host-side tool for controlling
VMs from outside. Menu 14 (VM snapshot reset) and menu 28 (gateway
topology wiring) are meant to run on your actual VirtualBox **host**,
never from inside a guest.

## "cryptography install fails on Termux"

Usually a missing Rust toolchain (the `cryptography` package compiles
some components in Rust):
```bash
pkg install rust clang
pip install cryptography
```

## "Portscan protection blocked my own legitimate traffic"

The default is >15 connections from one source within 60 seconds. If
your own tooling naturally exceeds that:
```
8   enable/disable: disable
```
then re-enable with different parameters (the CLI menu doesn't expose
custom hitcount/seconds directly — call `anti_recon.enable_portscan_protection(env, hitcount=30, seconds=60)`
from a Python shell, or adjust the defaults in `anti_recon.py` if this
is a recurring need for your setup).

## Still stuck?

Run `python3 main.py --status` (or menu 1) and check the environment
summary for anything unexpected — missing tools, root showing "no"
when you expected "yes," or an interface not showing up all point to
the actual cause faster than guessing from symptoms.
