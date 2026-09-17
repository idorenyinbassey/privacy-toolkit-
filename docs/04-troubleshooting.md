# Troubleshooting

## "Tor connection resets/closes repeatedly, never stabilizes"

**Root cause (fixed in 2.2.10)**: two compounding issues, both worth
checking directly rather than guessing:

1. **An orphaned Tor process from manual troubleshooting** — if you've
   ever run `sudo -u debian-tor tor -f /etc/tor/torrc` by hand (e.g.
   to test bootstrap directly) and just closed the terminal or hit
   Ctrl+C without confirming it actually exited, that process can keep
   running in the background indefinitely, silently holding the ports
   this tool needs. Check:
   ```bash
   ps aux | grep -i tor
   ```
   If you see more than one `tor` process, kill them all and restart
   clean:
   ```bash
   sudo systemctl stop tor
   sudo pkill -9 -x tor
   sudo ss -tlnp | grep -E "9050|9040|5353"   # should print nothing
   sudo systemctl start tor
   ```

2. **Debian/Kali's multi-instance Tor packaging**: `tor.service` is
   often just a stub unit (`ExecStart=/bin/true`) that does nothing —
   the real daemon runs under `tor@default.service`. Confirm which is
   which on your system:
   ```bash
   systemctl list-units --all 'tor*'
   ```
   Look for `tor@default.service` with SUB state `running` — that's
   the real one. If `tor.service` shows `exited` and `tor@default`
   shows `running`, you're on the multi-instance setup, and versions
   before 2.2.10 were silently controlling the wrong unit on every
   start/stop/restart. Current versions detect this automatically.

## "Tor connection resets, then times out — but only after 20-30 seconds"

**Root cause (fixed in 2.2.9)**: the portscan-protection feature's
own INPUT rule had no loopback exclusion, so this tool's own repeated
local checks (polling Tor's SocksPort while waiting for bootstrap)
could trip its own anti-scan defense after enough attempts — a
self-inflicted block, not a real network or Tor problem. Recognizable
by the pattern: early attempts fail with a real response (`Connection
reset by peer`), later attempts cleanly become `timed out` (silent
`DROP`) and never recover.

**Upgrading from an affected version needs one extra step**: the rule
already sitting in your kernel is the OLD one — updating the code
alone doesn't retroactively change rules already applied by iptables.
Do this BEFORE pulling the upgrade, or the old broken rule stays
active even on the new code:
```bash
sudo privacyguard
> 8   (anti-recon: portscan auto-block)
disable
```
Or, if that won't respond because you're still blocked:
```bash
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
rm ~/.privacyguard_state.json
```
The state file removal matters here too — without it, this tool still
believes portscan protection (and possibly other things) are already
active from before the manual flush, and will refuse to re-apply them
correctly. Deleting it just resets to defaults; nothing else is lost.

Then upgrade and start fresh:
```bash
git pull
pipx install ".[full]" --force
sudo privacyguard
```

## "Tor never bootstraps, or crash-loops instead of starting"

**Root cause (fixed in 2.2.6)**: `/etc/tor/torrc` had two conflicting
`TransPort` (or `DNSPort`) directives both claiming the same port —
often because this tool's OWN pre-2.2.1 README told people to
manually add those lines before auto-configuration existed, and the
old auto-config logic only checked whether its own managed block was
present, never whether some OTHER line elsewhere in the file was also
claiming the same port. Tor refuses to bind a duplicate port and
exits immediately — repeatedly, in a crash loop — which from the
outside looks identical to "slow to bootstrap" or "hung," but isn't.

**How to tell the difference**: `sudo journalctl -u tor -n 50` showing
`Starting`/`Finished` at the same timestamp, repeating every few
seconds or minutes, is a crash loop — not a slow bootstrap. Confirm
directly:
```bash
sudo systemctl stop tor
sudo -u debian-tor tor -f /etc/tor/torrc
```
This runs Tor in the foreground and prints its own error output. A
`Bootstrapped 10%... 50%... 100%` climb means it's genuinely working
(just slow — raise `--bootstrap-timeout`). An immediate exit with a
`Could not bind` or similar error means a config conflict — check:
```bash
sudo cat /etc/tor/torrc
```
for more than one `TransPort` or `DNSPort` line. Current versions
(2.2.6+) detect and remove this automatically before ever applying
the kill switch; if you're on an older version or the conflict was
introduced by hand, clean it up manually:
```bash
sudo cp /etc/tor/torrc /etc/tor/torrc.backup
sudo tee /etc/tor/torrc > /dev/null << 'TORRC'
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
SocksPort 9050
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
RunAsDaemon 1
TORRC
sudo systemctl restart tor
```

## "I enabled the kill switch and lost internet access"

**Root cause (fixed in 2.2.1):** the kill switch redirects all traffic
to Tor's TransPort (9040) and DNSPort (5353).
If `/etc/tor/torrc` doesn't have those ports configured, or Tor never
actually finished bootstrapping, nothing is listening on those ports
— every connection just fails. Older versions applied the firewall
regardless and left you stuck with no working path out.

**Current versions auto-fix this**: `enable_kill_switch` now checks
Tor is installed, writes the required torrc lines itself if missing,
restarts Tor, waits (default 45s, configurable) for it to actually
bootstrap, and **refuses to touch the firewall at all** if Tor never
comes up — instead of applying a firewall with no working exit. In
2.2.2 the function also returns whether it actually succeeded, so
"Start FULL anonymity mode" correctly skips the verification report
instead of running it against a firewall that was never touched.

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
elsewhere blocking Tor's own outbound connections, the VM's clock
being badly wrong (Tor refuses to bootstrap with a sufficiently
incorrect system time), or simply a slow/filtered connection needing
more than the default wait — raise it with `--bootstrap-timeout 90`
(CLI flag) or the timeout field on the GUI's Tor tab before assuming
Tor is actually blocked rather than just slow.

## "I lost internet even though the tool said it did NOT enable the kill switch"

If the log shows `[!] Tor did not bootstrap ... NOT enabling the kill
switch` and you *still* lost connectivity, the kill switch isn't the
cause — something else that ran earlier in the same sequence is.
The most likely culprit: **MAC address randomization**, which runs
unconditionally as part of "Start FULL anonymity mode" before the
kill switch check.

**Why this happens:** on a **bridged** VM (sharing your actual LAN,
e.g. a `192.168.x.x`/`10.x.x.x` address that matches your router's
range — as opposed to VirtualBox's own NAT range), changing the
interface's MAC while keeping the same IP leaves your router's
DHCP lease / ARP table pointing at the *old* MAC. Traffic can stop
routing correctly until something forces a fresh DHCP negotiation —
which is why a full reboot fixes it (a clean boot renegotiates DHCP).

**Fixed in 2.2.3**: `randomize_mac()` now automatically attempts a
DHCP renewal via `nmcli device connect <iface>` right after changing
the MAC, best-effort. This resolves it on most NetworkManager-managed
setups (which includes current Kali). If your network is still slow
or stubborn about accepting the new MAC, or you'd rather not risk it
at all on a bridged VM:

- **Skip MAC/hostname randomization entirely**: CLI menu 17 now asks
  "randomize MAC/hostname too? [Y/n]" — answer `n`. Or use the flag:
  `privacyguard --start --no-randomize-identity`. The GUI's Tor tab has
  a matching checkbox next to "Start FULL anonymity mode."
- **If it still breaks after the auto-renewal**, manually force one:
  `sudo nmcli device connect eth0` (or restart NetworkManager:
  `sudo systemctl restart NetworkManager`).
- The kill switch and Tor-bootstrap logic are entirely independent of
  this — you can safely disable identity randomization while keeping
  the kill switch, sysctl hardening, and portscan protection active.

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
