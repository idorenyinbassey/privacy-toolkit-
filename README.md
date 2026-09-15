# PrivacyGuard v2

Environment-aware Python toolkit for privacy/anonymity + anti-recon
automation while running Kali (or any Linux) on a VM, in Termux, or
standalone. For authorized pentesting/red-team work and your own
systems' OPSEC hardening only.

## Layout

```
privacyguard/
  environment.py   - detects Termux vs full Linux, root, installed tools
  state.py         - persistent state tracking (what's actually active right now)
  firewall_backup.py - iptables/ip6tables backup+restore before any destructive flush
  core.py          - MAC/hostname randomization, Tor kill switch, trace cleanup
  proxy_tor.py     - Tor control, circuit rotation, bridges, proxychains (Tor optional)
  proxy_only.py    - system-wide routing through a plain proxy, NO Tor (redsocks, auth supported)
  anti_recon.py    - fingerprint hardening, portscan detection/block, log watch
  dns_check.py     - DNS leak detection
  vm_snapshot.py   - VirtualBox/libvirt snapshot reset (run from host)
  crypto_log.py    - encrypted local session log
  ram_wipe.py      - kill risky apps + overwrite free RAM (ported from AnonSurf's Pandora)
  verify.py        - actually tests a kill switch works, rather than trusting exit codes
  vpn.py           - OpenVPN / WireGuard start/stop/status
  profiles.py      - encrypted saved profiles (proxy lists, bridges)
  monitor.py       - background leak monitor, periodic re-check during a session
  gateway_topology.py - host-side VM network wiring for two-VM gateway mode
  gateway.py       - gateway-VM-side transparent Tor proxy for an isolated workstation
  workstation.py   - workstation-VM-side network config + isolation verification
  orchestrate.py   - shared "full start/stop" logic used by both CLI and GUI
main.py            - CLI (interactive menu + flags)
gui.py             - Tkinter desktop GUI (full Linux VM/standalone; not Termux)
tests/             - pytest suite (37 tests, no root/network needed to run)
pyproject.toml, requirements.txt - packaging
```

Run the test suite with `pytest tests/` — no root or real network needed;
subprocess/network calls are mocked. `python3 main.py --version` prints
the installed version.

Run the CLI with `python3 main.py` (menu) or flags: `--status --start
--stop --clean --rotate-ip --dns-leak-check --state --verify --gui`.
Run the GUI directly with `python3 gui.py` (needs a display — a VM or
standalone Linux desktop, not Termux's CLI-only environment; Debian/
Kali may need `sudo apt install python3-tk` first).

## Answers to specific capability questions

**"Protect against nikto/nmap/Metasploit/curl probing?"**
There's no way to selectively block a *tool* — those all just send
network traffic. What works, and what's implemented:
- Fingerprint hardening (silence ICMP ping, disable TCP timestamp
  leaks) — makes OS/uptime fingerprinting less reliable.
- iptables "recent module" auto-block: a source making an unusual
  number of new connections in a short window gets logged and dropped
  — this catches the connection *pattern* nmap/nikto/Metasploit's scan
  modules produce, not the tool name.
- Optional live scapy-based watcher that flags a source touching many
  distinct ports quickly and can auto-block it.
- On Termux (no root/netfilter) you only get log-watching/alerting for
  services you host there — no firewall blocking is possible.

**"Proxychains / encryption / decoys when Tor is blocked?"**
Yes:
- `proxy_tor.generate_proxychains_conf()` builds a proxychains config
  chaining your own SOCKS/HTTP proxies (dynamic, strict, or random
  chain mode) as decoy hops, with or without Tor in the chain.
- `proxy_tor.configure_bridges()` writes obfs4 (or other pluggable
  transport) bridge lines into torrc so Tor traffic looks like
  ordinary encrypted traffic to a censor/firewall. **You have to fetch
  real bridge lines yourself** from https://bridges.torproject.org —
  the tool can't invent working ones.

**"Reset/randomize system snapshots on VMs?"**
Yes, via `vm_snapshot.py` — wraps `VBoxManage snapshot ... restore`
and `virsh snapshot-revert`. This must be run from the **host**, not
the guest, since it controls the hypervisor.

**"Clear system trails but keep encrypted logs for my private use?"**
Yes — `core.clean_traces()` wipes shell history (and optionally
`/var/log/*` with root), while `crypto_log.py` keeps its own separate
record of what PrivacyGuard did this session, encrypted at rest with
a passphrase you choose (PBKDF2 + Fernet/AES). Only readable by you,
with your passphrase — there's no recovery if you lose it.

**"Randomize/spoof IP?"**
Not packet-level spoofing — that forges the source address in
outgoing packets, which breaks two-way TCP (replies go to the forged
address, not you) and is used almost exclusively for DoS
reflection/amplification, not anonymity. It's not something a
legitimate anonymity tool implements.

What actually changes your visible IP, and what's implemented instead:
- `proxy_tor.rotate_tor_circuit()` — requests a new Tor circuit
  (new exit IP) via the control port (needs `stem` + `ControlPort 9051`
  in torrc), falling back to `SIGHUP` if unavailable.
- `random_chain` mode in the proxychains generator — picks a different
  proxy from your list per connection.
- Swapping which VPN/proxy provider you're connected to, which is a
  manual choice outside what a script should automate for you.

## Gateway mode — two-VM Whonix-style architecture (2.2.0)

A single VM with a kill switch is protected at the software/firewall
level. Gateway mode is stronger: a **Tor gateway VM** with the only
real internet connection, and an **isolated workstation VM** whose
*only* network adapter connects to an internal-only network shared
with the gateway. The workstation has no virtual wire to the internet
at all — not a firewall rule blocking it, an actual absent connection.
Even a kernel-level compromise on the workstation can't leak your real
IP, because there's nothing to leak through.

```
[Internet] -- external NIC -- [Gateway VM] -- internal NIC --+
                                                               |
                                    (isolated network,        |
                                     no route out)             |
                                                               |
                                    [Workstation VM] -- NIC ---+
                                    (this is its ONLY adapter)
```

New modules: `gateway_topology.py` (host-side — wires the VM network
adapters via VBoxManage/virsh), `gateway.py` (run inside the gateway
VM — transparent Tor proxy for the internal network, with **no**
MASQUERADE/FORWARD-ACCEPT rule ever issued, which is the actual
mechanism enforcing Tor-only routing), `workstation.py` (run inside
the workstation VM — points its networking at the gateway, and
verifies the isolation actually holds: one interface, one route, one
DNS resolver).

### Setup (three steps, three different machines)

**1. On the HOST** (CLI menu 28, or GUI Gateway Mode tab, section 1):
create/pick two VMs, both running Kali (or any Linux) — install the OS
in each normally first, PrivacyGuard doesn't do that part. Then wire
the topology:
```
python3 main.py
> 28
hypervisor [vbox/virsh]: vbox
gateway VM name: kali-gateway
workstation VM name: kali-workstation
gateway's external adapter [nat/bridged] (default nat): nat
```
This gives the gateway VM two NICs (external + internal) and the
workstation VM exactly **one** NIC (internal only). Boot both VMs
after this.

**2. Inside the GATEWAY VM** (CLI menu 29, or GUI Gateway Mode tab,
section 2): install `tor`, then enable gateway mode:
```
python3 main.py
> 29
enable or disable? [enable/disable]: enable
internal interface [eth1]: eth1
internal IP [10.152.152.10]: 10.152.152.10
```
This writes the TransPort/DNSPort bindings into `/etc/tor/torrc`,
restarts Tor, and sets up the redirect rules. Restart tor manually if
the tool says to (`sudo systemctl restart tor`).

**3. Inside the WORKSTATION VM** (CLI menu 30, or GUI Gateway Mode
tab, section 3): point it at the gateway, then verify:
```
python3 main.py
> 30
configure networking or verify isolation? [configure/verify]: configure
this VM's interface [eth0]: eth0
this VM's static IP [10.152.152.11]: 10.152.152.11
gateway's internal IP [10.152.152.10]: 10.152.152.10
> 30
configure networking or verify isolation? [configure/verify]: verify
expected gateway IP [10.152.152.10]: 10.152.152.10
```
The verify step checks reality, not intent: exactly one non-loopback
interface, exactly one default route, DNS pointed only at the
gateway. If any of those fail, go recheck the VM's adapter settings on
the **host** — the isolation is a topology property, not something
this step can fix from inside the guest.

### What this does and doesn't cover

Covers: the workstation has no software-reachable path to the
internet except through the gateway's Tor redirect, even with a
workstation-side compromise, because the FORWARD chain default-drops
and no MASQUERADE rule ever exists to route it directly.

Doesn't cover: application-layer leaks inside the workstation
(browser fingerprinting, clipboard sharing if guest tools are
enabled), Tor's own timing-correlation limitations, or physical/host
compromise — same caveats as everywhere else in this toolkit, just
now with one less layer (the network topology itself) that a
workstation-side bug could undermine.

## Production hardening (2.1.0)

See CHANGELOG.md for the full list. Highlights:

- **Idempotent, state-tracked, backed-up.** Every enable/disable
  (Tor kill switch, proxy-only kill switch, IPv6 block, portscan
  protection, fingerprint sysctls) now checks `state.py` before
  acting — running enable twice is a safe no-op, not a duplicated
  ruleset. Before any destructive `iptables -F`, the current rules are
  backed up (`firewall_backup.py`) and restored exactly on disable,
  instead of flushing to a guessed-at default.
- **Actually verified, not just "the command returned 0."** `verify.py`
  tests a kill switch by attempting a real direct connection (should
  fail) and confirming the tunneled path works — run automatically
  after `full_start`, or on demand (CLI menu 24 / GUI "Verify" buttons).
- **Tested.** `tests/` — 37 pytest tests covering config generation,
  state persistence, and idempotency/backup-ordering with mocked
  subprocess calls. Run with `pytest tests/`; no root needed.
- **VPN chaining, saved profiles, continuous monitoring.** `vpn.py`
  (OpenVPN/WireGuard), `profiles.py` (encrypted saved proxy
  lists/bridges), `monitor.py` (background periodic leak re-check
  during a session, not just on-demand).
- **Proxy authentication** — username/password support in the
  proxy-only redsocks config.

## New in this version

**Proxychains without Tor.** Target hosts increasingly blocklist Tor's
TLS fingerprint and known relay IPs, so `proxy_tor.generate_proxychains_conf(...,
include_tor=False)` builds a chain of ordinary SOCKS5/HTTP proxies with
no Tor hop at all — app-level, works on Termux too (wrap a command
with `proxychains4 -f <conf> <command>`). For **system-wide** no-Tor
routing (full Linux + root), `proxy_only.py` uses redsocks to
transparently redirect all outbound TCP to your proxy, the same way
the Tor kill switch redirects to Tor — just pointed elsewhere. This
only covers TCP; always follow up with a DNS leak check.

**DNS leak check** (`dns_check.py`). Combines: (1) flagging any
non-loopback resolver in `/etc/resolv.conf` when a tunnel is supposed
to be active, and (2) a live check using Google's CHAOS-class TXT
trick (`o-o.myaddr.l.google.com`) that reveals the IP of whichever
resolver actually asked on your behalf — this catches leaks even
through a local stub resolver that quietly forwards elsewhere. Needs
`dig` (`dnsutils` on Debian/Kali). Run it after enabling any kill
switch (Tor or proxy-only) to confirm nothing's leaking.

**Desktop GUI** (`gui.py`). Tkinter, so no extra framework — tabs for
Status/DNS, Tor, Proxy (including the no-Tor options above), Anti-Recon,
VM Snapshots, and Cleanup/Logs, with a live console pane. Intended for
a full Linux desktop — a VM or standalone install with a display — not
Termux, which has no GUI by default.

**IPv6 leak blocking**, ported from AnonSurf. IPv6 has historically
been able to leak around IPv4-only iptables kill switches (and IPv6
addresses can embed a NIC's permanent MAC). Both the Tor kill switch
(`core.enable_kill_switch`) and the proxy-only kill switch
(`proxy_only.enable_proxy_kill_switch`) now also block all IPv6
traffic via `ip6tables` while active, and restore it automatically
when disabled. Full Linux + root only.

**RAM/app hygiene**, ported from AnonSurf's companion tool Pandora
(`ram_wipe.py`):
- `kill_risky_apps()` closes common browsers/chat clients that tend to
  hold sensitive data in memory (open tabs, session tokens, chat
  history) — same idea as AnonSurf's "kill dangerous applications"
  step, but run on-demand rather than forced on every start.
- `wipe_free_ram()` uses `sdmem` (from the `secure-delete` package) to
  overwrite unused RAM, defending against cold-boot/RAM-remnant
  attacks. Without `sdmem` installed it falls back to a plain cache
  drop and says so explicitly — that fallback is NOT a secure wipe.
- `install_shutdown_hook()` registers a systemd unit so the wipe runs
  automatically on every shutdown/reboot, mirroring Pandora's
  automatic behavior — opt-in here rather than forced. `fast` mode is
  a single low-priority pass (seconds); `thorough` uses sdmem's
  default multi-pass overwrite (can take minutes on large RAM and
  delays shutdown accordingly).
All of the above are also reachable as optional add-ons when stopping
full anonymity mode (CLI menu option 18, or `--stop` combined with
`--kill-risky-apps`/`--wipe-ram`), rather than forced automatically.

## Install

```bash
# Kali / Debian
sudo apt install tor obfs4proxy macchanger iptables proxychains4 torsocks
pip install pysocks stem cryptography scapy --break-system-packages

# Termux
pkg install tor obfs4proxy torsocks proxychains-ng python dnsutils
pip install pysocks stem cryptography

# For proxy-only system-wide routing and GUI (full Linux only)
sudo apt install redsocks python3-tk dnsutils

# For real RAM overwrite (optional but recommended over the fallback)
sudo apt install secure-delete
```

`cryptography` on Termux sometimes needs a Rust toolchain:
`pkg install rust clang` before `pip install cryptography` if the
wheel build fails.

## Kill switch / portscan-block prerequisites

Both need root + iptables (full Linux only, not Termux). The kill
switch additionally needs `/etc/tor/torrc` to contain:
```
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

## User Manual — CLI (`main.py`)

Works everywhere: Termux, a VM, or standalone Kali. Run it from the
project root (the folder containing `main.py` and `privacyguard/`).

### Quick flags (one-shot, no menu)

| Command | What it does |
|---|---|
| `python3 main.py` | Opens the interactive menu (below) |
| `python3 main.py --status` | Prints environment summary + leak report and exits |
| `python3 main.py --dns-leak-check` | Runs the DNS leak check and exits |
| `python3 main.py --start` | Starts full anonymity mode (Tor path) and exits |
| `python3 main.py --stop` | Stops full anonymity mode and exits |
| `python3 main.py --clean` | Wipes local shell-history traces and exits |
| `python3 main.py --rotate-ip` | Requests a new Tor circuit (new exit IP) and exits |
| `python3 main.py --gui` | Launches the desktop GUI (needs a display) |

### Interactive menu

Running `python3 main.py` with no flags drops you into a numbered
menu, re-shown after every action so you can chain steps:

```
=== PrivacyGuard v2 ===
Env: Kali GNU/Linux | root=True
 1) Environment + leak report
 2) DNS leak check
 3) Start / Stop Tor
 4) Rotate Tor circuit (new exit IP)
 5) Randomize MAC / hostname
 6) Enable / disable Tor kill switch
 7) Anti-recon: fingerprint hardening (sysctls)
 8) Anti-recon: portscan auto-block (iptables)
 9) Anti-recon: live scan watch (scapy, full Linux)
10) Anti-recon: watch HTTP access log (Termux-friendly)
11) Configure Tor bridges (Tor blocked on this network)
12) Generate/test proxychains config (Tor optional)
13) Proxy-only system-wide kill switch, NO Tor (redsocks)
14) VM snapshot reset (VirtualBox/virsh, run from host)
15) Clean local traces
16) Save / decrypt encrypted session log
17) Start FULL anonymity mode (Tor path)
18) Stop FULL anonymity mode
19) Launch GUI
20) Kill risky apps now (browsers/chat clients)
21) Wipe free RAM now (sdmem)
22) Install / remove automatic RAM-wipe-on-shutdown hook
23) Show current state (what's actually active right now)
24) Verify active kill switch (real test, not just "command succeeded")
25) VPN: start/stop OpenVPN or WireGuard
26) Save / load / list encrypted profile (proxy list, bridges, etc.)
27) Start / stop continuous leak monitor
28) Gateway mode: host-side VM network wiring
29) Gateway mode: configure THIS VM as the gateway
30) Gateway mode: configure THIS VM as the workstation
 0) Exit
>
```

Type the number and press Enter. Options that need more input (a
hostname, a passphrase, proxy lines) will prompt for it right after
you pick them. A typical session before a scan:

```
> 1          # confirm environment/root, note current public IP
> 17         # start full anonymity mode (Tor, MAC/hostname randomize, kill switch) - self-verifying
> 2          # then: y  -> DNS leak check, expecting a tunnel to be active
> 24         # spot-check the kill switch is genuinely blocking direct traffic
> 9          # optional: watch for scanners touching this box while you work
```
...and afterward:
```
> 18         # stop full anonymity mode, revert networking
> 15         # y/N -> also wipe /var/log if authorized to
> 16         # save -> encrypt this session's action log with a passphrase
```

Menu options 11 (bridges) and 12 (proxychains) accept **multi-line
paste**: type or paste one entry per line, then press Enter on an
empty line to finish and continue. Option 12 also accepts proxy lines
with credentials (`socks5 host port user pass`).

Option 13 (proxy-only kill switch) asks for the proxy host, port,
type, and optional username/password — use this instead of 17 when
the target network is known to block Tor traffic. It offers to run
verification (option 24's check) right after enabling. Both kill
switches (13 and the Tor one via 6/17) also block IPv6 automatically
while active, and both are idempotent — re-running enable while
already active is a safe no-op rather than a duplicated ruleset.

Option 18 (stop full anonymity mode) will ask whether to also kill
risky apps and/or wipe free RAM before reverting networking — say `y`
if you want that cleanup now rather than as a separate step via 20/21.
Option 22 installs or removes a systemd hook so RAM wipes automatically
on every shutdown/reboot, independent of whether PrivacyGuard is
running at the time.

Option 23 prints exactly what's active right now — useful after a
crash or a new session, since state persists across runs. Option 24
doesn't just check "is a kill switch marked on" — it attempts a real
direct connection and confirms it fails, confirms the tunneled path
works, and checks for DNS leaks.

Options 28–30 are gateway mode — a two-VM architecture stronger than a
single-VM kill switch. Each option runs on a *different* machine (the
host, then inside the gateway VM, then inside the workstation VM) —
see the "Gateway mode" section above for the full walkthrough.

## User Manual — GUI (`gui.py`)

Full Linux desktop only (a VM with a display, or standalone Kali/
Debian with X11) — Termux has no GUI, use the CLI there.

### Launching

```bash
python3 -c "import tkinter"     # sanity check; if it errors:
sudo apt install python3-tk     # Debian/Kali
cd privacy-toolkit-             # project root
python3 gui.py                  # or: python3 main.py --gui
```

A single window opens (900×700) with a row of tabs across the top and
a black **Console output** pane pinned across the bottom — every
action's output (successes, errors, leak reports) streams there in
real time, same text you'd see in the CLI.

A live **status bar** sits above the tabs, reading from `state.py`
every 2 seconds — Tor kill switch, proxy-only kill switch, IPv6
blocked, portscan protection, and VPN, each as an on/off dot. This is
how you tell what's actually active without scrolling the console.

### Tabs

- **Status** — shows the detected environment (root, distro, which
  tools are installed) and has buttons for *Refresh Environment*,
  *Leak Report*, and *Show Full State* (the same detail as the status
  bar, spelled out). A checkbox ("A kill switch/tunnel is active right
  now") plus *Run DNS Leak Check* lives here too — tick it before
  checking if you expect to be tunneled, so the verdict is judged
  correctly.
- **Tor** — Start/Stop Tor, *Rotate Circuit* for a new exit IP, *Check
  Tor Active*, enable/disable the Tor kill switch, a *Verify* button
  that actually tests it (attempts a direct connection, confirms it
  fails), a text box to paste bridge lines into plus *Configure
  Bridges*, and buttons to start/stop **full** anonymity mode in one
  click (self-verifying by default).
- **Proxy** — paste proxy lines (one per line) and generate a
  proxychains config, with a **chain mode** dropdown (dynamic/strict/
  random) and an **"Include Tor in chain"** checkbox — leave it
  unticked when the target blocks Tor. Below that, the system-wide
  proxy-only kill switch: enter host/port/type plus optional
  username/password, enable/disable it (full Linux + root, needs
  `redsocks`), and *Verify* to test it the same way as the Tor tab. A
  note reminds you this is TCP-only — check DNS leaks after.
- **Anti-Recon** — toggle fingerprint hardening and portscan
  auto-block; run a bounded-duration live scan watch (set seconds and
  whether to auto-block detected scanners); or point *Watch HTTP
  access log* at a log file (via *Browse*) for alert-only scanner
  detection — has its own *Stop* button since that watch runs until
  you stop it.
- **VM Snapshots** — pick VirtualBox or virsh, enter the VM/domain
  name and snapshot name, and *Reset to Snapshot*. Run this from the
  **host** machine — it has no effect from inside a guest.
- **Cleanup / Logs** — *Clean Traces* (with an optional, root-gated
  "also wipe /var/log" checkbox), plus save/decrypt for the encrypted
  session log: enter a passphrase and *Save Encrypted Log*, or browse
  to a `.enc` file, enter its passphrase, and *Decrypt & Show* to read
  it back in the console pane. Below that, RAM/app hygiene ported from
  AnonSurf's Pandora: *Kill risky apps now* closes common browsers/chat
  clients on demand; a mode dropdown (fast/thorough) plus *Wipe Free
  RAM Now*, *Install Shutdown Hook*, and *Remove Shutdown Hook* control
  the `sdmem`-based RAM overwrite, one-off or automatic on every
  shutdown. A note flags when `sdmem` isn't installed, since the
  fallback (a cache drop) isn't a real security wipe.
- **VPN** — start/stop OpenVPN (browse to a `.ovpn` config, optional
  auth file) or WireGuard (interface name), for chaining a VPN
  underneath Tor/a proxy. Both need root + full Linux.
- **Profiles** — save/load an encrypted profile (proxy lines + bridge
  lines) under a name and passphrase, so you're not retyping them
  every session; *List Profiles* prints what's saved.
- **Monitor** — start a background thread that periodically re-checks
  Tor/DNS/public-IP and prints `[MONITOR ALERT]` lines in the console
  if something changes unexpectedly mid-session; set the interval and
  whether to expect a tunnel (for DNS-leak flagging). *Stop Monitor*
  ends it.
- **Gateway Mode** — the two-VM architecture (see the dedicated
  section above for the full walkthrough), laid out as three
  sub-panels matching the three machines involved: (1) **Host** — pick
  a hypervisor and both VM names, *Wire Topology* to give the gateway
  two NICs and the workstation exactly one; (2) **Gateway VM** — enter
  the internal interface/IP, *Enable/Disable Gateway Mode*; (3)
  **Workstation VM** — enter its interface/IP and the gateway's IP,
  *Configure Networking*, then *Verify Isolation* to actually check
  reality (one interface, one route, one DNS resolver) rather than
  just trusting the setup.

### Notes on GUI behavior

- Every button runs its action in a background thread, so the window
  never freezes — watch the console pane for progress/results rather
  than the button itself.
- Root-only actions (MAC/hostname randomization, kill switches,
  sysctl hardening, portscan block) will just print a permission
  message in the console if you're not running as root — launch with
  `sudo python3 gui.py` on a VM/standalone box if you need those.
- Closing the window stops the GUI but doesn't automatically undo an
  active kill switch or stop Tor — use the Tor tab's *Stop FULL
  anonymity mode* button (or the CLI's `--stop`) before closing if you
  want networking reverted.

## Safety notes

- Test the kill switch and portscan-block against a target you
  control before relying on it operationally — iptables rules with
  the wrong hitcount/seconds can lock out legitimate traffic too.
- `/var/log` wiping is irreversible and root-gated — only run it on
  systems you're authorized to modify, not client infrastructure.
- Encrypted session logs are for your own private notes; they aren't
  a substitute for a proper engagement report.
