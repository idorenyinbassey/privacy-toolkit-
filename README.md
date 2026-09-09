# PrivacyGuard v2

Environment-aware Python toolkit for privacy/anonymity + anti-recon
automation while running Kali (or any Linux) on a VM, in Termux, or
standalone. For authorized pentesting/red-team work and your own
systems' OPSEC hardening only.

## Layout

```
privacyguard/
  environment.py   - detects Termux vs full Linux, root, installed tools
  core.py          - MAC/hostname randomization, Tor kill switch, trace cleanup
  proxy_tor.py     - Tor control, circuit rotation, bridges, proxychains (Tor optional)
  proxy_only.py    - system-wide routing through a plain proxy, NO Tor (redsocks)
  anti_recon.py    - fingerprint hardening, portscan detection/block, log watch
  dns_check.py     - DNS leak detection
  vm_snapshot.py   - VirtualBox/libvirt snapshot reset (run from host)
  crypto_log.py    - encrypted local session log
  orchestrate.py   - shared "full start/stop" logic used by both CLI and GUI
main.py            - CLI (interactive menu + flags)
gui.py             - Tkinter desktop GUI (full Linux VM/standalone; not Termux)
```

Run the CLI with `python3 main.py` (menu) or flags: `--status --start
--stop --clean --rotate-ip --dns-leak-check --gui`.
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
 0) Exit
>
```

Type the number and press Enter. Options that need more input (a
hostname, a passphrase, proxy lines) will prompt for it right after
you pick them. A typical session before a scan:

```
> 1          # confirm environment/root, note current public IP
> 17         # start full anonymity mode (Tor, MAC/hostname randomize, kill switch)
> 2          # then: y  -> DNS leak check, expecting a tunnel to be active
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
empty line to finish and continue.

Option 13 (proxy-only kill switch) asks for the proxy host, port, and
type (`socks5`/`socks4`/`http-connect`) — use this instead of 17 when
the target network is known to block Tor traffic. Follow it with
option 2 to confirm no DNS leak.

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

### Tabs

- **Status** — shows the detected environment (root, distro, which
  tools are installed) and has buttons for *Refresh Environment* and
  *Leak Report*. A checkbox ("A kill switch/tunnel is active right
  now") plus *Run DNS Leak Check* lives here too — tick it before
  checking if you expect to be tunneled, so the verdict is judged
  correctly.
- **Tor** — Start/Stop Tor, *Rotate Circuit* for a new exit IP, *Check
  Tor Active*, enable/disable the Tor kill switch, a text box to paste
  bridge lines into plus *Configure Bridges*, and buttons to start/stop
  **full** anonymity mode in one click.
- **Proxy** — paste proxy lines (one per line) and generate a
  proxychains config, with a **chain mode** dropdown (dynamic/strict/
  random) and an **"Include Tor in chain"** checkbox — leave it
  unticked when the target blocks Tor. Below that, the system-wide
  proxy-only kill switch: enter host/port/type and enable/disable it
  (full Linux + root, needs `redsocks`). A note reminds you this is
  TCP-only — check DNS leaks after.
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
  it back in the console pane.

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
