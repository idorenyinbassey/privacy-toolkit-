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

## Safety notes

- Test the kill switch and portscan-block against a target you
  control before relying on it operationally — iptables rules with
  the wrong hitcount/seconds can lock out legitimate traffic too.
- `/var/log` wiping is irreversible and root-gated — only run it on
  systems you're authorized to modify, not client infrastructure.
- Encrypted session logs are for your own private notes; they aren't
  a substitute for a proper engagement report.
