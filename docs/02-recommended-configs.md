# Recommended Configurations

Pick the scenario closest to what you're doing. Each one lists exactly
what to enable, in order, and what to skip.

## "I just want general privacy on my Kali box"

```
17   Start FULL anonymity mode (Tor path)
2    DNS leak check (y — tunnel active)
24   Verify
```
That's it. Full mode already includes MAC/hostname randomization,
fingerprint sysctls, portscan protection, and the kill switch. Don't
add proxy-only mode on top — the two kill switches actively refuse to
run together (they'd fight over the same firewall chain).

## "I'm doing an authorized pentest and want to avoid fingerprinting while scanning"

```
17   Start FULL anonymity mode
7    (already on via 17) fingerprint hardening — silences ping, hides uptime
8    (already on via 17) portscan auto-block — protects THIS box from counter-recon
```
Note the asymmetry: options 7/8 protect *you* from being scanned back,
they don't help you scan more effectively — nmap/Metasploit traffic
still goes out through Tor via the kill switch, which most pentest
targets on an internal engagement won't expect or want. **For internal
network engagements, you typically do NOT want the Tor kill switch
active** — you want your own real IP reaching the target range. Use
options 7/8 alone (fingerprint hardening + portscan protection)
without 17 if that's your situation:
```
7    enable fingerprint hardening
8    enable portscan auto-block
```
Skip the kill switch and MAC randomization entirely for on-network
engagements where the client expects to see your actual test traffic.

## "Tor is blocked on this network"

```
12   Generate proxychains config — include Tor in chain? N
     (paste your own proxy list; use 'random' chain mode if you have several)
13   Proxy-only kill switch — enable, with the same proxy's host/port
2    DNS leak check (y) — redsocks doesn't tunnel DNS, so check carefully
```
If Tor is blocked but not fully unreachable (censored, not blocklisted),
try bridges before giving up on Tor entirely:
```
11   Configure Tor bridges (get real bridge lines from bridges.torproject.org first)
17   Start FULL anonymity mode
```

## "I want the strongest isolation available"

Two-VM gateway mode — see [Quick Start, section C](01-quick-start.md#c-two-vm-gateway-mode-strongest-option).
Use this when a workstation-level compromise is part of your threat
model, not just network-level snooping. Skip this if a single Kali VM
with the kill switch already covers your actual risk — gateway mode is
real setup overhead (two VMs, two OS installs) for a specific
additional guarantee (topological isolation), not a strictly-better
default.

## "I need a private record of what I did, but no trace on the system"

```
(do your work)
15   Clean local traces — also wipe /var/log? y (if you're authorized to)
16   save — encrypt this session's action log with a passphrase
```
The encrypted log lives in `~/.privacyguard_logs/`, readable only with
your passphrase — see [Persistent Logs & RAM Wipe](03-logs-and-ram-wipe.md)
for the full walkthrough including RAM wipe.

## What NOT to combine

- **Tor kill switch + proxy-only kill switch** — mutually exclusive by
  design (menu 6 and 13); enabling one while the other is active is
  refused, not silently overridden.
- **Gateway mode + a single-machine kill switch on the same VM** —
  `gateway.enable_gateway()` refuses to run if `tor_kill_switch` or
  `proxy_only_kill_switch` is already active on that VM, since gateway
  mode manages its own OUTPUT rules for that machine's own traffic.
- **RAM-wipe shutdown hook in `thorough` mode on a VM with limited
  RAM allocated** — multi-pass overwrite of several GB can add
  multiple minutes to every shutdown. Use `fast` mode unless you have
  a specific reason not to.
