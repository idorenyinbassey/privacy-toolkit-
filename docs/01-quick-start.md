# Quick Start

Pick the section matching your setup. Each one is the shortest path
from "just installed" to "actually protected," in order.

## A. Termux (phone, no root)

No kill switch, no MAC spoofing — Termux has no root/netfilter. This
gets you Tor + leak checking + per-command proxy wrapping.

```bash
pkg install tor obfs4proxy torsocks proxychains-ng python dnsutils
pip install pysocks stem cryptography

python3 main.py
> 3            # start/stop: start   (starts Tor)
> 1            # confirm public IP / Tor status
> 2            # DNS leak check (expect a tunnel: n — no kill switch exists here)
```
To route an individual command through Tor: `torsocks curl https://check.torproject.org/api/ip`.

## B. Single Kali VM or standalone box (most common)

Full feature set. This is the sequence that avoids the "lost internet"
problem — Tor gets verified as bootstrapped *before* the firewall
locks down, not after.

```bash
sudo apt install tor obfs4proxy macchanger iptables proxychains4 torsocks redsocks secure-delete python3-tk
pipx install ".[full]"   # or: pip install pysocks stem cryptography scapy --break-system-packages

sudo privacyguard        # root is required for nearly everything below
> 1                      # confirm environment: root=yes, tor=yes
> 17                     # Start FULL anonymity mode — this auto-configures torrc,
                          #   waits for Tor to actually bootstrap, THEN applies the
                          #   kill switch, then verifies it worked. Refuses to lock
                          #   the firewall if Tor never comes up.
> 2                      # DNS leak check: y (a tunnel is now active)
```
When you're done:
```
> 18                     # stop full anonymity mode
        also kill risky apps? y/N
        also wipe free RAM now? y/N
```

**If you're using the GUI instead:** the Tor tab's "Start FULL
anonymity mode" button does the same self-verifying sequence. Don't
click "Enable Kill Switch" on its own as your first action — it works
fine now (it does the same Tor-bootstrap check internally), but
starting from the single "Start FULL anonymity mode" button is the
simplest correct sequence if you're not sure what order things need to
happen in.

## C. Two-VM gateway mode (strongest option)

Three separate machines, three separate runs. See the README's
[Gateway mode section](../README.md#gateway-mode--two-vm-whonix-style-architecture-220)
for the full walkthrough — the short version:

```bash
# 1. On the HOST:
python3 main.py  →  menu 28   (wires gateway VM to 2 NICs, workstation VM to 1)

# 2. Inside the GATEWAY VM (needs tor installed):
sudo python3 main.py  →  menu 29  →  enable

# 3. Inside the WORKSTATION VM:
sudo python3 main.py  →  menu 30  →  configure, then  →  30  →  verify
```
Don't skip the verify step in (3) — it's the only thing that confirms
the isolation is real rather than assumed.

## After any of the above: confirm it actually worked

Don't just trust that enabling something worked — check:
```
> 1     # leak report: public IP, Tor status
> 2     # DNS leak check
> 24    # verify (actually tests the kill switch, not just "command returned 0")
```
If `24` fails any check, treat that as "not actually protected yet,"
not a cosmetic warning — see [Troubleshooting](04-troubleshooting.md).
