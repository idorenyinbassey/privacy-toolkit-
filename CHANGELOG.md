# Changelog

## 2.2.5 — Fix a real hang risk + a silent global-state bug in check_tor_active

Real-world report: "Start FULL anonymity mode" appeared to hang
indefinitely after "Portscan protection already active," with no
further output. Root cause: `check_tor_active()` did
`socket.socket = socks.socksocket` — monkey-patching Python's global
socket module for the ENTIRE PROCESS to route through Tor's SOCKS
proxy, and never undoing it. Two separate problems from that one line:

1. **Silent correctness bug, independent of any hang**: once called
   once, every OTHER network call anywhere else in that same process
   (leak reports, DNS checks, proxy tests) got silently rerouted
   through Tor's SOCKS proxy afterward too, whether intended or not.
2. **No real hang guarantee**: `urllib.request.urlopen(..., timeout=10)`
   does not reliably bound every step of a SOCKS5-then-TLS handshake
   against a proxy port that's open but not yet ready to negotiate —
   the loop calling this had no ceiling on top of that assumption.

Fix: `check_tor_active()` now runs an isolated, non-global-patching
SOCKS+TLS request (`_tor_check_via_socks`) inside a **daemon thread**,
with the result collected via an unbounded queue and a hard
`queue.get(timeout=...)` ceiling on the caller's side. A daemon thread
is abandoned cleanly at process exit if it never returns — a
`ThreadPoolExecutor` was deliberately NOT used here, since its own
`shutdown(wait=True)` would itself block waiting for a genuinely stuck
worker, defeating the point.

New tests, including one that simulates a worker that never returns
at all and confirms `check_tor_active` still returns within its
timeout, and one confirming the global `socket.socket` class is never
touched. Suite: 73/73 passing.

## 2.2.4 — Fix DHCP-renewal race condition ("device has no carrier")

Real-world report: the 2.2.3 fix (auto-renewing DHCP after a MAC
change via `nmcli device connect`) itself had a bug — it called nmcli
immediately after `ip link set dev <iface> up`, before the virtual
NIC's link had actually re-established carrier. nmcli correctly
refused with "device has no carrier," which is accurate but not
actionable, since the real fix is timing, not something the user
needs to intervene on.

- New `_wait_for_carrier(iface, timeout=5.0)` polls
  `/sys/class/net/<iface>/carrier` directly (the kernel's own
  link-state signal) instead of guessing with a fixed sleep.
  `randomize_mac()` now waits for carrier before attempting the
  renewal, and skips the renewal cleanly (with clear manual-fallback
  guidance) rather than trying and failing if carrier never returns
  within the timeout.
- New tests: `_wait_for_carrier` behavior directly, plus a case
  confirming `randomize_mac` never calls `nmcli` when carrier never
  comes back. Suite: 69/69 passing.

## 2.2.3 — Fix "MAC changed, lost internet on a bridged VM"

Real-world report: even after 2.2.2's fix confirmed the kill switch
correctly did nothing, internet access still broke — traced to MAC
randomization, which runs unconditionally in "Start FULL anonymity
mode" before the kill switch is ever touched. On a bridged VM (sharing
a physical LAN), changing the MAC while keeping the same IP leaves the
router's DHCP lease/ARP table pointed at the old MAC; connectivity
doesn't recover until something forces a fresh negotiation, which is
why a full reboot "fixed" it.

- `core.randomize_mac()` now automatically attempts a DHCP renewal
  (`nmcli device connect <iface>`) immediately after changing the MAC
  — best-effort, never fails the MAC change itself if renewal isn't
  possible, but resolves the issue outright on NetworkManager-managed
  systems (current Kali default).
- New `renew_dhcp` parameter (default `True`) and, more importantly,
  a new `randomize_identity` parameter on `orchestrate.full_start` to
  skip MAC/hostname randomization entirely — CLI menu 17 now asks,
  `--start --no-randomize-identity` flag added, GUI Tor tab has a
  matching checkbox. Kill switch / sysctl hardening / portscan
  protection remain fully independent and can stay on regardless.
- `docs/04-troubleshooting.md`: new section walking through this
  exact scenario and how to tell it apart from the Tor-bootstrap issue.
- New tests: DHCP-renewal-attempted / renewal-skipped-when-disabled,
  and full_start's identity-randomization on/off paths. Suite: 66/66.

## 2.2.2 — Fix misleading verification report + configurable bootstrap timeout

Real-world report: after 2.2.1 correctly refused to enable the kill
switch when Tor failed to bootstrap, `orchestrate.full_start` still
ran `verify.verify_tor_kill_switch` unconditionally afterward — printing
a `[FAIL]` report immediately after "NOT enabling the kill switch,"
reading as if something broke when the tool had actually done exactly
the right thing (nothing).

**Root cause:** `core.enable_kill_switch` and
`proxy_only.enable_proxy_kill_switch` returned `None` on every path,
giving callers no way to distinguish "applied" from "correctly
declined." Both now return `bool`; `orchestrate.full_start` and the
CLI's proxy-only menu check it and skip verification (with a clear
"kill switch was NOT enabled, skipping verification" message) rather
than running a check against a firewall that was never touched.

Also: default bootstrap timeout raised 30s -> 45s, and made
configurable everywhere it's used (CLI menu 6/17, `--start
--bootstrap-timeout N`, GUI Tor tab has a timeout field) — first
bootstrap can genuinely take longer than 30s on a slow or filtered
connection, and a fixed timeout was forcing a false negative there.

New tests: `tests/test_orchestrate.py` (full_start skips/runs
verification correctly based on the return value, timeout threads
through), plus return-value coverage for both enable functions.
Suite: 62/62 passing.

## 2.2.1 — Fix the actual "enabled kill switch, lost internet" bug + wiki

**Root cause fix:** `enable_kill_switch` and `enable_proxy_kill_switch`
previously applied their DROP-everything-except-tunnel firewall rules
unconditionally, trusting that Tor/the proxy was already reachable.
Kali's default Tor config has no `TransPort`/`DNSPort` configured out
of the box — enabling the kill switch against that default silently
redirected all traffic into ports nothing was listening on, dropping
all internet access with no working path out. Both functions now:
- Auto-configure the required torrc lines (idempotent managed block,
  same pattern as gateway.py) and restart Tor if changed.
- Actively wait for Tor to bootstrap (up to `bootstrap_timeout`
  seconds, default 30) — or, for the proxy-only switch, confirm the
  proxy is actually reachable via a real TCP connection attempt —
  BEFORE touching iptables.
- Refuse to apply the firewall at all if that check fails, printing
  what to check next, instead of leaving the system locked out.
- New tests: `test_enable_kill_switch_refuses_when_tor_never_bootstraps`,
  `test_proxy_only_refuses_when_proxy_unreachable`, plus coverage for
  the idempotent torrc-writing helper. Suite: 56/56 passing.

**New: `docs/` wiki.** Task-oriented guides linked from the README:
- `01-quick-start.md` — shortest path to running per environment
  (Termux / single VM / two-VM gateway), explicitly sequenced to avoid
  the lockout above.
- `02-recommended-configs.md` — a decision tree ("what to enable, in
  what order") for common scenarios, including what NOT to combine.
- `03-logs-and-ram-wipe.md` — exact steps and file locations for
  encrypted session logs, saved profiles, and RAM wipe (on-demand and
  automatic-on-shutdown).
- `04-troubleshooting.md` — fixes for problems actually encountered
  while using this tool, including this exact bug's manual recovery
  commands for anyone on an older version.

## 2.2.0 — Gateway mode (two-VM Whonix-style architecture)

New: a Tor gateway VM + an isolated workstation VM whose only network
adapter connects to an internal-only network shared with the gateway
— stronger than a single-VM kill switch because the isolation is a
property of the virtual network topology itself, not just a firewall
rule a workstation-side compromise could theoretically route around.

- `gateway_topology.py` (host-side) — wires VM network adapters via
  VBoxManage or virsh: the gateway gets two NICs (external + internal),
  the workstation gets exactly one (internal only).
- `gateway.py` (run inside the gateway VM) — configures Tor's
  TransPort/DNSPort to also bind the internal interface, and sets up
  PREROUTING REDIRECT rules so the workstation's traffic goes through
  this VM's local Tor instance. The load-bearing property is an
  absence: no MASQUERADE or FORWARD-ACCEPT rule is ever issued, and
  the FORWARD chain default-drops — so anything not caught by the
  REDIRECT rules goes nowhere instead of reaching the external
  interface directly. Idempotent, state-tracked, and backed up the
  same way as the single-machine kill switch.
- `workstation.py` (run inside the workstation VM) — points its
  networking at the gateway, and `verify_isolation()` checks reality
  rather than intent: exactly one non-loopback interface, exactly one
  default route, DNS pointed only at the gateway.
- CLI menu items 28–30 (one per machine in the setup) and a new GUI
  "Gateway Mode" tab with three sub-panels matching the three roles.
- Tests: `tests/test_gateway_mode.py`, 12 tests including one that
  specifically asserts no MASQUERADE/FORWARD-ACCEPT rule is ever
  issued during gateway setup — the actual security property this
  architecture depends on.

## 2.1.0 — Production hardening pass

Fixes nine flaws identified in review of 2.0.0, none of which had been
run against real iptables/Tor/redsocks before this pass — only
syntax-checked. All logic below is now covered by an automated test
suite (`tests/`, 37 tests, mocked subprocess/network, no root needed
to run).

**Correctness (previously the biggest risk):**
- No firewall backup before flushing → `firewall_backup.py` now runs
  `iptables-save`/`ip6tables-save` before every destructive flush in
  `core.py` and `proxy_only.py`, and restores that exact backup on
  disable instead of guessing at "typical defaults."
- No state tracking → `state.py` persists exactly what's active
  (which kill switch, IPv6 block, portscan protection, sysctls,
  RAM-wipe hook, VPN, active proxy) so a crash mid-operation, or
  running enable twice, doesn't leave an unknown or duplicated state.
  `enable_kill_switch`/`enable_proxy_kill_switch`/
  `enable_portscan_protection`/`enable_stealth_sysctls`/`block_ipv6`
  are all now idempotent and will refuse to double-apply or to run
  both kill switches at once (they share the same OUTPUT chain).
- No post-enable verification → `verify.py` actually tests a kill
  switch (attempts a direct/non-tunneled connection and confirms it
  fails, confirms the tunneled path works, checks for DNS leaks)
  instead of trusting "the iptables command returned 0." Wired into
  `orchestrate.full_start` automatically; also callable standalone
  (CLI menu 24, GUI "Verify" buttons on Tor/Proxy tabs).
- Along the way, found and fixed a real bug caught by the new test
  suite: `disable_portscan_protection` was hardcoded to remove rules
  assuming `hitcount=15/seconds=60`, so it would silently fail to
  clean up if you'd enabled it with different parameters. Now stores
  and reuses the exact params from enable time.

**Test suite:** `tests/` — pure-logic tests (config generation,
MAC/hostname format, state persistence) plus mocked-subprocess tests
for idempotency/backup ordering. Run with `pytest tests/`.

**New capabilities:**
- `vpn.py` — OpenVPN and WireGuard start/stop/status, for chaining
  VPN → Tor or VPN → proxy.
- `profiles.py` — encrypted (PBKDF2 + Fernet) saved profiles for
  proxy lists and bridge lines, so they don't need retyping every
  session.
- `monitor.py` — background thread that periodically re-checks
  Tor/DNS/public-IP during a session and alerts on unexpected change,
  rather than only checking once on demand.
- Proxy authentication — username/password support added to
  `proxy_only.generate_redsocks_conf` (redsocks' login/password
  fields), exposed in both CLI and GUI.

**Polish:**
- `pyproject.toml` + `requirements.txt` for pip installability;
  `--version` flag.
- GUI status bar reading live from `state.py` every 2s, so you can see
  what's actually on without scrolling the console.
- New CLI menu items 23–27 (state, verify, VPN, profiles, monitor) and
  matching GUI tabs (VPN, Profiles, Monitor) plus Verify buttons.

## 2.0.0 — Initial feature-complete version

Tor kill switch, MAC/hostname randomization, proxychains (Tor
optional), proxy-only redsocks kill switch, anti-recon (fingerprint
hardening, portscan auto-block, live scan watch, HTTP log watch), DNS
leak detection, VM snapshot reset, encrypted session logging, RAM/app
hygiene (ported from AnonSurf's Pandora), IPv6 leak blocking (ported
from AnonSurf), CLI + Tkinter GUI.
