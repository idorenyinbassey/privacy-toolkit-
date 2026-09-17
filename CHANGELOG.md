# Changelog

## 2.2.10 — Fix targeting the wrong systemd unit (stub vs real Tor daemon)

Real-world diagnosis: after the portscan-loopback fix (2.2.9), the
bootstrap wait showed consistent `Connection reset by peer` /
`Connection closed unexpectedly` for the entire wait, never resolving
to a working connection — a live, unstable Tor-level problem, not a
firewall one. Investigation found TWO compounding causes:

1. **An orphaned foreground Tor process** — a manual `sudo -u
   debian-tor tor -f /etc/tor/torrc` test run from earlier troubleshooting
   was never actually killed, silently squatting on ports 9050/9040/5353
   in the background the whole time.
2. **The bigger, structural bug**: Debian/Kali's tor package uses a
   multi-instance systemd setup where `tor.service` is a stub master
   unit (`ExecStart=/bin/true`, existing only for ordering) while the
   real daemon runs under `tor@default.service`. Every
   `systemctl start/stop/restart tor` call in this codebase — in
   `start_tor()`, `stop_tor()`, and `enable_kill_switch()`'s
   "restart tor to apply torrc" step — was targeting the harmless
   stub. The real running daemon was never actually being controlled
   by any of this tool's start/stop/restart calls on affected systems.

Fix: `_resolve_tor_systemd_unit()` (proxy_tor.py) detects whether
`tor@default.service` exists via `systemctl list-unit-files` and uses
that as the actual target for every start/stop/restart call instead
of assuming `tor.service` is the real unit; falls back to plain `tor`
on systems where that genuinely is the real daemon (non-Debian/Kali
setups). Resolved once per process and cached.

New tests covering unit resolution (both branches, error fallback,
caching) and confirming start_tor/stop_tor target the resolved unit,
not a hardcoded "tor". Suite: 90/90 passing.

## 2.2.9 — Fix portscan protection blocking the tool's own Tor bootstrap checks

Real-world diagnosis: after 2.2.8 made the bootstrap wait visible, the
live output showed a very specific pattern — early attempts got
`Connection reset by peer` (Tor itself, unstable but responding),
transitioning cleanly to `timed out` around the 30-second mark and
staying that way. A `DROP` iptables rule produces exactly silent
timeouts, and something new started dropping these connections partway
through the wait.

**Root cause**: `enable_portscan_protection`'s INPUT rule tracked "new
connections from one source" with no loopback exclusion. Loopback
traffic (`127.0.0.1 -> 127.0.0.1`) genuinely traverses the INPUT chain
on Linux. `_wait_for_tor_bootstrap`'s own retry loop polls Tor's
SocksPort (127.0.0.1:9050) roughly every 2 seconds while waiting —
after ~15 of the tool's OWN check attempts (the default hitcount),
the portscan rule started matching and dropping the tool's own
traffic. A self-inflicted feedback loop: wait longer for Tor -> check
more times -> exceed the anti-scan threshold -> get blocked by your
own defense -> Tor looks unreachable even if it's fine.

Fix: the tracking rule now excludes loopback (`! -i lo`), which is
also just the semantically correct scope for a feature meant to catch
external scanners, not the tool's own local traffic.
`disable_portscan_protection`'s removal rule updated to match exactly
(iptables -D requires an identical spec to find and remove a rule).

**If you're upgrading from an affected version**: the currently-active
rule in your kernel is still the OLD one — upgrading the code alone
does not retroactively fix already-applied iptables rules. Disable
portscan protection (or do a full `sudo iptables -F`) BEFORE
upgrading, then re-enable after, so the corrected rule actually gets
applied. See docs/04-troubleshooting.md for the exact commands.

New tests confirming the rule excludes loopback and that disable
targets the exact same spec. Suite: 84/84 passing.

## 2.2.8 — Make Tor-bootstrap wait visibly tick, and bound the first check

The first `check_tor_active()` call in `_wait_for_tor_bootstrap` ran
BEFORE the "waiting..." message printed, with the default ~12s
timeout — so if Tor's SOCKS port was open but slow to answer that
first check, the program looked frozen right after "Portscan
protection active" for up to ~12s with zero output, indistinguishable
from a real hang from the outside.

Fix: prints its intent BEFORE the first check, bounds each check at
8s explicitly, and prints a live `...still waiting (Ns/timeout)` line
every loop iteration with the current failure reason. Can no longer
sit silently — a genuine freeze is now immediately distinguishable
from normal slow-bootstrap waiting, since real waiting visibly ticks.

## 2.2.7 — Fix a false-failure bug in the kill switch's own verification

Real-world observation: after the 2.2.6 torrc fix, Tor bootstrapped
and the kill switch applied cleanly with zero errors — but
`verify_tor_kill_switch` still reported FAIL on the direct-connection
check. Traced to a real design bug in the verification itself, not
the kill switch.

**Root cause**: `_direct_tcp_probe()` opened a plain TCP connection to
test whether "direct" (non-Tor) traffic is blocked. But the kill
switch's own iptables rule — `-p tcp --syn -j REDIRECT --to-ports
9040` — redirects EVERY new outbound TCP SYN through Tor's TransPort,
regardless of destination. That's the entire mechanism: transparently
routing ordinary connections through Tor rather than dropping them.
A "direct" TCP probe therefore gets swept into that exact same
redirect and can genuinely succeed via Tor even when the kill switch
is working perfectly — the test's premise ("success = leak") was
simply wrong for this architecture, and could report a false failure
for a fully working kill switch.

**Fix**: replaced with `_direct_traffic_blocked()`, which uses ICMP
(ping) instead — not covered by any ACCEPT/REDIRECT rule in the
ruleset, so it correctly falls through to the final DROP. A ping
timing out is genuine evidence the kill switch blocks non-redirected
traffic; a ping succeeding is a genuine leak. Applied to both
`verify_tor_kill_switch` and `verify_proxy_kill_switch` (the
proxy-only kill switch has the identical redirect-everything design).

Also: the Tor-routing check now retries with backoff (up to 4
attempts, 3s apart) instead of judging on a single immediate check —
applying the kill switch flushes iptables first, which can briefly
disrupt a Tor circuit that was only just built moments earlier during
the bootstrap check.

New tests for both fixes. Suite: 81/81 passing.

## 2.2.6 — Fix the actual root cause of the whole "Tor never bootstraps" saga

Real-world diagnosis, tracing through several prior sessions of
"stuck"/"hangs"/"Tor did not bootstrap" reports that turned out to be
one underlying config bug, not any of the timing/threading issues
fixed in 2.2.1-2.2.5 (all of which were real, and stayed fixed —
this was a separate, deeper cause layered underneath them).

Manually running Tor in the foreground revealed it crash-looping
(exiting within the same second it started, repeatedly) rather than
slowly failing to bootstrap. `journalctl -u tor` only ever showed
generic systemd start/stop lines because Tor was dying before it
could log anything useful to its own log file.

**Root cause**: `/etc/tor/torrc` had TWO conflicting `TransPort`
directives — one unqualified (`TransPort 9040`, likely added manually
following this tool's OWN pre-2.2.1 README, which instructed manual
torrc setup before auto-configuration existed) and one from our own
auto-written managed block (`TransPort 127.0.0.1:9040`). Both claim
port 9040; Tor refuses to bind the second and exits immediately. The
old `_ensure_transparent_proxy_torrc()` only ever checked "is my own
managed-block marker present" — it never checked for OTHER
TransPort/DNSPort lines elsewhere in the file, so a leftover manual
line (or any other duplicate) was never cleaned up, even across many
runs where the marker WAS already present.

Fix: the function now strips ANY existing `TransPort`/`DNSPort` lines
— its own prior block, a manually-added one, or any stray duplicate —
before writing back exactly one canonical pair. Runs this
normalization every time regardless of whether its own marker is
already present, since marker-presence alone was never sufficient to
guarantee no conflicting line exists elsewhere.

New tests reproducing the exact reported scenario (pre-existing
unqualified `TransPort 9040`/`DNSPort 53` alongside our marked block)
and confirming cleanup happens even when the marker is already there.
Suite: 76/76 passing.

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
