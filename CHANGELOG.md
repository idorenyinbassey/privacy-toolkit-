# Changelog

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
