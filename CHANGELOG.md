# Changelog

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
