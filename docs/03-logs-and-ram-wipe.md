# Persistent Logs, Saved Profiles & RAM Wipe

Three separate features that often get asked about together. Each has
its own storage location and its own passphrase model.

## Encrypted session logs

**What it's for:** a private record of what PrivacyGuard did this
session (useful for engagement notes), kept even after `clean_traces`
wipes the system-level history.

**CLI:**
```
16   save or decrypt? [save/decrypt]: save
     passphrase for encrypted log: <your passphrase>
```
Saved to `~/.privacyguard_logs/session-<timestamp>.enc`.

**Read it back later:**
```
16   save or decrypt? [save/decrypt]: decrypt
     path to .enc file: ~/.privacyguard_logs/session-20260915-143000.enc
     passphrase: <same passphrase>
```

**GUI:** Cleanup/Logs tab — enter a passphrase, click *Save Encrypted
Log*; browse to a `.enc` file, enter its passphrase, click *Decrypt &
Show*.

**Important:** the passphrase is not recoverable if lost — there's no
reset mechanism by design (that's what makes it actually private).
Losing the passphrase means losing that log permanently.

## Saved profiles (proxy lists, bridge lines)

**What it's for:** not retyping the same proxy chain or bridge set
every session.

**CLI:**
```
26   save, load, or list? [save/load/list]: save
     profile name: my-usual-proxies
     Proxy lines (empty line to finish): <paste your list>
     Bridge lines (empty line to finish): <paste bridges, or just hit enter>
     passphrase to encrypt this profile: <your passphrase>
```
Saved to `~/.privacyguard_profiles/<name>.profile.enc`.

**Load it back:**
```
26   save, load, or list? [save/load/list]: load
     profile name: my-usual-proxies
     passphrase: <same passphrase>
```
This prints the saved proxy/bridge lines — you still paste them into
menu 12 (proxychains) or 11 (bridges) yourself; loading a profile
doesn't auto-apply it.

**GUI:** Profiles tab — fill in the proxy/bridge text boxes, name +
passphrase, *Save Profile*. *Load Profile* fills the text boxes back
in from a saved profile. *List Profiles* shows what's saved.

**Different passphrase than the session log** — these are separate
encrypted stores, each with its own passphrase. Reusing the same one
is fine but not required.

## RAM wipe (on-demand and automatic)

**What it's for:** overwriting free RAM so nothing recoverable (open
tabs, session tokens, chat history) survives in memory after you stop
working — defends against cold-boot/RAM-remnant forensic access to a
still-powered machine.

**Prerequisite for a real wipe** (not just a cache drop):
```bash
sudo apt install secure-delete
```
Without this, the wipe falls back to `sync && echo 3 > /proc/sys/vm/drop_caches`
— that frees clean cache pages but does **not** securely overwrite
memory contents. The tool tells you explicitly which one happened.

**One-off wipe, right now:**
```
21   wipe mode [fast/thorough] (default fast): fast
```
`fast` = one low-priority pass, seconds. `thorough` = sdmem's default
multi-pass overwrite — can take minutes on a VM with several GB of RAM.

**Also kill browsers/chat clients first** (they're what's most likely
to hold sensitive data in memory):
```
20   Kill risky apps now
```
This is also offered automatically when stopping full anonymity mode
(menu 18 asks "also kill risky apps? / also wipe free RAM now?").

**Automatic wipe on every shutdown/reboot** (independent of whether
PrivacyGuard is even running at the time):
```
22   install or remove the automatic shutdown hook? [install/remove]: install
     wipe mode [fast/thorough] (default fast): fast
```
This installs a systemd unit (`privacyguard-ramwipe.service`) that
runs the wipe as part of every shutdown sequence. Remove it the same
way (`22` → `remove`) if you no longer want the extra shutdown delay.

**GUI:** Cleanup/Logs tab, bottom section — *Kill risky apps now*, a
mode dropdown plus *Wipe Free RAM Now*, *Install Shutdown Hook*,
*Remove Shutdown Hook*.

**Check what's actually installed/active** at any time:
```
23   Show current state
```
This reports whether the shutdown hook is installed, among everything
else that's currently active.
