"""
Tor control, proxychains configuration, Tor pluggable-transport bridges
(for when Tor's public relays are blocked/censored), and legitimate IP
rotation (new Tor circuits / cycling through a proxy list).

NOTE ON "IP SPOOFING": true packet-level source-IP spoofing is not
implemented here. It breaks two-way TCP communication (replies go to
the forged address, not you) and its main real-world use is DoS
reflection/amplification, not anonymity. What actually changes your
*visible* IP to a target is rotating which Tor exit / proxy / VPN
endpoint your traffic leaves from — that's what this module does.
"""
import json
import queue
import ssl
import subprocess
import threading
from pathlib import Path

from . import environment as envmod


# --------------------------------------------------------------------
# Tor process control
# --------------------------------------------------------------------

_TOR_UNIT_CACHE = None


def _resolve_tor_systemd_unit() -> str:
    """Debian/Kali's tor package often uses a multi-instance systemd
    setup where 'tor.service' is just a stub master unit (commonly
    ExecStart=/bin/true, existing only for ordering) while the actual
    daemon runs under 'tor@default.service'. Targeting the stub with
    start/stop/restart silently does nothing to the real process —
    detect which one actually exists and controls the real daemon."""
    global _TOR_UNIT_CACHE
    if _TOR_UNIT_CACHE is not None:
        return _TOR_UNIT_CACHE
    unit = "tor"
    try:
        result = subprocess.run(["systemctl", "list-unit-files", "tor@default.service"],
                                 capture_output=True, text=True, timeout=5)
        if "tor@default.service" in result.stdout:
            unit = "tor@default"
    except Exception:
        pass
    _TOR_UNIT_CACHE = unit
    return unit


def start_tor(env: envmod.Environment) -> bool:
    if not env.has_tor:
        print("[!] tor is not installed.")
        print("    Termux : pkg install tor")
        print("    Debian : sudo apt install tor")
        return False
    try:
        if env.termux:
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            unit = _resolve_tor_systemd_unit()
            subprocess.run(["systemctl", "start", unit], check=False)
            subprocess.run(["service", "tor", "start"], check=False)
        print("[+] Tor start requested — allow ~10s to bootstrap.")
        return True
    except Exception as e:
        print(f"[!] Could not start tor: {e}")
        return False


def stop_tor(env: envmod.Environment) -> None:
    try:
        if env.termux:
            subprocess.run(["pkill", "-x", "tor"], check=False)
        else:
            unit = _resolve_tor_systemd_unit()
            subprocess.run(["systemctl", "stop", unit], check=False)
            subprocess.run(["service", "tor", "stop"], check=False)
        print("[+] Tor stop requested.")
    except Exception as e:
        print(f"[!] Could not stop tor: {e}")


def _tor_check_via_socks(timeout: float) -> dict:
    """Talks to check.torproject.org through Tor's SOCKS proxy using an
    isolated socket, not the global socket module — the previous
    implementation did `socket.socket = socks.socksocket`, which
    silently rerouted EVERY OTHER network call in the process through
    Tor from that point on (a real correctness bug independent of any
    hang), and never undid it."""
    import socks  # type: ignore
    sock = socks.socksocket()
    sock.settimeout(timeout)
    sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    sock.connect(("check.torproject.org", 443))
    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname="check.torproject.org")
    try:
        ssock.sendall(b"GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n")
        chunks = []
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        ssock.close()
    body = b"".join(chunks).split(b"\r\n\r\n", 1)[-1]
    return json.loads(body.decode())


def check_tor_active(timeout: float = 10.0) -> dict:
    """Returns the check.torproject.org API response, or {'error': ...}.
    Hard-bounded by `timeout` regardless of what the SOCKS handshake or
    TLS negotiation does internally. Runs the actual check in a DAEMON
    thread rather than a ThreadPoolExecutor: a bare per-socket timeout
    doesn't fully guarantee completion across a multi-step SOCKS5+TLS
    handshake, and if the underlying call genuinely never returns, a
    ThreadPoolExecutor's own shutdown() would block waiting for it too
    — a daemon thread is abandoned cleanly at process exit instead,
    so a stuck proxy can never hang the whole program, only this call
    up to `timeout`."""
    if not envmod.have_module("socks"):
        return {"error": "PySocks not installed. pip install pysocks --break-system-packages"}

    result_q: "queue.Queue[dict]" = queue.Queue()  # unbounded — worker's put() never blocks

    def worker():
        try:
            result_q.put(_tor_check_via_socks(timeout))
        except Exception as e:
            result_q.put({"error": str(e)})

    threading.Thread(target=worker, daemon=True).start()
    try:
        return result_q.get(timeout=timeout + 2)
    except queue.Empty:
        return {"error": f"timed out after {timeout}s talking to Tor's SOCKS proxy (127.0.0.1:9050) — "
                          f"Tor may not be running, or its SocksPort isn't ready yet"}


# --------------------------------------------------------------------
# New circuit ("rotate my exit IP") — this is the real equivalent of
# "randomize my IP" for Tor users.
# --------------------------------------------------------------------

def rotate_tor_circuit(env: envmod.Environment, control_password: str = None) -> bool:
    """Request a new Tor circuit (new exit IP) via the control port if
    possible; otherwise fall back to SIGHUP which also forces Tor to
    eventually rebuild circuits."""
    if env.has_stem:
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=9051) as controller:
                if control_password:
                    controller.authenticate(password=control_password)
                else:
                    controller.authenticate()  # cookie auth
                controller.signal(Signal.NEWNYM)
            print("[+] Sent NEWNYM — new Tor circuit requested.")
            return True
        except Exception as e:
            print(f"[!] stem control-port NEWNYM failed ({e}); falling back to SIGHUP.")
    try:
        if env.termux:
            subprocess.run(["pkill", "-HUP", "-x", "tor"], check=True)
        else:
            subprocess.run(["pkill", "-HUP", "-x", "tor"], check=True)
        print("[+] Sent SIGHUP to tor (circuits will rotate shortly).")
        return True
    except Exception as e:
        print(f"[!] Could not rotate circuit: {e}")
        print("    For reliable NEWNYM, enable Tor's ControlPort 9051 + CookieAuthentication 1")
        print("    in torrc, and `pip install stem`.")
        return False


# --------------------------------------------------------------------
# Tor bridges / pluggable transports — for when Tor's public relays
# are blocked by a network/ISP/country firewall.
# --------------------------------------------------------------------

def default_torrc_path(env: envmod.Environment) -> Path:
    if env.termux:
        return Path.home() / "../usr/etc/tor/torrc"  # Termux's $PREFIX/etc/tor/torrc
    return Path("/etc/tor/torrc")


def configure_bridges(env: envmod.Environment, bridge_lines: list, torrc_path: Path = None) -> None:
    """
    bridge_lines: lines you obtained from https://bridges.torproject.org
    or the Telegram/email bridge bot, e.g.:
      obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0
    This tool does not generate or guess bridge addresses — you must
    fetch real ones from the Tor Project, since made-up ones won't work.
    """
    if not bridge_lines:
        print("[!] No bridge lines provided. Get them from https://bridges.torproject.org")
        return
    if not env.has_obfs4proxy:
        print("[!] obfs4proxy not installed — obfs4 bridges won't work.")
        print("    Termux : pkg install obfs4proxy")
        print("    Debian : sudo apt install obfs4proxy")

    path = torrc_path or default_torrc_path(env)
    try:
        existing = path.read_text() if path.exists() else ""
    except PermissionError:
        print(f"[!] No permission to read {path} — need root/appropriate user.")
        return

    lines = [l for l in existing.splitlines() if not l.strip().startswith(("UseBridges", "Bridge "))]
    lines.append("UseBridges 1")
    for b in bridge_lines:
        lines.append(f"Bridge {b.strip()}")

    try:
        path.write_text("\n".join(lines) + "\n")
        print(f"[+] Wrote {len(bridge_lines)} bridge line(s) to {path}")
        print("    Restart tor for this to take effect.")
    except PermissionError:
        print(f"[!] No permission to write {path} — need root/appropriate user.")


# --------------------------------------------------------------------
# proxychains — decoy hop chaining, also useful when Tor itself is
# blocked but ordinary SOCKS/HTTP proxies aren't.
# --------------------------------------------------------------------

def proxychains_conf_path(env: envmod.Environment) -> Path:
    if env.termux:
        return Path.home() / ".proxychains" / "proxychains.conf"
    return Path("/etc/proxychains.conf") if Path("/etc/proxychains.conf").exists() else Path("/etc/proxychains4.conf")


def generate_proxychains_conf(env: envmod.Environment, proxies: list, chain_mode: str = "dynamic",
                               include_tor: bool = True) -> Path:
    """
    proxies: list of strings like 'socks5 203.0.113.5 1080' or
             'http 203.0.113.9 8080 user pass'
    chain_mode: 'dynamic' (skip dead proxies), 'strict' (all must be up,
                in order), or 'random' (pick a random one per connection —
                closest thing to 'rotating IP' via proxychains alone).
    """
    mode_map = {"dynamic": "dynamic_chain", "strict": "strict_chain", "random": "random_chain"}
    mode_line = mode_map.get(chain_mode, "dynamic_chain")

    conf = [
        f"{mode_line}",
        "proxy_dns",
        "remote_dns_subnet 224",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "[ProxyList]",
    ]
    if include_tor:
        conf.append("socks5 127.0.0.1 9050")
    for p in proxies:
        conf.append(p.strip())

    path = proxychains_conf_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(conf) + "\n")
    print(f"[+] proxychains config written to {path} ({chain_mode} chain, {len(proxies)} proxy hop(s) + "
          f"{'Tor' if include_tor else 'no Tor'})")
    print(f"    Use it with: proxychains4 -f {path} <command>")
    return path


def test_proxychains(env: envmod.Environment) -> None:
    if not (env.has_proxychains):
        print("[!] proxychains not installed.")
        return
    binary = "proxychains4" if envmod.have("proxychains4") else "proxychains"
    conf = proxychains_conf_path(env)
    if not conf.exists():
        print(f"[!] No config at {conf} yet — generate one first.")
        return
    try:
        out = subprocess.run([binary, "-f", str(conf), "curl", "-s", "https://api.ipify.org"],
                              capture_output=True, text=True, timeout=30)
        print(f"[i] Exit IP through proxychains: {out.stdout.strip() or '(no response)'}")
        if out.stderr:
            print(out.stderr.strip()[-500:])
    except Exception as e:
        print(f"[!] proxychains test failed: {e}")
