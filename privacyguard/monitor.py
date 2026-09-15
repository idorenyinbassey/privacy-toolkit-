"""
Continuous monitoring: every leak/DNS check so far has been "check
once, right now." Nothing watched for a leak developing mid-session —
a Tor circuit dying, a VPN dropping, a route change — which is exactly
when it matters most. This runs the checks periodically in a
background thread and calls an alert callback when something changes
unexpectedly.
"""
import threading

from . import environment as envmod
from . import core, proxy_tor, dns_check


class LeakMonitor:
    def __init__(self, env: envmod.Environment, interval: int = 30, on_alert=None,
                 expect_tunnel: bool = True):
        self.env = env
        self.interval = interval
        self.on_alert = on_alert or (lambda msg: print(f"[ALERT] {msg}"))
        self.expect_tunnel = expect_tunnel
        self._stop_event = threading.Event()
        self._thread = None
        self._baseline_ip = None

    def _check_once(self) -> None:
        ip = core.get_public_ip()
        if ip.startswith("error"):
            self.on_alert(f"Could not fetch public IP to check for leaks: {ip}")
            return

        if self._baseline_ip is None:
            self._baseline_ip = ip
            return  # first check just establishes the baseline

        if self.expect_tunnel:
            tor_check = proxy_tor.check_tor_active()
            if "error" not in tor_check and not tor_check.get("IsTor"):
                self.on_alert(f"Traffic no longer appears to be routing through Tor "
                              f"(exit check failed). Current public IP: {ip}")
            dns_report = dns_check.dns_leak_check(self.env, expect_local_only=True)
            if "LIKELY LEAKING" in dns_report["leak_verdict"]:
                self.on_alert(f"DNS leak detected mid-session: {dns_report['leak_verdict']}")

        if ip != self._baseline_ip:
            # Not necessarily bad (Tor rotates exits) — but worth surfacing
            self.on_alert(f"Public/exit IP changed: {self._baseline_ip} -> {ip}")
            self._baseline_ip = ip

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._check_once()
            except Exception as e:
                self.on_alert(f"Monitor check raised an exception: {e}")
            self._stop_event.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            print("[i] Monitor already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[+] Leak monitor started (checking every {self.interval}s).")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        print("[+] Leak monitor stopped.")

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
