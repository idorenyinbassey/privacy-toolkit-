"""
Tests for the state.py race-condition fix: the GUI runs every button's
action in its own background thread (gui.py's _run_bg), so concurrent
enable/disable actions can race on load-modify-save against the same
JSON file. A threading.Lock around load/update/save, plus an atomic
(temp-file + os.replace) write, closes both the lost-update race and
the torn-read risk.
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacyguard import state as statemod


def test_concurrent_updates_do_not_lose_writes(tmp_path, monkeypatch):
    """The actual race this fix closes: two threads each doing their
    own load-modify-save on state.json used to be able to stomp on
    each other, silently dropping one thread's field change — e.g.
    enabling the kill switch and enabling portscan protection at
    nearly the same time from two GUI button clicks."""
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    statemod.update()  # create the file with defaults first

    keys = [f"probe_key_{i}" for i in range(30)]

    def worker(key):
        for _ in range(20):  # hammer it to make a lost update likely without the lock
            statemod.update(**{key: True})

    threads = [threading.Thread(target=worker, args=(k,)) for k in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = statemod.load()
    missing = [k for k in keys if final.get(k) is not True]
    assert not missing, f"lost update(s) for keys: {missing}"


def test_save_is_atomic_no_leftover_tmp_file(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(statemod, "STATE_FILE", state_file)
    statemod.update(tor_kill_switch=True)
    assert state_file.exists()
    assert not (tmp_path / "state.json.tmp").exists(), "the temp file must be renamed away, not left behind"


def test_state_still_valid_json_after_many_updates(tmp_path, monkeypatch):
    monkeypatch.setattr(statemod, "STATE_FILE", tmp_path / "state.json")
    for i in range(10):
        statemod.update(active_proxy=f"socks5://1.2.3.{i}:1080")
    loaded = statemod.load()
    assert loaded["active_proxy"] == "socks5://1.2.3.9:1080"
