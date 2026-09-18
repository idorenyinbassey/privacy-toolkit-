"""
Tests for main.py's small CLI-prompt helpers, extracted from four
near-identical "paste lines until blank line" blocks (menu options 11,
12, and two inside 26) and five near-identical "enable or disable?"
prompts (options 6, 7, 8, 13, 29) that had drifted slightly out of
sync with each other — different wording ("enable/disable" vs "enable
or disable? [enable/disable]"), and a couple were case-sensitive while
the rest weren't.
"""
import builtins
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main


def _feed(monkeypatch, values):
    it = iter(values)
    monkeypatch.setattr(builtins, "input", lambda *a, **kw: next(it))


def test_read_lines_stops_at_blank_line(monkeypatch):
    _feed(monkeypatch, ["first", "second", ""])
    assert main._read_lines() == ["first", "second"]


def test_read_lines_prints_prompt_when_given(monkeypatch, capsys):
    _feed(monkeypatch, [""])
    main._read_lines("Paste something:")
    assert "Paste something:" in capsys.readouterr().out


def test_read_lines_no_prompt_prints_nothing(monkeypatch, capsys):
    _feed(monkeypatch, [""])
    main._read_lines()
    assert capsys.readouterr().out == ""


def test_read_lines_empty_input_returns_empty_list(monkeypatch):
    _feed(monkeypatch, [""])
    assert main._read_lines() == []


def test_prompt_enable_true_on_enable(monkeypatch):
    _feed(monkeypatch, ["enable"])
    assert main._prompt_enable() is True


def test_prompt_enable_case_insensitive(monkeypatch):
    _feed(monkeypatch, ["ENABLE"])
    assert main._prompt_enable() is True


def test_prompt_enable_false_on_disable(monkeypatch):
    _feed(monkeypatch, ["disable"])
    assert main._prompt_enable() is False


def test_prompt_enable_false_on_blank(monkeypatch):
    _feed(monkeypatch, [""])
    assert main._prompt_enable() is False
