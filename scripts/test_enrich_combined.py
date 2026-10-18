import sys

import pytest

import enrich_combined


def _fake_steps(monkeypatch, returncode=0):
    calls = []
    monkeypatch.setattr(
        enrich_combined, "APPLY_STEPS",
        [("up", "upstream", "one.py", []),
         ("mid", "inserted later", "mid.py", []),
         ("down", "dependent write-back", "two.py", [])])
    monkeypatch.setattr(
        enrich_combined.subprocess, "run",
        lambda cmd: calls.append(cmd[1].replace("\\", "/").rsplit("/", 1)[1])
        or type("Result", (), {"returncode": returncode})())
    return calls


def test_default_orchestrator_fails_before_dependent_step(monkeypatch):
    calls = _fake_steps(monkeypatch, returncode=9)
    monkeypatch.setattr(sys, "argv", ["enrich_combined.py"])
    assert enrich_combined.main() == 1
    assert calls == ["one.py"]


def test_steps_are_selected_by_stable_name(monkeypatch):
    calls = _fake_steps(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["enrich_combined.py", "--only", "down"])
    assert enrich_combined.main() == 0
    assert calls == ["two.py"]

    del calls[:]
    monkeypatch.setattr(sys, "argv", ["enrich_combined.py", "--skip", "mid", "1"])
    assert enrich_combined.main() == 0
    assert calls == ["two.py"]


@pytest.mark.parametrize("argv", [["--skip", "2,3"], ["--skip", "fnv"],
                                  ["--only", "9"], ["--only", "0"]])
def test_unknown_step_tokens_are_rejected_not_ignored(monkeypatch, argv):
    calls = _fake_steps(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["enrich_combined.py"] + argv)
    with pytest.raises(SystemExit) as raised:
        enrich_combined.main()
    assert raised.value.code == 2
    assert calls == []


def test_step_names_are_unique_and_documented():
    names = [step[0] for step in enrich_combined.APPLY_STEPS]
    assert len(names) == len(set(names))
    assert not any(name.isdigit() for name in names)
    for name, label, _script, _extra in enrich_combined.APPLY_STEPS:
        assert name in enrich_combined.__doc__
        assert label in enrich_combined.__doc__
    # every Skyrim runtime the project holds has its own addressable step
    assert {"skyrim-16640", "skyrim-17104"} <= set(names)
