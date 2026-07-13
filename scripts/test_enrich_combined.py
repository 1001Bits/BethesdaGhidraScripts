import sys

import enrich_combined


def test_default_orchestrator_fails_before_dependent_step(monkeypatch):
    calls = []
    monkeypatch.setattr(
        enrich_combined, "APPLY_STEPS",
        [("upstream", "one.py", []), ("dependent write-back", "two.py", [])])
    monkeypatch.setattr(
        enrich_combined.subprocess, "run",
        lambda cmd: calls.append(cmd) or type("Result", (), {"returncode": 9})())
    monkeypatch.setattr(sys, "argv", ["enrich_combined.py"])
    assert enrich_combined.main() == 1
    assert len(calls) == 1
