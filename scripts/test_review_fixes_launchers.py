"""Launcher/gate fixes from the 2026-10 review (driver fixes: core/)."""
import ast
import csv
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))

import apply_enrichment_to_user_project as enrich_one  # noqa: E402
import discover_combined  # noqa: E402
import evidence_identity  # noqa: E402
import quality_gate  # noqa: E402
import review_queue  # noqa: E402
import run  # noqa: E402
from pyghidra_result import completion_line  # noqa: E402

SHA = "a" * 64
VA = {"image_base": 0x140000000, "pointer_size": 8, "address_coordinate": "VA"}
PROGRAM_PATH = "/Skyrim/SkyrimSE_1_5_97.exe"


class _Address:
    def getOffset(self):
        return 0x140000000


class _DomainFile:
    def getPathname(self):
        return PROGRAM_PATH


class _Program:
    def __init__(self):
        self.transactions = []
        self.saves = []

    def getName(self):
        return "SkyrimSE_1_5_97.exe"

    def getDomainFile(self):
        return _DomainFile()

    def getExecutableSHA256(self):
        return SHA

    def getImageBase(self):
        return _Address()

    def getDefaultPointerSize(self):
        return 8

    def startTransaction(self, label):
        self.transactions.append([label, None])
        return len(self.transactions) - 1

    def endTransaction(self, transaction_id, commit):
        self.transactions[transaction_id][1] = commit
        return commit

    def save(self, label, _monitor):
        self.saves.append(label)


# ---------------------------------------- 2: one queue naming, skip survives
def test_both_launchers_and_the_appliers_derive_the_same_queue_paths():
    program = _Program()
    for spec in (review_queue.GLOBALS, review_queue.CTORS):
        from_path = review_queue.queue_paths(spec, PROGRAM_PATH, {})
        # The in-Ghidra applier passes its Program: same files.
        assert review_queue.queue_paths(spec, program, {}) == from_path
        assert all("Skyrim_SkyrimSE_1_5_97_exe" in p for p in from_path)
    environment = review_queue.queue_environment(PROGRAM_PATH, {})
    assert environment["BGS_GLOBALS_CSV"].endswith(
        "globals_evidence_Skyrim_SkyrimSE_1_5_97_exe.csv")
    assert environment["BGS_CTOR_DECISIONS_CSV"].endswith(
        "ctor_decisions_Skyrim_SkyrimSE_1_5_97_exe.csv")
    # An explicit override still wins.
    assert review_queue.queue_environment(
        PROGRAM_PATH, {"BGS_CTOR_CSV": "x.csv"})["BGS_CTOR_CSV"] == "x.csv"
    source = inspect.getsource(discover_combined.main)
    assert "queue_paths(spec, prog_path, {})" in source
    assert "globals_evidence_{tag}" not in source


def test_skip_from_a_reviewed_queue_reaches_the_single_driver_applier(
        tmp_path):
    """Mine + review, then apply through the same derived paths: the
    reviewer's ``skip`` must arrive (it used to be lost to a name mismatch)."""
    environ = {"BGS_GLOBALS_CSV": str(tmp_path / "evidence.csv"),
               "BGS_GLOBALS_APPLY_CSV": str(tmp_path / "decisions.csv")}
    evidence, decisions = review_queue.queue_paths(
        review_queue.GLOBALS, PROGRAM_PATH, environ)

    def harvest(*_args, **_kwargs):
        with open(evidence, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["global_addr", "inferred_type", "confidence",
                             "decision_type"])
            writer.writerow(["0x140001000", "Foo", "high", ""])
        evidence_identity.bind_for_hash(evidence, "globals_evidence", SHA,
                                        "game.exe", **VA)
        return "ok\n" + completion_line("globals_harvest") + "\n", ""

    assert enrich_one.run_driver(harvest, object(), _Program(),
                                 "globals_harvest", applying=False,
                                 monitor=None, environ=environ) is True
    text = Path(decisions).read_text(encoding="utf-8")
    Path(decisions).write_text(text.replace("Foo,high,", "Foo,high,skip"),
                               encoding="utf-8")
    rows, n_decisions = review_queue.load_reviewed_rows(
        *review_queue.queue_paths(review_queue.GLOBALS, _Program(), environ),
        _Program(), review_queue.GLOBALS)
    assert n_decisions == 1 and rows[0]["decision_type"] == "skip"


# ---------------------------------------- 6: miners are never committed
def test_single_driver_launcher_commits_only_mutating_drivers():
    assert enrich_one.MUTATING == discover_combined.MUTATING
    assert not ({"ctor_mine", "globals_harvest", "havok_mine"}
                & enrich_one.MUTATING)
    program = _Program()
    out = "ok\n" + completion_line("havok_mine") + "\n"
    assert enrich_one.run_driver(lambda *a, **k: (out, ""), object(), program,
                                 "havok_mine", applying=True,
                                 monitor=None) is True
    assert program.transactions[0][1] is False and program.saves == []


# ---------------------------------------- 10: option 9 + recovered exes
def test_failed_option9_sequence_ends_the_session_non_zero(monkeypatch,
                                                           capsys):
    answers = iter(["9", "q"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(run, "_print_status", lambda: None)
    monkeypatch.setattr(run, "_show_menu", lambda: None)
    monkeypatch.setattr(run, "_enrich_menu", lambda: False)
    assert run._run_menu() == 1
    assert "improvement sequence did not complete" in capsys.readouterr().out
    # Backing out of the submenu (None) is not a failure.
    answers = iter(["9", "q"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(run, "_enrich_menu", lambda: None)
    assert run._run_menu() == 0


def test_enrich_menu_returns_the_sequence_result(monkeypatch):
    answers = iter(["1", "1"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(run, "_discover_ghidra_projects",
                        lambda: [("Combined", "C:/P", "Combined")])
    monkeypatch.setattr(run, "_list_programs_in_project",
                        lambda _d, _n: [(PROGRAM_PATH, None)])
    monkeypatch.setattr(run, "_run_enrichment_sequence",
                        lambda *_args: False)
    assert run._enrich_menu() is False


def test_recovered_exe_never_lands_beside_a_staged_original(tmp_path,
                                                           monkeypatch):
    monkeypatch.setattr(run, "EXES_ROOT", tmp_path)
    entry = next(e for e in run.VERSION_CATALOG
                 if e[4] == run._infer_commonlib_script(
                     Path(PROGRAM_PATH).name))
    ver_dir = tmp_path / entry[3]
    ver_dir.mkdir(parents=True)
    # Empty version folder: the recovered exe IS the staged target.
    assert run._recovery_dir(PROGRAM_PATH) == ver_dir
    original = ver_dir / "SkyrimSE.exe"
    original.write_bytes(b"MZ")
    (ver_dir / "SkyrimSE.unpacked.exe").write_bytes(b"MZ")
    target = run._recovery_dir(PROGRAM_PATH)
    assert target == ver_dir / run.RECOVERED_DIR_NAME
    target.mkdir()
    recovered = target / Path(PROGRAM_PATH).name
    recovered.write_bytes(b"MZ")
    # Discovery still sees exactly one original; candidates include both.
    assert run._discover_exes() == [
        (Path(entry[3]).parts[0], Path(entry[3]).parts[1], original)]
    assert recovered in run._local_target_pe_candidates(PROGRAM_PATH)
    assert run._is_recovered_artifact(recovered)
    assert not run._is_recovered_artifact(original)


# ---------------------------------------- 11: quality gate rule
def test_gate_flags_an_ignored_end_transaction_before_save(tmp_path,
                                                           monkeypatch):
    bad = ("def f(p, tx, ok, m):\n"
           "    p.endTransaction(tx, ok)\n"
           "    p.save('x', m)\n")
    good = ("def f(p, tx, ok, m):\n"
            "    if not p.endTransaction(tx, ok):\n"
            "        raise RuntimeError('rolled back')\n"
            "    p.save('x', m)\n"
            "def g(p, tx):\n"
            "    p.endTransaction(tx, False)\n"
            "    p.save('rollback has nothing to check', None)\n"
            "def h(p, tx, ok):\n"
            "    p.endTransaction(tx, ok)\n")
    path = tmp_path / "scripts" / "driver.py"
    path.parent.mkdir()
    monkeypatch.setattr(quality_gate, "ROOT", tmp_path)
    monkeypatch.setattr(quality_gate, "_python_files", lambda: iter([path]))
    path.write_text(bad, encoding="utf-8")
    errors = quality_gate.static_checks()[0]
    assert len(errors) == 1 and "endTransaction() result ignored" in errors[0]
    path.write_text(good, encoding="utf-8")
    assert quality_gate.static_checks()[0] == []


def test_files_fixed_here_pass_the_new_gate_rule():
    core = Path(__file__).resolve().parent / "core"
    for name in ("vtable_name_reconciler.py", "console_harvest_sf.py",
                 "settings_harvest.py"):
        tree = ast.parse((core / name).read_text(encoding="utf-8"))
        assert quality_gate.ignored_end_transaction_before_save(tree) == [], name
