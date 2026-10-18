"""Launcher-level safety: what gets committed, saved, selected and refused."""
import csv
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))

import analyze_sf_program  # noqa: E402
import apply_enrichment_to_user_project as enrich_one  # noqa: E402
import discover_combined  # noqa: E402
import evidence_identity  # noqa: E402
import ghidra_project  # noqa: E402
import review_queue  # noqa: E402
import target_pe  # noqa: E402
from pyghidra_result import completion_line  # noqa: E402

SHA = "a" * 64
VA = {"image_base": 0x140000000, "pointer_size": 8, "address_coordinate": "VA"}


# --------------------------------------------------------------- fakes
class _Address:
    def __init__(self, offset):
        self._offset = offset

    def getOffset(self):
        return self._offset


class _Options:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.in_transaction = lambda: True
        self.writes_outside_transaction = []

    def getString(self, key, default):
        return self.values.get(key, default)

    def getBoolean(self, key, default):
        return self.values.get(key, default)

    def setBoolean(self, key, value):
        if not self.in_transaction():
            self.writes_outside_transaction.append(key)
        self.values[key] = value


class _Program:
    def __init__(self, sha=SHA, path="", name="game.exe", end_result=None,
                 save_error=None, options=None):
        self.sha, self.path, self.name = sha, path, name
        self.transactions = []
        self.saves = []
        self.end_result = end_result
        self.save_error = save_error
        self.options = _Options(options)
        self.options.in_transaction = self._open_transaction

    def _open_transaction(self):
        return any(state is None for _label, state in self.transactions)

    def getName(self):
        return self.name

    def getExecutableSHA256(self):
        return self.sha

    def getExecutablePath(self):
        return self.path

    def getImageBase(self):
        return _Address(0x140000000)

    def getDefaultPointerSize(self):
        return 8

    def getOptions(self, _name):
        return self.options

    def startTransaction(self, label):
        self.transactions.append([label, None])
        return len(self.transactions) - 1

    def endTransaction(self, transaction_id, commit):
        self.transactions[transaction_id][1] = commit
        return commit if self.end_result is None else self.end_result

    def save(self, label, _monitor):
        if self.save_error is not None:
            raise self.save_error
        self.saves.append(label)


def _script(driver, stderr=""):
    out = "ran\n" + completion_line(driver) + "\n"
    return lambda *args, **kwargs: (out, stderr)


def _run(program, driver, apply):
    return discover_combined._run_driver(
        _script(driver), object(), program, driver, apply=apply, pass_no=1,
        monitor=None, evidence="", decisions="")


# ---------------------------------------------------- L11: commit + save
def test_dry_run_and_read_only_miners_are_rolled_back_not_committed():
    for driver, apply in (("ctor_apply", False), ("ctor_mine", False),
                          ("ctor_mine", True), ("globals_harvest", True)):
        program = _Program()
        assert _run(program, driver, apply) == "OK"
        assert program.transactions[0][1] is False, (driver, apply)
        assert program.saves == []


def test_applying_mutating_driver_commits_and_saves():
    program = _Program()
    assert _run(program, "globals_apply", True) == "OK"
    assert program.transactions[0][1] is True
    assert program.saves == ["discover: globals_apply pass 1"]


def test_poisoned_outer_transaction_is_a_failure_and_never_saved():
    # endTransaction returning False == nested work was rolled back.
    program = _Program(end_result=False)
    assert _run(program, "globals_apply", True) == "FAIL"
    assert program.saves == []


def test_raising_save_is_reported_as_fail_not_a_traceback(capsys):
    program = _Program(save_error=OSError("disk full"))
    assert _run(program, "globals_apply", True) == "FAIL-save"
    out = capsys.readouterr().out
    assert "disk full" in out and "NOT on disk" in out


def test_single_driver_launcher_has_the_same_commit_rules():
    program = _Program(end_result=False)
    assert enrich_one.run_driver(_script("settings_harvest"), object(), program,
                                 "settings_harvest", applying=True,
                                 monitor=None) is False
    assert program.saves == []
    program = _Program(save_error=OSError("disk full"))
    assert enrich_one.run_driver(_script("settings_harvest"), object(), program,
                                 "settings_harvest", applying=True,
                                 monitor=None) is False
    program = _Program()
    assert enrich_one.run_driver(_script("settings_harvest"), object(), program,
                                 "settings_harvest", applying=False,
                                 monitor=None) is True
    assert program.transactions[0][1] is False and program.saves == []
    # A driver that raised arrives as stderr: FAIL + rollback, even applying.
    program = _Program()
    assert enrich_one.run_driver(
        _script("ctor_apply", stderr="ReviewQueueError: no ctor evidence"),
        object(), program, "ctor_apply", applying=True, monitor=None) is False
    assert program.transactions[0][1] is False and program.saves == []


# ------------------------------------------ L6: explicit programs, env scrub
def _args(**overrides):
    values = dict(programs=None, all_programs=False)
    values.update({dest: None for dest, _ in discover_combined.TUNING.values()})
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _error(message):
    raise SystemExit(message)


def test_apply_without_explicit_programs_is_refused():
    with pytest.raises(SystemExit, match="--programs"):
        discover_combined._resolve_programs(_args(), {"globals"}, _error)
    assert discover_combined._resolve_programs(
        _args(programs=["/A/b.exe"]), {"globals"}, _error) == ["/A/b.exe"]
    assert discover_combined._resolve_programs(
        _args(all_programs=True), {"globals"}, _error
    ) == discover_combined.DEFAULT_PROGRAMS
    # A dry run may still default to everything.
    assert discover_combined._resolve_programs(
        _args(), set(), _error) == discover_combined.DEFAULT_PROGRAMS


def test_inherited_tuning_is_scrubbed_and_cli_values_are_echoed():
    environ = {"BGS_GLOBALS_MIN_CONF": "medium", "BGS_ENRICH_APPLY": "go",
               "BGS_TARGET_PE": "C:/evil.exe", "BGS_CTOR_TIMEOUT": "1",
               "UNRELATED": "kept"}
    lines = discover_combined._apply_tuning(
        _args(globals_min_indeg=3, ctor_timeout=0), environ)
    assert environ == {"UNRELATED": "kept", "BGS_GLOBALS_MIN_INDEG": "3"}
    text = "\n".join(lines)
    assert "BGS_GLOBALS_MIN_INDEG" in text and "(CLI)" in text
    assert "inherited 'medium' IGNORED" in text


# ------------------------------------------------------- L5: --target-pe
def test_target_pe_candidate_with_the_import_hash_is_selected(tmp_path):
    wrong = tmp_path / "wrong.exe"
    right = tmp_path / "right.exe"
    wrong.write_bytes(b"w")
    right.write_bytes(b"r")
    hashes = {str(wrong): "b" * 64, str(right): SHA}
    inspected = []

    def inspect(path):
        inspected.append(path)
        return {"sha256": hashes[path]}

    program = _Program(path="/C:/gone/Game.exe")
    path, manifest = target_pe.select_target_pe(
        program, [str(tmp_path / "missing.exe"), str(wrong), str(right)],
        inspect=inspect)
    assert path == str(right) and manifest == {"sha256": SHA}


def test_dead_recorded_path_without_candidates_is_actionable(tmp_path):
    program = _Program(path="/C:/gone/Game.exe")
    with pytest.raises(target_pe.TargetPEError) as info:
        target_pe.select_target_pe(program, [], inspect=lambda path: {})
    assert "--target-pe" in str(info.value) and SHA in str(info.value)
    wrong = tmp_path / "wrong.exe"
    wrong.write_bytes(b"w")
    with pytest.raises(target_pe.TargetPEError, match="SHA-256 differs"):
        target_pe.select_target_pe(
            program, [str(wrong)], inspect=lambda path: {"sha256": "b" * 64})


def test_driver_uses_env_target_but_still_verifies(monkeypatch, tmp_path):
    import binary_identity
    seen = {}
    monkeypatch.setattr(binary_identity, "inspect_pe",
                        lambda path: seen.setdefault("path", path) and {"p": path})

    def verify(program, manifests):
        seen["verified"] = manifests
        raise ValueError("wrong file")

    monkeypatch.setattr(binary_identity, "verify_ghidra_program", verify)
    program = _Program(path="/C:/gone/Game.exe")
    with pytest.raises(ValueError, match="wrong file"):       # fails closed
        target_pe.driver_target_manifest(
            program, {"BGS_TARGET_PE": str(tmp_path / "x.exe")})
    assert seen["path"] == str(tmp_path / "x.exe")
    assert seen["verified"] == [{"p": str(tmp_path / "x.exe")}]


# ------------------------------------------- L4 / V6: evidence + decisions
def _write(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


GLOBAL_FIELDS = ["global_addr", "inferred_type", "confidence", "decision_type"]


def _mine_globals(evidence):
    _write(evidence, GLOBAL_FIELDS, [{"global_addr": "0x140001000",
                                      "inferred_type": "Foo",
                                      "confidence": "high"}])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", SHA, "game.exe", **VA)


def test_harvest_then_apply_works_through_the_single_driver_launcher(
        tmp_path, monkeypatch):
    """V6.1: harvest bound `globals_evidence`, apply demanded
    `globals_decisions` on the same path -- it could never apply."""
    evidence = tmp_path / "globals_queue_game_exe.csv"
    decisions = tmp_path / "globals_decisions_game_exe.csv"
    environ = {"BGS_GLOBALS_CSV": str(evidence),
               "BGS_GLOBALS_APPLY_CSV": str(decisions)}
    out = "ok\n" + completion_line("globals_harvest") + "\n"

    def harvest(*_args, **_kwargs):
        _mine_globals(evidence)
        return out, ""

    program = _Program()
    assert enrich_one.run_driver(harvest, object(), program, "globals_harvest",
                                 applying=False, monitor=None,
                                 environ=environ) is True
    assert decisions.is_file()
    # What globals_apply does next, with the same env:
    paths = review_queue.queue_paths(review_queue.GLOBALS, "game.exe", environ)
    rows, n_decisions = review_queue.load_reviewed_rows(
        *paths, program, review_queue.GLOBALS)
    assert [row["inferred_type"] for row in rows] == ["Foo"]
    assert n_decisions == 0


def test_reviewer_can_fill_decisions_without_breaking_the_evidence_binding(
        tmp_path):
    evidence = tmp_path / "evidence.csv"
    decisions = tmp_path / "decisions.csv"
    _mine_globals(evidence)
    review_queue.merge_review_queue(evidence, decisions, review_queue.GLOBALS)
    text = decisions.read_text(encoding="utf-8").replace(
        "Foo,high,", "Tampered,high,ReviewedFoo")
    decisions.write_text(text, encoding="utf-8")
    rows, n_decisions = review_queue.load_reviewed_rows(
        evidence, decisions, _Program(), review_queue.GLOBALS)
    assert n_decisions == 1
    assert rows[0]["decision_type"] == "ReviewedFoo"
    # Only the decision column is taken from the editable file.
    assert rows[0]["inferred_type"] == "Foo"


def test_missing_stale_or_foreign_evidence_is_refused(tmp_path):
    evidence = tmp_path / "evidence.csv"
    with pytest.raises(review_queue.ReviewQueueError, match="no globals evidence"):
        review_queue.load_reviewed_rows(evidence, None, _Program(),
                                        review_queue.GLOBALS)
    _mine_globals(evidence)
    with pytest.raises(review_queue.ReviewQueueError, match="does not match"):
        review_queue.load_reviewed_rows(evidence, None, _Program(sha="c" * 64),
                                        review_queue.GLOBALS)
    evidence.write_text(evidence.read_text(encoding="utf-8") + "x\n",
                        encoding="utf-8")
    with pytest.raises(review_queue.ReviewQueueError, match="changed after mining"):
        review_queue.load_reviewed_rows(evidence, None, _Program(),
                                        review_queue.GLOBALS)


CTOR_FIELDS = ["class", "offset", "type", "name", "slot_state", "votes",
               "confidence", "constructors", "decision"]


def _mine_ctors(evidence, type_name="float"):
    _write(evidence, CTOR_FIELDS, [{
        "class": "Actor", "offset": "0x10", "type": type_name, "name": "speed",
        "slot_state": "unknown", "votes": "3", "confidence": "low",
        "constructors": "f@0x1"}])
    evidence_identity.bind_for_hash(evidence, "ctor_fields", SHA, "game.exe")


def test_ctor_decisions_survive_a_remine_only_for_the_same_proposal(tmp_path):
    evidence = tmp_path / "ctor_fields.csv"
    decisions = tmp_path / "ctor_decisions.csv"
    _mine_ctors(evidence)
    review_queue.merge_review_queue(evidence, decisions, review_queue.CTORS)
    decisions.write_text(
        decisions.read_text(encoding="utf-8").replace("f@0x1,", "f@0x1,apply"),
        encoding="utf-8")
    rows, _ = review_queue.load_reviewed_rows(
        evidence, decisions, _Program(), review_queue.CTORS)
    assert rows[0]["decision"] == "apply"          # V6.2: no rebind needed
    _mine_ctors(evidence)                                  # same proposal
    review_queue.merge_review_queue(evidence, decisions, review_queue.CTORS)
    rows, _ = review_queue.load_reviewed_rows(
        evidence, decisions, _Program(), review_queue.CTORS)
    assert rows[0]["decision"] == "apply"
    _mine_ctors(evidence, type_name="int")                 # a DIFFERENT proposal
    review_queue.merge_review_queue(evidence, decisions, review_queue.CTORS)
    rows, _ = review_queue.load_reviewed_rows(
        evidence, decisions, _Program(), review_queue.CTORS)
    assert rows[0]["decision"] == ""


class _DataTypeManager:
    def getAllDataTypes(self):
        return []


def _ctor_apply(monkeypatch, tmp_path, apply):
    import ctor_apply
    program = _Program()
    program.getDataTypeManager = lambda: _DataTypeManager()
    monkeypatch.setattr(ctor_apply, "APPLY", apply)
    monkeypatch.setattr(ctor_apply, "currentProgram", program, raising=False)
    monkeypatch.setenv("BGS_CTOR_CSV", str(tmp_path / "absent.csv"))
    monkeypatch.setenv("BGS_CTOR_DECISIONS_CSV", str(tmp_path / "absent2.csv"))
    return ctor_apply


def test_ctor_apply_without_evidence_raises_when_applying(tmp_path, monkeypatch):
    driver = _ctor_apply(monkeypatch, tmp_path, apply=True)
    with pytest.raises(review_queue.ReviewQueueError, match="no ctor evidence"):
        driver.run()


def test_ctor_apply_without_evidence_says_refused_in_dry_run(
        tmp_path, monkeypatch, capsys):
    _ctor_apply(monkeypatch, tmp_path, apply=False).run()
    assert "REFUSED:" in capsys.readouterr().out


def test_globals_apply_without_evidence_raises_when_applying(tmp_path, monkeypatch):
    import globals_apply
    symbol = types.ModuleType("ghidra.program.model.symbol")
    symbol.SourceType = object()
    for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", symbol)
    monkeypatch.setattr(target_pe, "driver_target_manifest",
                        lambda program: {"image_base": 0x140000000,
                                         "image_size": 0x1000, "sections": []})

    class _Anything:
        def __getattr__(self, _name):
            return lambda *args, **kwargs: _Anything()

    program = _Program()
    for name in ("getDataTypeManager", "getListing", "getSymbolTable",
                 "getAddressFactory"):
        setattr(program, name, lambda: _Anything())
    monkeypatch.setattr(globals_apply, "currentProgram", program, raising=False)
    monkeypatch.setenv("BGS_GLOBALS_CSV", str(tmp_path / "absent.csv"))
    monkeypatch.setenv("BGS_GLOBALS_APPLY_CSV", str(tmp_path / "absent2.csv"))
    monkeypatch.setattr(globals_apply, "APPLY", True)
    with pytest.raises(review_queue.ReviewQueueError, match="no globals evidence"):
        globals_apply.run()
    monkeypatch.setattr(globals_apply, "APPLY", False)
    globals_apply.run()                                   # dry-run: no raise


# --------------------------------------------------------- L13: ambiguity
class _File:
    def __init__(self, name):
        self._name = name

    def getName(self):
        return self._name


class _Folder:
    def __init__(self, name, files=(), folders=()):
        self._name, self._files, self._folders = name, files, folders

    def getName(self):
        return self._name

    def getFiles(self):
        return list(self._files)

    def getFolders(self):
        return list(self._folders)


def test_by_name_lookup_refuses_several_matching_builds():
    first, second = _File("Starfield.exe"), _File("Starfield.exe.unpacked.exe")
    root = _Folder("", folders=[_Folder("a", [first]), _Folder("b", [second])])
    with pytest.raises(ghidra_project.AmbiguousProgramError) as info:
        ghidra_project.find_program_by_name(root, "Starfield.exe")
    assert "/a/Starfield.exe" in str(info.value)
    assert "--program-path" in str(info.value)
    assert ghidra_project.find_program_by_name(
        root, "Starfield.exe", "/b/Starfield.exe.unpacked.exe") is second
    lone = _Folder("", folders=[_Folder("a", [first])])
    assert ghidra_project.find_program_by_name(lone, "Starfield.exe") is first


# --------------------------------------------------- L3: analyze_sf_program
class _Manager:
    def __init__(self, log):
        self.log = log

    def initializeOptions(self):
        self.log.append("init")

    def reAnalyzeAll(self, _set):
        self.log.append("reanalyze")

    def startAnalysis(self, _monitor):
        self.log.append("start")


class _Monitor:
    def isCancelled(self):
        return False


def _analyze(monkeypatch, program, **kwargs):
    log = []
    monkeypatch.setattr(analyze_sf_program, "select_target_pe",
                        lambda prog, candidates: ("x.exe", {"sha256": SHA}))
    monkeypatch.setattr(analyze_sf_program, "verify_ghidra_program",
                        lambda prog, manifests: log.append("verified"))
    analyze_sf_program.analyze(
        program, "/Starfield/x", _Monitor(),
        manager_factory=lambda prog: _Manager(log), **kwargs)
    return log


def test_analysis_refuses_an_already_analyzed_program(monkeypatch):
    for options in ({"Analyzed": True}, {"BGS Pipeline Stage": "generic-v2"}):
        program = _Program(options=options)
        with pytest.raises(RuntimeError, match="refusing to re-analyze"):
            _analyze(monkeypatch, program)
        assert program.transactions == [] and program.saves == []
    program = _Program(options={"Analyzed": True})
    assert "start" in _analyze(monkeypatch, program, force=True)


def test_analysis_verifies_identity_first_and_flags_inside_the_transaction(
        monkeypatch):
    program = _Program()
    log = _analyze(monkeypatch, program)
    assert log == ["verified", "init", "reanalyze", "start"]
    assert program.options.values["Analyzed"] is True
    assert program.options.writes_outside_transaction == []
    assert program.transactions == [["auto-analysis", True]]
    assert program.saves == ["Full auto-analysis"]


def test_analysis_is_not_saved_when_the_transaction_did_not_commit(monkeypatch):
    program = _Program(end_result=False)
    with pytest.raises(RuntimeError, match="did not commit"):
        _analyze(monkeypatch, program)
    assert program.saves == []


def test_analysis_stops_on_identity_mismatch(monkeypatch):
    program = _Program()
    monkeypatch.setattr(analyze_sf_program, "select_target_pe",
                        lambda prog, candidates: ("x.exe", {}))

    def verify(_program, _manifests):
        raise ValueError("SHA-256 mismatch")

    monkeypatch.setattr(analyze_sf_program, "verify_ghidra_program", verify)
    with pytest.raises(ValueError):
        analyze_sf_program.analyze(program, "/p", _Monitor(),
                                   manager_factory=lambda prog: None)
    assert program.transactions == []


# ------------------------------------------------ fixed point vs. rollbacks
def test_a_rollback_never_counts_as_a_change_for_the_fixed_point():
    """Ghidra bumps getModificationNumber() on ROLLBACK (probed on 12.0.4), and
    miners / dry-runs are always rolled back: the fixed point must ignore it."""
    assert discover_combined._driver_changed(3, 4, committed=False) is False
    assert discover_combined._driver_changed(3, 4, committed=True) is True
    assert discover_combined._driver_changed(4, 4, committed=True) is False

    class _Functions:
        def getFunctions(self, _forward):
            return []

        def getFunctionCount(self):
            return 0

    class _Symbols:
        def getAllSymbols(self, _forward):
            return []

    class _Counting:
        modification = 7

        def getFunctionManager(self):
            return _Functions()

        def getSymbolTable(self):
            return _Symbols()

        def getModificationNumber(self):
            return self.modification

    program = _Counting()
    before = discover_combined._metrics(program)
    program.modification = 8                      # a rolled-back miner ran
    assert discover_combined._metrics(program) == before
