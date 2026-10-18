import csv

import discover_combined
import evidence_identity


FIELDS = ["global_addr", "inferred_type", "decision_type"]
VA_BINDING = {
    "image_base": 0x140000000,
    "pointer_size": 8,
    "address_coordinate": "VA",
}


def _write(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def test_review_merge_preserves_only_same_target_decisions(tmp_path):
    evidence = tmp_path / "evidence.csv"
    decisions = tmp_path / "decisions.csv"
    _write(evidence, [{"global_addr": "0x10", "inferred_type": "Foo",
                       "decision_type": ""}])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", "a" * 64, "game.exe", **VA_BINDING)
    _write(decisions, [{"global_addr": "0x10", "inferred_type": "Old",
                        "decision_type": "ReviewedFoo"}])
    evidence_identity.bind_for_hash(
        decisions, "globals_decisions", "a" * 64, "game.exe", **VA_BINDING)

    discover_combined._merge_review_queue(evidence, decisions)

    row = next(csv.DictReader(decisions.open(newline="", encoding="utf-8")))
    assert row["inferred_type"] == "Foo"
    assert row["decision_type"] == "ReviewedFoo"
    binding = evidence_identity.read_binding(decisions, "globals_decisions", True)
    assert binding["target_sha256"] == "a" * 64


def test_review_merge_drops_stale_target_decisions(tmp_path):
    evidence = tmp_path / "evidence.csv"
    decisions = tmp_path / "decisions.csv"
    _write(evidence, [{"global_addr": "0x10", "inferred_type": "Foo",
                       "decision_type": ""}])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", "a" * 64, **VA_BINDING)
    _write(decisions, [{"global_addr": "0x10", "inferred_type": "Old",
                        "decision_type": "WrongTarget"}])
    evidence_identity.bind_for_hash(
        decisions, "globals_decisions", "b" * 64, **VA_BINDING)

    discover_combined._merge_review_queue(evidence, decisions)

    row = next(csv.DictReader(decisions.open(newline="", encoding="utf-8")))
    assert row["decision_type"] == ""


def test_review_merge_drops_same_sha_rebased_va_decisions(tmp_path):
    evidence = tmp_path / "evidence.csv"
    decisions = tmp_path / "decisions.csv"
    _write(evidence, [{"global_addr": "0x150001000", "inferred_type": "Foo",
                       "decision_type": ""}])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", "a" * 64,
        image_base=0x150000000, pointer_size=8, address_coordinate="VA")
    _write(decisions, [{"global_addr": "0x140001000", "inferred_type": "Old",
                        "decision_type": "WrongBase"}])
    evidence_identity.bind_for_hash(
        decisions, "globals_decisions", "a" * 64,
        image_base=0x140000000, pointer_size=8, address_coordinate="VA")

    discover_combined._merge_review_queue(evidence, decisions)

    row = next(csv.DictReader(decisions.open(newline="", encoding="utf-8")))
    assert row["decision_type"] == ""


class _FakeProgram:
    def __init__(self):
        self.transactions = []
        self.saves = []

    def startTransaction(self, label):
        self.transactions.append([label, None])
        return len(self.transactions) - 1

    def endTransaction(self, transaction_id, commit):
        self.transactions[transaction_id][1] = commit
        return commit

    def save(self, label, monitor):
        self.saves.append(label)


def _run(stdout, stderr="", driver="ctor_apply", apply=True):
    program = _FakeProgram()
    rc = discover_combined._run_driver(
        lambda *args, **kwargs: (stdout, stderr), object(), program, driver,
        apply=apply, pass_no=1, monitor=None, evidence="", decisions="")
    return rc, program


def test_driver_without_output_is_a_failure_and_is_rolled_back():
    rc, program = _run("")
    assert rc == "FAIL-no-op"
    assert program.transactions == [["Atomic discovery driver ctor_apply", False]]
    assert program.saves == []


def test_driver_with_output_but_no_sentinel_is_a_failure():
    rc, program = _run("ctor-apply (x): DRY-RUN\n")
    assert rc == "FAIL-no-op"
    assert program.saves == []


def test_driver_with_another_drivers_sentinel_is_a_failure():
    from pyghidra_result import completion_line
    rc, _program = _run(completion_line("console_harvest") + "\n",
                        driver="console_harvest_sf")
    assert rc == "FAIL-no-op"


def test_driver_stderr_fails_even_with_sentinel():
    from pyghidra_result import completion_line
    rc, program = _run(completion_line("ctor_apply"), stderr="Traceback ...")
    assert rc == "FAIL"
    assert program.transactions[0][1] is False
    assert program.saves == []


def test_completed_driver_commits_and_saves_only_when_applying():
    from pyghidra_result import completion_line
    out = "ctor-apply: ok\n" + completion_line("ctor_apply") + "\n"
    rc, program = _run(out)
    assert rc == "OK"
    assert program.transactions[0][1] is True
    assert program.saves == ["discover: ctor_apply pass 1"]
    rc, program = _run(out, apply=False)
    assert rc == "OK" and program.saves == []
    rc, program = _run(completion_line("ctor_mine"), driver="ctor_mine")
    assert rc == "OK" and program.saves == []


def test_no_op_stops_the_program_like_any_other_failure():
    import inspect
    source = inspect.getsource(discover_combined.main)
    assert "if rc.startswith('FAIL'):" in source
    assert "if rc == 'FAIL'" not in source
