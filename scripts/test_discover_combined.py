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
