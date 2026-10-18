"""diff_importer_symbols keys placements by (name, rva) only, and
measure_port_precision grades --create-missing rows by default."""
import csv
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, filename):
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location(name, HERE / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
    return module


diff = _load("sse_diff_importer_symbols", "diff_importer_symbols.py")


def _importer(path, symbols, fallback):
    path.write_text(
        "SYMBOLS = _json.loads({!r})\nFALLBACK_SYMBOLS = _json.loads({!r})\n".format(
            json.dumps(symbols), json.dumps(fallback)), encoding="utf-8")
    return path


def test_a_symbol_that_only_changed_table_is_not_wrong(tmp_path):
    moved = {"n": "VTABLE_Foo", "t": "label", "si": 1, "17104": 0x1000}
    old = _importer(tmp_path / "old.py", [moved], [])
    new = _importer(tmp_path / "new.py", [], [dict(moved, si=None, src="x")])
    rows, _old, _new = diff.wrong_rows(diff.load_symbols(old),
                                       diff.load_symbols(new), "17104")
    assert rows == []


def test_moved_and_vanished_placements_are_listed(tmp_path):
    old = _importer(tmp_path / "old.py", [
        {"n": "A::f", "t": "func", "ai": 5, "17104": 0x10},
        {"n": "B::g", "t": "func", "ai": 6, "17104": 0x20},
        {"n": "C::h", "t": "func", "ai": 7, "17104": 0x30}], [])
    new = _importer(tmp_path / "new.py", [
        {"n": "A::f", "t": "func", "ai": 5, "17104": 0x11},   # moved
        {"n": "C::h", "t": "func", "ai": 7, "17104": 0x30}],  # unchanged
        [])
    rows, _old, _new = diff.wrong_rows(diff.load_symbols(old),
                                       diff.load_symbols(new), "17104")
    assert [(r["name"], r["wrong_rva"], r["correct_rva"]) for r in rows] == [
        ("A::f", "0x10", "0x11"), ("B::g", "0x20", "")]


def test_create_rows_are_graded_by_default(tmp_path, monkeypatch, capsys):
    measure = _load("sse_measure_port_precision", "measure_port_precision.py")
    importer = _importer(tmp_path / "imp.py", [
        {"n": "A::f", "t": "func", "a": 0x100, "s": 0x900}], [])
    evidence = tmp_path / "evidence.csv"
    with open(evidence, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "source_rva", "target_rva", "decision"])
        writer.writerow(["A::f", "0x100", "0x904", "create"])
    monkeypatch.setattr(sys, "argv", ["measure", str(evidence), str(importer),
                                      "--source-key", "a", "--target-key", "s"])
    measure.main()
    assert "correct=0  wrong=1" in capsys.readouterr().out
