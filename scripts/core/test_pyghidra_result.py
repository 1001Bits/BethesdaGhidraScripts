import pytest

from pyghidra_result import (PyGhidraScriptError, end_outer_transaction,
                             require_script_success)


def test_empty_stderr_is_success():
    require_script_success(None)
    require_script_success("")
    require_script_success("  \n")


def test_any_script_stderr_fails_closed():
    with pytest.raises(PyGhidraScriptError, match="import failed"):
        require_script_success("Traceback\nimport failed", "generated importer")


def test_outer_transaction_must_report_final_commit():
    class Program:
        def __init__(self, result):
            self.result = result

        def endTransaction(self, transaction_id, commit):
            assert transaction_id == 7
            return self.result

    end_outer_transaction(Program(False), 7, False, "rolled back")
    end_outer_transaction(Program(True), 7, True, "importer")
    with pytest.raises(PyGhidraScriptError, match="did not commit"):
        end_outer_transaction(Program(False), 7, True, "importer")


def test_script_program_resolves_pyghidra_style_globals():
    import pyghidra_result as pr

    class ScriptGlobals(dict):
        # PyGhidraScript resolves GhidraScript state on lookup only; ``in``
        # stays false, which is what silently disabled the old guards.
        def __missing__(self, key):
            if key == "currentProgram":
                return "program"
            raise KeyError(key)

    script_globals = ScriptGlobals()
    assert "currentProgram" not in script_globals
    assert pr.script_program(script_globals) == "program"
    assert pr.script_program({}) is None
    assert pr.script_program({"currentProgram": None}) is None


def test_driver_completion_sentinel_is_required():
    import pyghidra_result as pr

    line = pr.completion_line("ctor_mine")
    pr.require_driver_completion("ctor-mine: 3 classes\n" + line + "\n", "ctor_mine")
    pr.require_driver_completion("  " + line + "  \r\n", "ctor_mine")
    for stdout in (None, "", "ctor-mine: 3 classes\n",
                   pr.completion_line("ctor_apply"),
                   "prefix " + line, line + "_sf"):
        with pytest.raises(pr.PyGhidraScriptNoOp, match="ctor_mine"):
            pr.require_driver_completion(stdout, "ctor_mine")


def test_no_script_gates_its_entry_point_on_in_globals():
    """``'currentProgram' in globals()`` is always False under PyGhidra."""
    import ast
    from pathlib import Path

    scripts = Path(__file__).resolve().parent.parent
    offenders = []
    for path in sorted(scripts.rglob("*.py")):
        if path.name.startswith("test_"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and
                    isinstance(node.ops[0], (ast.In, ast.NotIn))):
                continue
            target = node.comparators[0]
            if (isinstance(target, ast.Call) and
                    isinstance(target.func, ast.Name) and
                    target.func.id in ("globals", "locals", "vars", "dir")):
                offenders.append("{}:{}".format(path.relative_to(scripts), node.lineno))
    assert offenders == []


def test_every_sequenced_driver_prints_its_own_completion_sentinel():
    import ast
    import sys
    from pathlib import Path

    scripts = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(scripts))
    try:
        import apply_enrichment_to_user_project as single
        import discover_combined as sequencer
    finally:
        sys.path.remove(str(scripts))
    drivers = dict(single.DRIVERS)
    drivers.update(sequencer.DRIVER_PATHS)
    assert set(sequencer.DRIVER_PATHS) <= set(single.DRIVERS)
    for name, path in sorted(drivers.items()):
        assert Path(path).stem == name
        tree = ast.parse(Path(path).read_text(encoding="utf-8-sig"))
        guard = tree.body[-1]
        assert isinstance(guard, ast.If), name
        assert ast.unparse(guard.test) == "script_program(globals()) is not None", name
        assert [ast.unparse(stmt) for stmt in guard.body] == [
            "run()", "print(completion_line({!r}))".format(name)], name
