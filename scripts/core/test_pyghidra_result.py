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
