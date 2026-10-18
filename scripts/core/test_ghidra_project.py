"""A locked Ghidra project must explain itself, not raise a Java stack trace."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ghidra_project  # noqa: E402


class _Javaish(Exception):
    """Stands in for the Java exception pyghidra surfaces."""


def test_lock_exception_is_recognised():
    assert ghidra_project.is_lock_error(
        _Javaish("ghidra.framework.store.LockException: Unable to lock project! "
                 "C:\\GhidraProjects\\Combined"))


def test_wrapped_lock_exception_is_recognised():
    # pyghidra re-raises through Python, so the lock is usually a __cause__.
    inner = _Javaish("LockException: Unable to lock project!")
    outer = RuntimeError("failed to open project")
    outer.__cause__ = inner
    assert ghidra_project.is_lock_error(outer)


def test_unrelated_failure_is_not_a_lock():
    assert not ghidra_project.is_lock_error(
        FileNotFoundError("no such project: Combined.gpr"))


def test_self_referential_cause_chain_terminates():
    # A cycle in __cause__/__context__ must not hang the check.
    first = RuntimeError("a")
    second = RuntimeError("b")
    first.__cause__ = second
    second.__cause__ = first
    assert ghidra_project.is_lock_error(first) is False


def test_message_names_the_lock_files_when_they_exist(tmp_path):
    (tmp_path / "Combined.lock").write_text("", encoding="ascii")
    message = ghidra_project.lock_message(tmp_path, "Combined")
    assert str(tmp_path / "Combined.lock") in message
    assert "crashed" in message


def test_message_explains_the_jvm_race_when_no_lock_file_exists(tmp_path):
    # The lock that actually bites is the *previous step's* JVM still exiting:
    # no lock file is on disk by the time we look, so a message that only says
    # "close Ghidra" sends the user hunting for a window that is not open.
    message = ghidra_project.lock_message(tmp_path, "Combined")
    assert "No lock file is present" in message
    assert "wait a few seconds and retry" in message
    assert "nothing was written" in message


def test_open_exits_with_the_reserved_code_when_locked(tmp_path, monkeypatch, capsys):
    fake = type(sys)("pyghidra")

    def open_project(*_args, **_kwargs):
        raise _Javaish("LockException: Unable to lock project!")

    fake.open_project = open_project
    monkeypatch.setitem(sys.modules, "pyghidra", fake)

    with pytest.raises(SystemExit) as excinfo:
        ghidra_project.open_user_project(tmp_path, "Combined")
    assert excinfo.value.code == ghidra_project.PROJECT_LOCKED_EXIT
    assert "is locked" in capsys.readouterr().out


def test_open_reraises_a_failure_that_is_not_a_lock(tmp_path, monkeypatch):
    fake = type(sys)("pyghidra")

    def open_project(*_args, **_kwargs):
        raise FileNotFoundError("Combined.gpr")

    fake.open_project = open_project
    monkeypatch.setitem(sys.modules, "pyghidra", fake)

    with pytest.raises(FileNotFoundError):
        ghidra_project.open_user_project(tmp_path, "Combined")
