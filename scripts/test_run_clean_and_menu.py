"""Option 8 / ``clean`` must not delete by accident, and a failed child step
must not kill the interactive menu."""
import subprocess

import pytest

import run


def _project(tmp_path, monkeypatch):
    projects = tmp_path / "ghidraprojects"
    project_dir = projects / run.GHIDRA_PROJECT_NAME
    project_dir.mkdir(parents=True)
    (project_dir / "work.gpr").write_text("x", encoding="ascii")
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="ascii")
    monkeypatch.setattr(run, "PROJECTS_DIR", projects)
    monkeypatch.setattr(run, "STATE_FILE", state)
    return project_dir, state


def _menu(monkeypatch, answers):
    replies = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(replies))
    monkeypatch.setattr(run, "_print_status", lambda: None)
    monkeypatch.setattr(run, "_show_menu", lambda: None)
    return run._run_menu()


def test_menu_clean_needs_a_typed_yes(tmp_path, monkeypatch):
    project_dir, state = _project(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(run, "clean_project", lambda: calls.append("clean"))
    # "8" then a stray Enter / wrong word: nothing may be deleted.
    assert _menu(monkeypatch, ["8", "", "8", "y", "q"]) == 0
    assert calls == []
    assert project_dir.exists() and state.exists()
    assert _menu(monkeypatch, ["8", "yes", "q"]) == 0
    assert calls == ["clean"]


def test_clean_refuses_while_the_project_is_locked(tmp_path, monkeypatch):
    project_dir, state = _project(tmp_path, monkeypatch)
    (project_dir / (run.GHIDRA_PROJECT_NAME + ".lock")).write_text(
        "", encoding="ascii")
    with pytest.raises(RuntimeError, match="locked"):
        run.clean_project()
    assert (project_dir / "work.gpr").exists() and state.exists()


def test_noninteractive_clean_still_works_without_a_prompt(tmp_path, monkeypatch):
    project_dir, state = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt="": pytest.fail("the clean subcommand must not prompt"))
    monkeypatch.setattr(run, "_enable_log_tee", lambda: None)
    monkeypatch.setattr(run.sys, "argv", ["run.py", "clean"])
    run.main()
    assert not project_dir.exists() and not state.exists()


@pytest.mark.parametrize("error", [
    subprocess.CalledProcessError(3, ["git", "submodule", "update"]),
    FileNotFoundError("git"),
    PermissionError("locked file"),
])
def test_menu_survives_a_failed_child_step(error, monkeypatch, capsys):
    def boom():
        raise error

    monkeypatch.setattr(run, "update_submodules", boom)
    calls = []
    monkeypatch.setattr(run, "_enrich_menu", lambda: calls.append("enrich"))
    # The failure is reported, the menu continues with the next choice, and
    # the session still ends non-zero.
    assert _menu(monkeypatch, ["2", "9", "q"]) == 1
    assert calls == ["enrich"]
    assert "ERROR" in capsys.readouterr().out
