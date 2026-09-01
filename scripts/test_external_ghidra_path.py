from pathlib import Path

import run


def test_external_ghidra_path_overrides_release_local_cache(tmp_path):
    external = tmp_path / "external-ghidra"
    resolved = run._resolve_ghidra_dir(
        tmp_path / "release", {"GHIDRA_INSTALL_DIR": str(external)})
    assert resolved == external.resolve()


def test_local_ghidra_cache_is_default(tmp_path):
    assert run._resolve_ghidra_dir(tmp_path, {}) == (
        tmp_path / "tools" / "ghidra")


def test_project_listing_fails_early_with_install_guidance(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run, "GHIDRA_DIR", tmp_path / "missing-ghidra")
    monkeypatch.setattr(run, "_project_lock_files", lambda *_: [])
    assert run._list_programs_in_project(tmp_path, "ExampleProject") is None
    output = capsys.readouterr().out
    assert "menu option 1" in output
    assert "GHIDRA_INSTALL_DIR" in output


def test_all_declared_ghidra_dirs_honor_environment_override():
    repo = Path(__file__).resolve().parents[1]
    files = [repo / "run.py"] + sorted((repo / "scripts").rglob("*.py"))
    declarations = 0
    for path in files:
        if path.name.startswith("test"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("GHIDRA_DIR") and "=" in line:
                declarations += 1
                if path == repo / "run.py":
                    assert "_resolve_ghidra_dir" in line
                else:
                    assert "GHIDRA_INSTALL_DIR" in line, str(path)
    assert declarations > 0
