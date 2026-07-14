import tarfile
import zipfile
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import run
import steamless

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_headless


def test_zip_traversal_is_rejected(tmp_path):
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "bad")
    with zipfile.ZipFile(archive_path) as archive:
        with pytest.raises(RuntimeError, match="unsafe zip"):
            run._safe_extract_zip(archive, tmp_path / "out")


def test_tar_symlink_is_rejected(tmp_path):
    archive_path = tmp_path / "bad.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside"
        archive.addfile(member)
    with tarfile.open(archive_path) as archive:
        with pytest.raises((RuntimeError, tarfile.FilterError)):
            run._safe_extract_tar(archive, tmp_path / "out")


def test_recursive_delete_is_confined_to_declared_root(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="ascii")
    with pytest.raises(RuntimeError, match="outside"):
        run._safe_rmtree(root, outside, "fixture")
    assert (outside / "keep.txt").is_file()


def test_launch_ghidra_reaches_process_start(tmp_path, monkeypatch):
    ghidra = tmp_path / "tools" / "ghidra"
    ghidra.mkdir(parents=True)
    (ghidra / "ghidraRun.bat").write_text("@echo off\n", encoding="ascii")
    project = tmp_path / "ghidraprojects" / run.GHIDRA_PROJECT_NAME
    project.mkdir(parents=True)
    gpr = project / (run.GHIDRA_PROJECT_NAME + ".gpr")
    gpr.write_text("", encoding="ascii")
    launched = []

    monkeypatch.setattr(run, "REPO_DIR", Path(tmp_path))
    monkeypatch.setattr(run, "GHIDRA_DIR", ghidra)
    monkeypatch.setattr(run, "PROJECTS_DIR", tmp_path / "ghidraprojects")
    monkeypatch.setattr(run, "_project_lock_files", lambda *_args: [])
    monkeypatch.setattr(run.sys, "platform", "win32")
    monkeypatch.setattr(run.subprocess, "Popen",
                        lambda *args, **kwargs: launched.append((args, kwargs)))

    assert run.launch_ghidra() is True
    assert launched and launched[0][0][0] == [str(ghidra / "ghidraRun.bat"),
                                              str(gpr)]


def test_importer_inference_never_guesses_unsupported_variants():
    assert run._infer_commonlib_script("SkyrimAE_GOG Edition.exe") is None
    assert run._infer_commonlib_script("SkyrimSE.exe") is None
    assert run._infer_commonlib_script("StarfieldVR.exe") is None
    assert run._infer_commonlib_script("Fallout4.exe") is None
    assert run._infer_commonlib_script("Fallout4_unknown.exe") is None


def test_commonlib_offer_reports_subprocess_failure(tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    scripts = tmp_path / "scripts"
    generated.mkdir()
    scripts.mkdir()
    (generated / "CommonLibImport_F4_221.py").write_text(
        "# fixture\n", encoding="ascii")
    (scripts / "apply_f4_to_user_project.py").write_text(
        "# fixture\n", encoding="ascii")

    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)
    monkeypatch.setattr(run, "SCRIPTS_DIR", scripts)
    monkeypatch.setattr(run, "_wait_for_unlock", lambda *_args: True)
    # Binding is its own step with its own tests; this one is about the applier.
    monkeypatch.setattr(run, "_ensure_importer_bound", lambda *_args: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=17))

    assert run._offer_commonlib_apply(
        "project-dir", "Combined",
        "/Fallout4/Fallout4_1_11_221.exe") is False


def test_locked_project_step_is_retried_not_reported_as_failed(monkeypatch, capsys):
    """The usual holder is the previous step's JVM, still exiting.

    No lock file is on disk by then, so the pre-flight file check waves the step
    through and the open loses the race.  Retrying is the entire fix, so a step
    that exits PROJECT_LOCKED_EXIT must offer one rather than report a failure.
    """
    codes = iter([run.PROJECT_LOCKED_EXIT, run.PROJECT_LOCKED_EXIT, 0])
    attempts = []

    def fake_run(cmd, **_kwargs):
        attempts.append(cmd)
        return SimpleNamespace(returncode=next(codes))

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    rc = run._run_project_step(["step"], "project-dir", "Combined", "the step")
    assert rc == 0
    assert len(attempts) == 3


def test_declining_the_retry_leaves_the_step_locked(monkeypatch):
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=run.PROJECT_LOCKED_EXIT))
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    assert run._run_project_step(
        ["step"], "project-dir", "Combined", "the step") == run.PROJECT_LOCKED_EXIT


def test_a_real_failure_is_not_mistaken_for_a_lock(monkeypatch):
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=4)

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    monkeypatch.setattr("builtins.input", _never_asked)

    assert run._run_project_step(
        ["step"], "project-dir", "Combined", "the step") == 4
    assert len(calls) == 1


def _never_asked(_prompt):
    raise AssertionError("a non-lock exit code must not prompt for a retry")


def test_unbound_importer_is_never_applied(tmp_path, monkeypatch):
    """An importer that names no build must not reach the applier at all."""
    generated = tmp_path / "generated"
    scripts = tmp_path / "scripts"
    generated.mkdir()
    scripts.mkdir()
    (generated / "CommonLibImport_F4_221.py").write_text(
        "# legacy, unbound\n", encoding="ascii")
    (scripts / "apply_f4_to_user_project.py").write_text(
        "# fixture\n", encoding="ascii")
    applied = []

    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)
    monkeypatch.setattr(run, "SCRIPTS_DIR", scripts)
    monkeypatch.setattr(run, "_wait_for_unlock", lambda *_args: True)
    # "Apply now?" -> yes; "Regenerate?" -> no.
    answers = iter(["y", "n"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *args, **kwargs: applied.append(args) or SimpleNamespace(returncode=0))

    assert run._offer_commonlib_apply(
        "project-dir", "Combined",
        "/Fallout4/Fallout4_1_11_221.exe") is False
    assert not applied, "an unbound importer must never be handed to the applier"


def test_true_vr_importer_is_preferred_when_generated(tmp_path, monkeypatch):
    """The powerof3 VR importer emits no vtables; prefer the CommonLibVR one."""
    generated = tmp_path / "generated"
    generated.mkdir()
    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)

    # Not generated yet -> the inferred (powerof3) importer stands.
    assert run._preferred_importer("CommonLibImport_VR.py") == "CommonLibImport_VR.py"

    (generated / "CommonLibImport_CLVR_VR.py").write_text("# fixture\n", encoding="ascii")
    assert run._preferred_importer("CommonLibImport_VR.py") == "CommonLibImport_CLVR_VR.py"

    # Other runtimes are untouched, and an unknown program stays unknown.
    assert run._preferred_importer("CommonLibImport_SE.py") == "CommonLibImport_SE.py"
    assert run._preferred_importer(None) is None


def test_true_vr_importer_resolves_to_the_skyrim_vr_build():
    """The alias must still name exes/skyrim/vr, or its errors point nowhere."""
    from version_catalog import entry_for_importer, target_for_importer

    assert entry_for_importer("CommonLibImport_CLVR_VR.py")[0] == "svr"
    assert target_for_importer("CommonLibImport_CLVR_VR.py") == (
        "Skyrim VR 1.4.15", "skyrim/vr")


def test_true_f4vr_importer_is_preferred_and_resolves_to_the_f4vr_build(
        tmp_path, monkeypatch):
    """Fallout 4 VR gets the same upgrade: CommonLibF4 emits no VR vtables."""
    from version_catalog import entry_for_importer, generation_target, target_for_importer

    generated = tmp_path / "generated"
    generated.mkdir()
    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)

    assert run._preferred_importer("CommonLibImport_F4_VR.py") == "CommonLibImport_F4_VR.py"
    (generated / "CommonLibImport_CLF4VR_VR.py").write_text("# fixture\n", encoding="ascii")
    assert run._preferred_importer("CommonLibImport_F4_VR.py") == "CommonLibImport_CLF4VR_VR.py"

    assert entry_for_importer("CommonLibImport_CLF4VR_VR.py")[0] == "f4vr"
    assert target_for_importer("CommonLibImport_CLF4VR_VR.py") == (
        "Fallout 4 VR 1.2.72", "f4/vr")
    assert generation_target("CommonLibImport_CLF4VR_VR.py") == ("f4", "vr")


def test_ensure_importer_bound_recovers_exe_when_none_is_staged(
        tmp_path, monkeypatch):
    """The exe is usually gone, so offer recovery instead of a dead end."""
    importer = tmp_path / "CommonLibImport_VR.py"
    importer.write_text("# legacy, unbound\n", encoding="ascii")
    calls = []

    monkeypatch.setattr(run, "_version_status", lambda _entry: (False, True, None))
    monkeypatch.setattr(run, "_recover_target_pe",
                        lambda *args: calls.append("recover") or "recovered.exe")

    def _fake_generate(games=None, only_version=None):
        calls.append(("generate", tuple(sorted(games)), only_version))
        importer.write_text("TARGET_MANIFESTS = []\n", encoding="ascii")

    monkeypatch.setattr(run, "generate_scripts", _fake_generate)
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    # TARGET_MANIFESTS = [] is still not a valid binding, so this must fail --
    # and it must have tried recovery and a VR-only regeneration to get there.
    assert run._ensure_importer_bound(
        "CommonLibImport_VR.py", importer,
        "project-dir", "Combined", "/Skyrim/SkyrimVR_1_4_15.exe") is False
    assert calls == ["recover", ("generate", ("skyrim",), "vr")]


def test_ensure_importer_bound_passes_through_a_bound_importer(tmp_path, monkeypatch):
    importer = tmp_path / "CommonLibImport_VR.py"
    importer.write_text("# unused\n", encoding="ascii")
    monkeypatch.setattr(run, "extract_target_manifests", lambda _path: [{"sha256": "a" * 64}])
    monkeypatch.setattr("builtins.input", _no_input)

    assert run._ensure_importer_bound(
        "CommonLibImport_VR.py", importer,
        "project-dir", "Combined", "/Skyrim/SkyrimVR_1_4_15.exe") is True


def _no_input(_prompt):
    raise AssertionError("a bound importer must not prompt the user")


def test_option9_stops_before_rtti_when_commonlib_apply_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(
        run, "_offer_commonlib_apply",
        lambda *_args, **_kwargs: calls.append("commonlib") or False)
    monkeypatch.setattr(
        run, "_wait_for_unlock",
        lambda *_args: calls.append("unlock") or True)
    monkeypatch.setattr(
        run, "_run_vtable_reconciler",
        lambda *_args, **_kwargs: calls.append("reconciler"))
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *_args, **_kwargs: calls.append("rtti"))

    assert run._run_enrichment_sequence(
        "Combined", "project-dir", "Combined", "/game.exe") is False
    assert calls == ["commonlib"]


def test_option9_stops_before_reconciler_when_rtti_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(
        run, "_offer_commonlib_apply", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(run, "_wait_for_unlock", lambda *_args: True)
    monkeypatch.setattr(run, "_local_target_pe_candidates", lambda _path: [])
    monkeypatch.setattr(run, "_header", lambda _message: None)
    monkeypatch.setattr(
        run, "_run_vtable_reconciler",
        lambda *_args, **_kwargs: calls.append("reconciler"))
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=9))

    assert run._run_enrichment_sequence(
        "Combined", "project-dir", "Combined", "/game.exe") is False
    assert calls == []


def test_option9_passes_all_local_identity_candidates_to_rtti(
        tmp_path, monkeypatch):
    calls = []
    first = tmp_path / "Fallout4.exe"
    unpacked = tmp_path / "Fallout4.exe.unpacked.exe"
    first.write_bytes(b"one")
    unpacked.write_bytes(b"two")
    monkeypatch.setattr(
        run, "_offer_commonlib_apply", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(run, "_wait_for_unlock", lambda *_args: True)
    monkeypatch.setattr(
        run, "_local_target_pe_candidates", lambda _path: [first, unpacked])
    monkeypatch.setattr(run, "_header", lambda _message: None)
    monkeypatch.setattr(
        run, "_run_vtable_reconciler",
        lambda *_args, **_kwargs: calls.append(("reconciler",)) or True)

    def fake_run(args, **_kwargs):
        calls.append(tuple(args))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    assert run._run_enrichment_sequence(
        "Combined", "project-dir", "Combined", "/game.exe") is True
    assert calls[0][-4:] == (
        "--target-pe", str(first), "--target-pe", str(unpacked))
    assert calls[1] == ("reconciler",)


def _write_reconciler_importer(path, *, with_vtables=True, with_manifest=True):
    vtables = ("[('VTABLE_Foo', 'Foo', 8, '/Test', "
               "[(0, 'method')])]" if with_vtables else "[]")
    manifest = ("\nTARGET_MANIFESTS = _json_target.loads("
                "'[{\"sha256\": \"" + "a" * 64 + "\"}]')\n"
                if with_manifest else "\n")
    path.write_text("VTABLES = " + vtables + manifest, encoding="utf-8")


def test_reconciler_uses_inferred_importer_without_prompts_or_dry_run(
        tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    scripts = tmp_path / "scripts" / "core"
    generated.mkdir()
    scripts.mkdir(parents=True)
    chosen = generated / "CommonLibImport_F4_221.py"
    _write_reconciler_importer(chosen)
    _write_reconciler_importer(generated / "CommonLibImport_SE.py")
    (scripts / "vtable_name_reconciler.py").write_text(
        "# fixture\n", encoding="ascii")
    calls = []

    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)
    monkeypatch.setattr(run, "SCRIPTS_DIR", tmp_path / "scripts")
    monkeypatch.setattr(run, "_wait_for_unlock", lambda *_args: True)
    monkeypatch.setattr(run, "_header", lambda *_args: None)
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: pytest.fail("guided reconciliation must not prompt"))
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda args, **_kwargs: calls.append(args) or
        SimpleNamespace(returncode=0))

    program = "/Fallout4/Fallout4_1_11_221.exe"
    assert run._run_vtable_reconciler(
        "project-dir", "Combined", program) is True
    assert len(calls) == 1
    command = calls[0]
    assert command[command.index("--import-script") + 1] == str(chosen)
    assert command[command.index("--program") + 1] == program
    assert "--dry-run" not in command


def test_reconciler_skips_empty_or_unresolved_importer_without_pyghidra(
        tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    generated.mkdir()
    _write_reconciler_importer(
        generated / "CommonLibImport_F4_221.py", with_vtables=False)
    monkeypatch.setattr(run, "GHIDRA_SCRIPTS_DIR", generated)
    monkeypatch.setattr(
        run.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("reconciler must not launch"))

    assert run._run_vtable_reconciler(
        "project-dir", "Combined",
        "/Fallout4/Fallout4_1_11_221.exe") is True
    assert run._run_vtable_reconciler(
        "project-dir", "Combined", "/Unknown/game.exe") is True


def test_cmd_all_does_not_launch_failed_build(monkeypatch):
    launched = []
    monkeypatch.setattr(run, "_cmd_setup", lambda: None)
    monkeypatch.setattr(run, "_discover_games", lambda: {"skyrim"})
    monkeypatch.setattr(run, "generate_scripts", lambda _games: None)
    monkeypatch.setattr(run, "run_headless", lambda: 7)
    monkeypatch.setattr(run, "_finalize_build", lambda rc, _games: rc)
    monkeypatch.setattr(run, "launch_ghidra", lambda: launched.append(True))
    with pytest.raises(SystemExit) as exc:
        run._cmd_all()
    assert exc.value.code == 7
    assert launched == []


def test_headless_enrichment_stage_is_idempotent_and_rejects_stale_state():
    sha = "a" * 64
    assert run_headless._enrichment_stage_action("", sha, True) == "apply"
    assert run_headless._enrichment_stage_action(
        run_headless.PIPELINE_STAGE_GENERIC, sha, False) == "apply"
    assert run_headless._enrichment_stage_action(
        run_headless.PIPELINE_STAGE_ENRICHED + sha, sha, False) == "skip"
    with pytest.raises(RuntimeError, match="different or legacy"):
        # A legacy stamp: the marker on disk says "enriched" whatever we now
        # call the step, so the stage check must still recognise it.
        run_headless._enrichment_stage_action("enriched:" + sha, sha, False)
    with pytest.raises(RuntimeError, match="different or legacy"):
        run_headless._enrichment_stage_action(
            run_headless.PIPELINE_STAGE_ENRICHED + "b" * 64, sha, False)
    with pytest.raises(RuntimeError, match="no pipeline-stage provenance"):
        run_headless._enrichment_stage_action("", sha, False)


def test_clean_cli_dispatches_to_scoped_project_cleanup(monkeypatch):
    calls = []
    monkeypatch.setattr(run, "_enable_log_tee", lambda: None)
    monkeypatch.setattr(run, "clean_project", lambda: calls.append("clean"))
    monkeypatch.setattr(run.sys, "argv", ["run.py", "clean"])
    run.main()
    assert calls == ["clean"]


def test_interactive_cli_bootstraps_selected_python_before_menu(monkeypatch):
    calls = []
    monkeypatch.setattr(run, "_require_supported_python", lambda: None)
    monkeypatch.setattr(run, "_configure_utf8_console", lambda: None)
    monkeypatch.setattr(run, "_enable_log_tee", lambda: None)
    monkeypatch.setattr(
        run, "_ensure_python_packages", lambda: calls.append("runtime"))
    monkeypatch.setattr(run, "_run_menu", lambda: calls.append("menu"))
    monkeypatch.setattr(run.sys, "argv", ["run.py"])

    run.main()
    assert calls == ["runtime", "menu"]


def test_interactive_cli_never_opens_menu_after_runtime_failure(monkeypatch):
    monkeypatch.setattr(run, "_require_supported_python", lambda: None)
    monkeypatch.setattr(run, "_configure_utf8_console", lambda: None)
    monkeypatch.setattr(run, "_enable_log_tee", lambda: None)
    monkeypatch.setattr(
        run, "_ensure_python_packages",
        lambda: (_ for _ in ()).throw(RuntimeError("bootstrap failed")))
    monkeypatch.setattr(
        run, "_run_menu", lambda: pytest.fail("menu must remain gated"))
    monkeypatch.setattr(run.sys, "argv", ["run.py"])

    with pytest.raises(SystemExit) as exc:
        run.main()
    assert exc.value.code == 1


def test_python_bootstrap_installs_exact_binary_wheels_and_rechecks(
        monkeypatch):
    installed = False
    commands = []

    monkeypatch.setattr(run, "REQUIRED_PACKAGES", {"pyghidra": "pyghidra==3.0.2"})
    monkeypatch.setattr(run, "_header", lambda *_args: None)
    monkeypatch.setattr(
        run, "_requirement_satisfied",
        lambda *_args: installed)

    def fake_check_call(command):
        nonlocal installed
        commands.append(command)
        installed = True

    monkeypatch.setattr(run.subprocess, "check_call", fake_check_call)
    run._ensure_python_packages()

    assert len(commands) == 1
    assert commands[0][:4] == [
        run.sys.executable, "-m", "pip", "install"]
    assert "--no-deps" in commands[0]
    assert "--only-binary=:all:" in commands[0]
    assert commands[0][-1] == "pyghidra==3.0.2"


def test_python_bootstrap_is_noop_for_prepared_interpreter(monkeypatch):
    monkeypatch.setattr(run, "REQUIRED_PACKAGES", {"ready": "ready==1"})
    monkeypatch.setattr(
        run, "_requirement_satisfied", lambda *_args: True)
    monkeypatch.setattr(
        run.subprocess, "check_call",
        lambda *_args, **_kwargs: pytest.fail("pip must not run"))
    run._ensure_python_packages()


def test_python_bootstrap_rejects_unresolved_install(monkeypatch):
    monkeypatch.setattr(run, "REQUIRED_PACKAGES", {"missing": "missing==1"})
    monkeypatch.setattr(
        run, "_requirement_satisfied", lambda *_args: False)
    monkeypatch.setattr(run, "_header", lambda *_args: None)
    monkeypatch.setattr(
        run.subprocess, "check_call", lambda *_args, **_kwargs: None)

    with pytest.raises(RuntimeError, match="did not produce the locked runtime"):
        run._ensure_python_packages()


def test_toolchain_lock_matches_launcher_and_requirements():
    lock = json.loads(run.TOOLCHAIN_LOCK_FILE.read_text(encoding="utf-8"))
    assert lock["python"]["implementation"] == "CPython"
    assert lock["python"]["minimum"] == ".".join(
        map(str, run.SUPPORTED_PYTHON_MIN))
    assert lock["python"]["maximum"] == ".".join(
        map(str, run.SUPPORTED_PYTHON_MAX))
    assert lock["python"]["architecture"] == "64-bit"
    assert (lock["python"]["python_3_14_jpype_bridge"] ==
            run._jpype_requirement((3, 14)).split("==", 1)[1])
    assert lock["ghidra"]["version"] == run.PINNED_GHIDRA_VERSION
    assert lock["llvm"]["version"] == run.PINNED_LLVM_VERSION
    assert (run.LOCKED_ASSET_DIGESTS[
        lock["llvm"]["windows_x86_64_asset"]] ==
        "sha256:" + lock["llvm"]["windows_x86_64_sha256"])
    assert (run.LOCKED_ASSET_DIGESTS[
        lock["llvm"]["windows_aarch64_asset"]] ==
        "sha256:" + lock["llvm"]["windows_aarch64_sha256"])
    assert lock["steamless"]["version"] == run.PINNED_STEAMLESS_VERSION
    assert (lock["steamless"]["cli_sha256"] ==
            run.PINNED_STEAMLESS_CLI_SHA256)
    assert lock["steamless"]["cli_sha256"] == steamless._PINNED_CLI_SHA256
    assert (run.LOCKED_ASSET_DIGESTS[lock["ghidra"]["asset"]] ==
            "sha256:" + lock["ghidra"]["sha256"])
    assert (run.LOCKED_ASSET_DIGESTS[lock["steamless"]["asset"]] ==
            "sha256:" + lock["steamless"]["sha256"])
    assert lock["fakepdb"]["version"] == run.PINNED_FAKEPDB_VERSION
    assert (lock["fakepdb"]["executable_sha256"] ==
            run.PINNED_FAKEPDB_EXE_SHA256)
    assert (run.LOCKED_ASSET_DIGESTS[lock["fakepdb"]["asset"]] ==
            "sha256:" + lock["fakepdb"]["sha256"])
    requirements = {
        line.strip() for line in (run.REPO_DIR / lock["python_requirements"])
        .read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert requirements == set(run.PYTHON_LOCK_REQUIREMENTS)


def test_python_runtime_matrix_and_jpype_bridge_are_explicit():
    assert run._python_compatibility_error((3, 11), 2 ** 63) is None
    assert run._python_compatibility_error((3, 14), 2 ** 63) is None
    assert "3.11 through 3.14" in run._python_compatibility_error(
        (3, 10), 2 ** 63)
    assert "not yet supported" in run._python_compatibility_error(
        (3, 15), 2 ** 63)
    assert "64-bit" in run._python_compatibility_error((3, 13), 2 ** 31)
    assert run._jpype_requirement((3, 11)) == "JPype1==1.5.2"
    assert run._jpype_requirement((3, 13)) == "JPype1==1.5.2"
    assert run._jpype_requirement((3, 14)) == "JPype1==1.7.1"


def test_core_runtime_has_no_legacy_pdbparse_dependency():
    assert not any("pdbparse" in requirement.lower()
                   for requirement in run.PYTHON_LOCK_REQUIREMENTS)
    assert not hasattr(run, "OPTIONAL_PACKAGES")
