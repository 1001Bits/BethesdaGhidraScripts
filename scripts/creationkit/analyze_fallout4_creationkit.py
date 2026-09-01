#!/usr/bin/env python3
"""Identity-pinned staged analysis for Fallout 4 Creation Kit 1.11.137.0.

The stages are deliberately separate so the ExampleProject project is saved and the
JVM is released between expensive passes.  No stage will operate on a Program
whose import-time identity and live layout do not match the exact Steam PE.

Typical order::

    python analyze_fallout4_creationkit.py import
    python analyze_fallout4_creationkit.py analyze --label baseline
    python analyze_fallout4_creationkit.py unwind
    python analyze_fallout4_creationkit.py analyze --label post-unwind
    # Run Ghidra's RecoverClassesFromRTTIScript.java in a fresh headless JVM.
    python analyze_fallout4_creationkit.py policy
    python analyze_fallout4_creationkit.py metrics
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent.parent
CORE_DIR = REPO_DIR / "scripts" / "core"
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

DEFAULT_PROJECT_DIR = Path(r"C:\GhidraProjects")
DEFAULT_PROJECT_NAME = "ExampleProject"
DEFAULT_SOURCE = Path(
    r"C:\games\steam\steamapps\common\Fallout 4\CreationKit.exe")
FOLDER_PATH = "/Creation Kit"
PROGRAM_NAME = "CreationKit Fallout 4 1.11.137.0.exe"
PROGRAM_PATH = FOLDER_PATH + "/" + PROGRAM_NAME

EXPECTED_SHA256 = (
    "222fd0aad949e76721d85c922ae508ada6816ba2f3e1fc11647c7239c24c2e13")
EXPECTED_FILE_SIZE = 69_017_440
EXPECTED_MACHINE = 0x8664
EXPECTED_POINTER_SIZE = 8
EXPECTED_IMAGE_BASE = 0x140000000
EXPECTED_IMAGE_SIZE = 0x84BA000
EXPECTED_TIMESTAMP = 0x68FEB70A
EXPECTED_FILE_VERSION = [1, 11, 137, 0]

STAGE_OPTION = "BGS Creation Kit Stage"
MANIFEST_OPTION = "BGS Target Manifest"
DPID_OPTION = "Decompiler Parameter ID"
AGGRESSIVE_OPTION = "Aggressive Instruction Finder"

if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from binary_identity import (  # noqa: E402
    canonical_identity,
    inspect_pe,
    manifest_matches,
    verify_ghidra_program,
)
from pyghidra_result import end_outer_transaction  # noqa: E402


def _expected_identity() -> dict:
    return {
        "sha256": EXPECTED_SHA256,
        "file_size": EXPECTED_FILE_SIZE,
        "machine": EXPECTED_MACHINE,
        "pointer_size": EXPECTED_POINTER_SIZE,
        "image_base": EXPECTED_IMAGE_BASE,
        "image_size": EXPECTED_IMAGE_SIZE,
        "timestamp": EXPECTED_TIMESTAMP,
        "file_version": EXPECTED_FILE_VERSION,
    }


def _inspect_source(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError("Fallout 4 Creation Kit PE not found: {}".format(path))
    actual = inspect_pe(str(path))
    matches, reasons = manifest_matches(_expected_identity(), actual)
    if not matches:
        raise RuntimeError(
            "refusing non-pinned Fallout 4 Creation Kit:\n  " +
            "\n  ".join(reasons))
    return actual


def _find_file(root, exact_path: str):
    wanted = "/" + exact_path.strip("/")
    found = []

    def walk(folder, prefix=""):
        for domain_file in folder.getFiles():
            path = prefix + "/" + str(domain_file.getName())
            if path == wanted:
                found.append(domain_file)
        for child in folder.getFolders():
            walk(child, prefix + "/" + str(child.getName()))

    walk(root)
    if len(found) > 1:
        raise RuntimeError("ambiguous project path {}".format(wanted))
    return found[0] if found else None


def _folder(root):
    folder = root.getFolder("Creation Kit")
    if folder is None:
        folder = root.createFolder("Creation Kit")
    return folder


def _resolve_ckpe_root(explicit: Path | None) -> Path:
    """Resolve the pinned CKPE checkout using the documented search order."""
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    configured = os.environ.get("BGS_CKPE_ROOT")
    if configured:
        candidates.append(Path(configured))
    candidates.extend((
        REPO_DIR / "third_party" / "Creation-Kit-Platform-Extended",
        REPO_DIR.parent / "Creation-Kit-Platform-Extended",
        Path(r"C:\tmp\ckpe-f4-audit-cfd8533d"),
    ))
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise RuntimeError(
        "pinned CKPE checkout not found; pass --ckpe-root, set "
        "BGS_CKPE_ROOT, or prepare a documented checkout (checked: {})".format(
            rendered))


def _analysis_idle(program) -> None:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    manager = AutoAnalysisManager.getAnalysisManager(program)
    try:
        if manager.isAnalyzing():
            raise RuntimeError("Ghidra auto-analysis is already active")
    except AttributeError:
        pass


def _set_policy(program) -> tuple[bool, bool]:
    """Disable the two analyzers that are unsafe/noisy for this workflow."""
    from ghidra.program.model.listing import Program

    options = program.getOptions(Program.ANALYSIS_PROPERTIES)
    options.setBoolean(DPID_OPTION, False)
    options.setBoolean(AGGRESSIVE_OPTION, False)
    return (
        bool(options.getBoolean(DPID_OPTION, True)),
        bool(options.getBoolean(AGGRESSIVE_OPTION, True)),
    )


def _bind(program, manifest: dict, stage: str | None = None) -> None:
    from ghidra.program.model.listing import Program

    verified = verify_ghidra_program(program, [manifest])
    if str(program.getDomainFile().getPathname()) != PROGRAM_PATH:
        raise RuntimeError(
            "target is at {}, expected {}".format(
                program.getDomainFile().getPathname(), PROGRAM_PATH))
    options = program.getOptions(Program.PROGRAM_INFO)
    existing = options.getString(MANIFEST_OPTION, "") or ""
    if existing:
        try:
            recorded = json.loads(existing)
        except Exception as error:
            raise RuntimeError("invalid stored target manifest") from error
        matches, reasons = manifest_matches(recorded, verified)
        if not matches:
            raise RuntimeError("stored target manifest mismatch: " + "; ".join(reasons))
    options.setString(MANIFEST_OPTION, json.dumps(canonical_identity(verified), sort_keys=True))
    if stage:
        options.setString(STAGE_OPTION, stage)


def _open_target(project, manifest: dict, consumer, monitor, *, update: bool):
    domain_file = _find_file(project.getProjectData().getRootFolder(), PROGRAM_PATH)
    if domain_file is None:
        raise RuntimeError("{} is not present in the project".format(PROGRAM_PATH))
    program = domain_file.getDomainObject(consumer, update, False, monitor)
    verify_ghidra_program(program, [manifest])
    return program


def _import_target(project, source: Path, manifest: dict, monitor) -> None:
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.app.util.opinion import PeLoader
    import java.io
    import java.lang

    root = project.getProjectData().getRootFolder()
    existing = _find_file(root, PROGRAM_PATH)
    if existing is not None:
        consumer = java.lang.Object()
        program = existing.getDomainObject(consumer, True, False, monitor)
        try:
            verify_ghidra_program(program, [manifest])
            from ghidra.program.model.listing import Program
            current_stage = (program.getOptions(Program.PROGRAM_INFO)
                             .getString(STAGE_OPTION, "") or "")
            tx = program.startTransaction(
                "Repair/verify Fallout 4 Creation Kit import binding")
            commit = False
            try:
                # Preserve later checkpoints on an idempotent import rerun, but
                # repair the narrow crash window after LoadResults.save() and
                # before the first identity/policy transaction was committed.
                _bind(program, manifest, current_stage or "imported")
                dpid, aggressive = _set_policy(program)
                if dpid or aggressive:
                    raise RuntimeError("failed to disable analysis policy")
                commit = True
            finally:
                end_outer_transaction(
                    program, tx, commit,
                    "Fallout 4 Creation Kit import binding repair")
            program.save("verify exact Fallout 4 Creation Kit import", monitor)
            print("Exact target verified at {} (stage={})".format(
                PROGRAM_PATH, current_stage or "imported"))
            return
        finally:
            program.release(consumer)

    folder = _folder(root)
    raw = folder.getFile(source.name)
    if raw is not None:
        raise RuntimeError(
            "{} already exists; refusing to guess whether a partial import is safe".format(
                FOLDER_PATH + "/" + source.name))

    print("Importing exact PE: {}".format(source))
    log = MessageLog()
    # AutoImporter may enable dependency discovery based on saved/import UI
    # state.  CreationKit imports several adjacent and system DLLs; pulling
    # those into ExampleProject is both out of scope and extremely expensive because
    # each PE has its own exception table.  Bind the PE loader explicitly and
    # fail closed with both library-loading paths disabled.
    results = (ProgramLoader.builder()
               .source(java.io.File(str(source)))
               .project(project)
               .projectFolderPath(FOLDER_PATH)
               .name(PROGRAM_NAME)
               .loaders(PeLoader.class_)
               .addLoaderArg("-loader-loadLibraries", "false")
               .addLoaderArg("-loader-linkExistingProjectLibraries", "false")
               .addLoaderArg("-loader-libraryLoadDepth", "0")
               .log(log)
               .monitor(monitor)
               .load())
    if not results or results.size() != 1:
        if results:
            results.close()
        raise RuntimeError("expected exactly one imported Program")
    try:
        results.save(monitor)
    finally:
        results.close()

    renamed = folder.getFile(PROGRAM_NAME)
    if renamed is None:
        raise RuntimeError("import completed but {} was not created".format(PROGRAM_NAME))

    consumer = java.lang.Object()
    program = renamed.getDomainObject(consumer, True, False, monitor)
    try:
        tx = program.startTransaction("Bind Fallout 4 Creation Kit identity")
        commit = False
        try:
            _bind(program, manifest, "imported")
            dpid, aggressive = _set_policy(program)
            if dpid or aggressive:
                raise RuntimeError("failed to disable analysis policy")
            commit = True
        finally:
            end_outer_transaction(
                program, tx, commit,
                "Fallout 4 Creation Kit import identity binding")
        program.save("exact identity-bound Fallout 4 Creation Kit import", monitor)
    finally:
        program.release(consumer)
    print("Imported and checkpointed at {}".format(PROGRAM_PATH))


def _run_analysis(project, manifest: dict, monitor, label: str) -> None:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.model.listing import Program
    import java.lang

    consumer = java.lang.Object()
    program = _open_target(project, manifest, consumer, monitor, update=True)
    try:
        _analysis_idle(program)
        manager = AutoAnalysisManager.getAnalysisManager(program)
        tx = program.startTransaction("Fallout 4 Creation Kit full analysis: " + label)
        commit = False
        try:
            manager.initializeOptions()
            dpid, aggressive = _set_policy(program)
            if dpid or aggressive:
                raise RuntimeError("failed to enforce analysis policy")
            manager.reAnalyzeAll(None)
            print("Full analysis scheduled ({})".format(label))
            manager.startAnalysis(monitor)
            if monitor.isCancelled():
                raise RuntimeError(
                    "analysis was cancelled before the queue drained")
            program.getOptions(Program.PROGRAM_INFO).setBoolean("Analyzed", True)
            _bind(program, manifest, "analyzed:" + label)
            dpid, aggressive = _set_policy(program)
            if dpid or aggressive:
                raise RuntimeError("analysis changed required policy")
            commit = True
        finally:
            end_outer_transaction(
                program, tx, commit,
                "Fallout 4 Creation Kit full analysis: " + label)
        program.save("Fallout 4 Creation Kit analysis checkpoint: " + label, monitor)
        print("Analysis checkpoint saved ({})".format(label))
    finally:
        program.release(consumer)


def _run_unwind(project, manifest: dict, monitor) -> None:
    import java.lang
    import pyghidra

    consumer = java.lang.Object()
    program = _open_target(project, manifest, consumer, monitor, update=True)
    old_apply = os.environ.get("BGS_ENRICH_APPLY")
    try:
        _analysis_idle(program)
        os.environ["BGS_ENRICH_APPLY"] = "go"
        stdout, stderr = pyghidra.ghidra_script(
            CORE_DIR / "pe_unwind_enrich.py", project, program,
            echo_stdout=False, echo_stderr=False)
        if stdout:
            print(stdout.rstrip())
        if stderr and stderr.strip():
            raise RuntimeError("PE unwind script failed:\n" + stderr.strip())
        tx = program.startTransaction("Record PE unwind stage")
        commit = False
        try:
            _bind(program, manifest, "pe-unwind")
            _set_policy(program)
            commit = True
        finally:
            end_outer_transaction(
                program, tx, commit,
                "Fallout 4 Creation Kit PE unwind binding")
        program.save("Fallout 4 Creation Kit PE unwind checkpoint", monitor)
        print("PE unwind checkpoint saved")
    finally:
        if old_apply is None:
            os.environ.pop("BGS_ENRICH_APPLY", None)
        else:
            os.environ["BGS_ENRICH_APPLY"] = old_apply
        program.release(consumer)


def _run_ckpe(project, manifest: dict, monitor, *, apply: bool,
              ckpe_root: Path) -> None:
    """Run the exact FO4 CKPE Python-3 driver and save only on apply."""
    import java.lang
    import pyghidra
    from pyghidra_result import require_script_success

    if not ckpe_root.is_dir():
        raise RuntimeError("pinned CKPE checkout not found: {}".format(ckpe_root))
    consumer = java.lang.Object()
    program = _open_target(
        project, manifest, consumer, monitor, update=bool(apply))
    old_root = os.environ.get("BGS_CKPE_ROOT")
    old_apply = os.environ.get("BGS_CKPE_APPLY")
    try:
        _analysis_idle(program)
        os.environ["BGS_CKPE_ROOT"] = str(ckpe_root.resolve())
        os.environ["BGS_CKPE_APPLY"] = "go" if apply else "dry"
        stdout, stderr = pyghidra.ghidra_script(
            SCRIPT_DIR / "apply_fallout4_ckpe_evidence.py",
            project, program, echo_stdout=False, echo_stderr=False)
        if stdout:
            print(stdout.rstrip())
        require_script_success(stderr, "Fallout 4 CKPE evidence")
        if apply:
            program.save("exact Fallout 4 CKPE annotations", monitor)
            print("CKPE annotation checkpoint saved")
    finally:
        if old_root is None:
            os.environ.pop("BGS_CKPE_ROOT", None)
        else:
            os.environ["BGS_CKPE_ROOT"] = old_root
        if old_apply is None:
            os.environ.pop("BGS_CKPE_APPLY", None)
        else:
            os.environ["BGS_CKPE_APPLY"] = old_apply
        program.release(consumer)


def _restore_policy(project, manifest: dict, monitor) -> None:
    import java.lang

    consumer = java.lang.Object()
    program = _open_target(project, manifest, consumer, monitor, update=True)
    try:
        tx = program.startTransaction("Restore Fallout 4 Creation Kit analysis policy")
        commit = False
        try:
            # This command restores policy only.  Class-recovery completion is
            # established by recovered-type/vtable metrics in the finalizer,
            # not inferred merely because this helper was invoked.
            _bind(program, manifest, "policy-restored")
            dpid, aggressive = _set_policy(program)
            if dpid or aggressive:
                raise RuntimeError("failed to restore analysis policy")
            commit = True
        finally:
            end_outer_transaction(
                program, tx, commit,
                "Fallout 4 Creation Kit policy restoration")
        program.save("restore Fallout 4 Creation Kit analysis policy", monitor)
        print("Decompiler Parameter ID and Aggressive Instruction Finder are disabled")
    finally:
        program.release(consumer)


def _qualified_function_name(function) -> str:
    try:
        return str(function.getSymbol().getName(True))
    except Exception:
        return str(function.getName())


def _metrics(project, manifest: dict, monitor) -> dict:
    from ghidra.program.model.data import Structure
    from ghidra.program.model.listing import Program
    import java.lang

    consumer = java.lang.Object()
    program = _open_target(project, manifest, consumer, monitor, update=False)
    try:
        functions = list(program.getFunctionManager().getFunctions(True))
        default_re = re.compile(r"^(?:FUN_|sub_|thunk_FUN_|thunk_sub_)[0-9A-Fa-f]+$")
        named = sum(
            1 for function in functions
            if not default_re.match(_qualified_function_name(function)))
        class_types = class_structures = 0
        for data_type in program.getDataTypeManager().getAllDataTypes():
            category = str(data_type.getCategoryPath().getPath())
            if category == "/ClassDataTypes" or category.startswith("/ClassDataTypes/"):
                class_types += 1
                if isinstance(data_type, Structure):
                    class_structures += 1
        vtables = 0
        for symbol in program.getSymbolTable().getAllSymbols(True):
            name = str(symbol.getName())
            if name == "vftable" or name.startswith("vftable_") or name.startswith("VTABLE_"):
                vtables += 1
        analysis = program.getOptions(Program.ANALYSIS_PROPERTIES)
        info = program.getOptions(Program.PROGRAM_INFO)
        result = {
            "program_path": str(program.getDomainFile().getPathname()),
            "sha256": str(program.getExecutableSHA256()).lower(),
            "stage": info.getString(STAGE_OPTION, "") or "",
            "functions": len(functions),
            "named_functions": named,
            "symbols": int(program.getSymbolTable().getNumSymbols()),
            "class_datatypes": class_types,
            "class_structures": class_structures,
            "vtable_symbols": vtables,
            "decompiler_parameter_id": bool(
                analysis.getBoolean(DPID_OPTION, False)),
            "aggressive_instruction_finder": bool(
                analysis.getBoolean(AGGRESSIVE_OPTION, False)),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return result
    finally:
        program.release(consumer)


def _start_ghidra(temp_dir: Path, max_cpu: int) -> None:
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    temp_dir.mkdir(parents=True, exist_ok=True)
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA_DIR)
    launcher.add_vmargs(
        "-Djava.io.tmpdir={}".format(temp_dir.resolve()),
        "-XX:ActiveProcessorCount={}".format(max_cpu),
    )
    launcher.start()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "stage", choices=(
            "import", "analyze", "unwind", "ckpe-dry", "ckpe-apply",
            "policy", "metrics"))
    parser.add_argument("--project-dir", type=Path, default=DEFAULT_PROJECT_DIR)
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--label", default="full")
    parser.add_argument("--max-cpu", type=int, default=4)
    parser.add_argument(
        "--temp-dir", type=Path,
        default=Path(r"D:\GhidraTemp\Fallout4CreationKit"))
    parser.add_argument(
        "--ckpe-root", type=Path,
        default=None,
        help=("pinned CKPE checkout; otherwise use BGS_CKPE_ROOT, the "
              "documented local candidates, or the prepared audit checkout"))
    args = parser.parse_args(argv)
    if args.max_cpu < 1:
        parser.error("--max-cpu must be positive")

    manifest = _inspect_source(args.source)
    _start_ghidra(args.temp_dir, args.max_cpu)

    import pyghidra
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    with pyghidra.open_project(
            args.project_dir, args.project_name, create=False) as project:
        if args.stage == "import":
            _import_target(project, args.source, manifest, monitor)
        elif args.stage == "analyze":
            _run_analysis(project, manifest, monitor, args.label)
        elif args.stage == "unwind":
            _run_unwind(project, manifest, monitor)
        elif args.stage == "ckpe-dry":
            _run_ckpe(
                project, manifest, monitor, apply=False,
                ckpe_root=_resolve_ckpe_root(args.ckpe_root))
        elif args.stage == "ckpe-apply":
            _run_ckpe(
                project, manifest, monitor, apply=True,
                ckpe_root=_resolve_ckpe_root(args.ckpe_root))
        elif args.stage == "policy":
            _restore_policy(project, manifest, monitor)
        else:
            _metrics(project, manifest, monitor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
