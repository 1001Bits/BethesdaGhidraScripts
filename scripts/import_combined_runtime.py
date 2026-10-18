#!/usr/bin/env python3
"""Import and fully analyze one exact PE in a Combined Ghidra project."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_DIR / "scripts" / "core"
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
MANIFEST_OPTION = "BGS Target Manifest"
STAGE_OPTION = "BGS Pipeline Stage"
GENERIC_STAGE = "generic-v2"

sys.path.insert(0, str(CORE_DIR))
from binary_identity import (  # noqa: E402
    canonical_identity,
    inspect_pe,
    manifest_matches,
    verify_ghidra_program,
)
from ghidra_project import open_program, open_user_project  # noqa: E402
from pyghidra_result import end_outer_transaction  # noqa: E402


def _find(root, exact_path):
    wanted = "/" + exact_path.strip("/")
    hits = []

    def walk(folder, prefix=""):
        for domain_file in folder.getFiles():
            path = prefix + "/" + str(domain_file.getName())
            if path == wanted:
                hits.append(domain_file)
        for child in folder.getFolders():
            walk(child, prefix + "/" + str(child.getName()))

    walk(root)
    if len(hits) > 1:
        raise RuntimeError("ambiguous project path {}".format(wanted))
    return hits[0] if hits else None


def _folder(root, path):
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("--program-path must be /folder/program")
    folder = root.getFolder(parts[0])
    if folder is None:
        folder = root.createFolder(parts[0])
    return folder, parts[0], parts[1]


def _bind(program, expected, stage):
    from ghidra.program.model.listing import Program

    actual = verify_ghidra_program(program, [expected])
    info = program.getOptions(Program.PROGRAM_INFO)
    raw = info.getString(MANIFEST_OPTION, "") or ""
    if raw:
        recorded = json.loads(raw)
        matches, reasons = manifest_matches(recorded, actual)
        if not matches:
            raise RuntimeError(
                "stored target manifest mismatch: " + "; ".join(reasons))
    info.setString(
        MANIFEST_OPTION,
        json.dumps(canonical_identity(actual), sort_keys=True))
    info.setString(STAGE_OPTION, stage)


def _set_analysis_policy(program):
    from ghidra.program.model.listing import Program

    options = program.getOptions(Program.ANALYSIS_PROPERTIES)
    options.setBoolean("Decompiler Parameter ID", False)
    options.setBoolean("Aggressive Instruction Finder", False)


def _import(project, source, program_path, expected, monitor):
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.app.util.opinion import PeLoader
    import java.io
    import java.lang

    root = project.getProjectData().getRootFolder()
    existing = _find(root, program_path)
    if existing is not None:
        consumer = java.lang.Object()
        program = open_program(existing, consumer, monitor, write=False)
        try:
            verify_ghidra_program(program, [expected])
            print("Exact program already exists: {}".format(program_path))
            return
        finally:
            program.release(consumer)

    folder, folder_name, program_name = _folder(root, program_path)
    if folder.getFile(program_name) is not None:
        raise RuntimeError("refusing to overwrite {}".format(program_path))
    log = MessageLog()
    results = (ProgramLoader.builder()
               .source(java.io.File(str(source)))
               .project(project)
               .projectFolderPath("/" + folder_name)
               .name(program_name)
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
        raise RuntimeError("expected exactly one imported PE: {}".format(log))
    try:
        results.save(monitor)
    finally:
        results.close()

    domain_file = _find(root, program_path)
    if domain_file is None:
        raise RuntimeError("import did not create {}".format(program_path))
    consumer = java.lang.Object()
    program = open_program(domain_file, consumer, monitor, write=True)
    try:
        tx = program.startTransaction("Bind exact Combined runtime import")
        commit = False
        try:
            _bind(program, expected, "imported-v1")
            _set_analysis_policy(program)
            commit = True
        finally:
            end_outer_transaction(program, tx, commit, "runtime import binding")
        program.save("exact identity-bound runtime import", monitor)
    finally:
        program.release(consumer)
    print("Imported {}".format(program_path))


def _require_unanalyzed(program, program_path, force):
    """Full analysis is for a fresh import only.

    ``all`` on a program that already exists skips the import and used to fall
    straight through to ``reAnalyzeAll`` -- hours of analyzers running over an
    enriched, hand-annotated program, which was then re-stamped ``generic-v2``.
    """
    from ghidra.program.model.listing import Program

    stage = program.getOptions(Program.PROGRAM_INFO).getString(
        STAGE_OPTION, "") or ""
    if stage == "imported-v1" or force:
        return
    raise RuntimeError(
        "refusing to re-analyze {}: its pipeline stage is {!r}, not "
        "'imported-v1'.  Re-analysis would run every analyzer over existing "
        "enrichment and reset the stage; pass --force-reanalyze only if that "
        "is really intended.".format(program_path, stage or "<unset>"))


def _analyze(project, program_path, expected, monitor, force=False):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.model.listing import Program
    import java.lang

    domain_file = _find(project.getProjectData().getRootFolder(), program_path)
    if domain_file is None:
        raise RuntimeError("{} is not present".format(program_path))
    consumer = java.lang.Object()
    program = open_program(domain_file, consumer, monitor, write=True)
    try:
        verify_ghidra_program(program, [expected])
        _require_unanalyzed(program, program_path, force)
        manager = AutoAnalysisManager.getAnalysisManager(program)
        tx = program.startTransaction("Full Combined runtime analysis")
        commit = False
        # WindowsResourceReferenceAnalyzer runs a helper GhidraScript.  Without
        # a bundle host that is an NPE stack trace and no resource references.
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            manager.initializeOptions()
            _set_analysis_policy(program)
            manager.reAnalyzeAll(None)
            manager.startAnalysis(monitor)
            if monitor.isCancelled():
                raise RuntimeError("analysis was cancelled")
            program.getOptions(Program.PROGRAM_INFO).setBoolean("Analyzed", True)
            _bind(program, expected, GENERIC_STAGE)
            commit = True
        finally:
            try:
                end_outer_transaction(
                    program, tx, commit, "runtime full analysis")
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
        program.save("full generic runtime analysis", monitor)
        print("Analyzed {}: functions={}, symbols={}".format(
            program_path,
            program.getFunctionManager().getFunctionCount(),
            program.getSymbolTable().getNumSymbols()))
    except BaseException as error:
        # A failed save leaves the domain object "locked by save", so the
        # release below throws too and would mask the real cause (a full disk,
        # for one).  Report the cause first.
        print("ERROR: analysis/save of {} failed: {}: {}".format(
            program_path, type(error).__name__, str(error)[:500]))
        raise
    finally:
        try:
            program.release(consumer)
        except Exception as release_error:  # noqa: BLE001
            print("WARNING: release failed after the error above: {}".format(
                str(release_error)[:200]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("import", "analyze", "all"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--program-path", required=True)
    parser.add_argument("--project-dir", default="C:/GhidraProjects")
    parser.add_argument("--project-name", default="Combined")
    parser.add_argument("--force-reanalyze", action="store_true",
                        help="analyze a program that is already past the "
                             "'imported-v1' stage (runs every analyzer over "
                             "existing enrichment)")
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.is_file():
        parser.error("source does not exist: {}".format(source))
    expected = inspect_pe(str(source))
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    with open_user_project(
            Path(args.project_dir), args.project_name) as project:
        if args.action in ("import", "all"):
            _import(project, source, args.program_path, expected, monitor)
        if args.action in ("analyze", "all"):
            _analyze(project, args.program_path, expected, monitor,
                     force=args.force_reanalyze)


if __name__ == "__main__":
    main()
