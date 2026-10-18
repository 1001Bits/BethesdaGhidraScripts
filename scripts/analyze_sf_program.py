#!/usr/bin/env python3
"""Run full Ghidra auto-analysis on a program inside a user project.

The Starfield program in Combined.gpr was imported + disassembled (211k
functions, our CommonLib symbols applied) but its ``Analyzed`` flag is
False and the reference-creating analyzers never ran -- 0 of its
VTABLE_ symbols carry a single reference.  That starves every
discovery driver (ctor_mine / globals_harvest / settings_harvest /
console_harvest all rely on data xrefs).  This runs the missing
analysis so those references (code->vtable, data->global, string xrefs)
get recovered, then saves.

Heavy: hours of CPU on a ~100 MB binary.  pyghidra holds an exclusive
lock; the Ghidra GUI must be closed.

Safety:
  * the program is identity-verified against its backing executable (the
    recorded import path, or a ``--target-pe`` candidate whose SHA-256 equals
    the Program's import hash) before anything runs;
  * a program that is ALREADY analyzed (``Analyzed`` flag set, or a pipeline
    stage past ``imported-v1``) is refused unless ``--force-reanalyze``:
    re-running every analyzer over hand-enriched work is never a default;
  * the ``Analyzed`` flag is set INSIDE the analysis transaction, and the
    program is saved only when that transaction provably committed.

Usage:
  python scripts/analyze_sf_program.py
      [--project-dir C:/GhidraProjects --project-name Combined]
      [--program-path "/Starfield/Starfield 1.16.236"]
      [--target-pe PATH ...] [--force-reanalyze]
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
CORE_DIR   = REPO_DIR / "scripts" / "core"
STAGE_OPTION = "BGS Pipeline Stage"
FRESH_STAGES = ("", "imported-v1")

sys.path.insert(0, str(CORE_DIR))
from binary_identity import verify_ghidra_program  # noqa: E402
from ghidra_project import (UnsavedRecoveryError, find_program,  # noqa: E402
                            open_program, open_user_project)
from pyghidra_result import end_outer_transaction  # noqa: E402
from target_pe import select_target_pe  # noqa: E402


def _require_unanalyzed(program, program_path, force, program_info="Program Information"):
    """Full analysis is for a program that never had it.

    Mirrors ``import_combined_runtime._require_unanalyzed``: hours of analyzers
    running over an enriched, hand-annotated program is never what a bare
    invocation should do.
    """
    options = program.getOptions(program_info)
    stage = options.getString(STAGE_OPTION, "") or ""
    analyzed = bool(options.getBoolean("Analyzed", False))
    if force or (not analyzed and stage in FRESH_STAGES):
        return
    raise RuntimeError(
        "refusing to re-analyze {}: Analyzed={}, pipeline stage={!r}.  "
        "Re-analysis would run every analyzer over existing enrichment; pass "
        "--force-reanalyze only if that is really intended.".format(
            program_path, analyzed, stage or "<unset>"))


def analyze(program, program_path, monitor, *, candidates=(), force=False,
            manager_factory=None, program_info="Program Information"):
    """Verify, guard, analyze inside one proven transaction, then save."""
    _executable, manifest = select_target_pe(program, candidates)
    verify_ghidra_program(program, [manifest])
    _require_unanalyzed(program, program_path, force, program_info)
    mgr = manager_factory(program)
    print("Scheduling full re-analysis over all initialized memory ...")
    tx = program.startTransaction("auto-analysis")
    commit = False
    try:
        mgr.initializeOptions()
        # reAnalyzeAll(null) schedules every analyzer over all memory;
        # startAnalysis blocks until the queue drains.
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(monitor)
        if monitor.isCancelled():
            raise RuntimeError("analysis was cancelled")
        # Inside the transaction: an option write outside one is rejected
        # (and used to be swallowed by a bare try/except).
        program.getOptions(program_info).setBoolean("Analyzed", True)
        commit = True
    finally:
        # Raises when the commit did not happen, so a rolled-back analysis
        # is never saved and never reported as done.
        end_outer_transaction(program, tx, commit, "full auto-analysis")
    print("Analysis complete. Saving (this can take a while) ...")
    program.save("Full auto-analysis", monitor)
    print("Done.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--program-path', default="/Starfield/Starfield 1.16.236")
    ap.add_argument('--target-pe', action='append', default=[], metavar='PATH',
                    help="candidate backing executable (repeatable); used when "
                         "the recorded import path is gone")
    ap.add_argument('--force-reanalyze', action='store_true',
                    help="analyze a program that is already analyzed (runs "
                         "every analyzer over existing enrichment)")
    args = ap.parse_args()

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.model.listing import Program
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()
        domain_file = find_program(root, args.program_path)
        if domain_file is None:
            print(f"ERROR: {args.program_path} not found")
            return 1
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        try:
            program = open_program(domain_file, consumer, monitor, write=True)
        except UnsavedRecoveryError as exc:
            print(f"ERROR: {exc}")
            return 1
        # WindowsResourceReferenceAnalyzer runs a helper GhidraScript.  Without
        # a bundle host that is an NPE stack trace and no resource references.
        from ghidra.app.script import GhidraScriptUtil
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            analyze(program, args.program_path, monitor,
                    candidates=args.target_pe, force=args.force_reanalyze,
                    manager_factory=AutoAnalysisManager.getAnalysisManager,
                    program_info=Program.PROGRAM_INFO)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {type(exc).__name__}: {exc}")
            return 1
        finally:
            try:
                GhidraScriptUtil.releaseBundleHostReference()
            finally:
                program.release(consumer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
