#!/usr/bin/env python3
"""Run full Ghidra auto-analysis on a program inside a user project.

The Starfield program in ExampleProject.gpr was imported + disassembled (211k
functions, our CommonLib symbols applied) but its ``Analyzed`` flag is
False and the reference-creating analyzers never ran -- 0 of its
VTABLE_ symbols carry a single reference.  That starves every
discovery driver (ctor_mine / globals_harvest / settings_harvest /
console_harvest all rely on data xrefs).  This runs the missing
analysis so those references (code->vtable, data->global, string xrefs)
get recovered, then saves.

Heavy: hours of CPU on a ~100 MB binary.  pyghidra holds an exclusive
lock; the Ghidra GUI must be closed.

Usage:
  python scripts/analyze_sf_program.py
      [--project-dir C:/GhidraProjects --project-name ExampleProject]
      [--program-path "/Starfield/Starfield 1.16.236"]
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="ExampleProject")
    ap.add_argument('--program-path', default="/Starfield/Starfield 1.16.236")
    args = ap.parse_args()

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()
        match = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                if prefix + "/" + f.getName() == args.program_path:
                    match.append(f)
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())

        walk(root)
        if not match:
            print(f"ERROR: {args.program_path} not found")
            sys.exit(1)
        print(f"Found program: {match[0].getPathname()}")

        consumer = java.lang.Object()
        program = match[0].getDomainObject(consumer, True, False, monitor)
        try:
            mgr = AutoAnalysisManager.getAnalysisManager(program)
            print("Scheduling full re-analysis over all initialized memory ...")
            tx = program.startTransaction("auto-analysis")
            success = False
            try:
                mgr.initializeOptions()
                # reAnalyzeAll(null) schedules every analyzer over all memory;
                # startAnalysis blocks until the queue drains.
                mgr.reAnalyzeAll(None)
                mgr.startAnalysis(monitor)
                success = True
            finally:
                program.endTransaction(tx, success)

            # Flip the Analyzed flag so the program reports as analyzed.
            try:
                from ghidra.program.model.listing import Program
                opts = program.getOptions(Program.PROGRAM_INFO)
                opts.setBoolean("Analyzed", True)
            except Exception as e:
                print(f"  (could not set Analyzed flag: {e})")

            print("Analysis complete. Saving (this can take a while) ...")
            program.save("Full auto-analysis", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
