#!/usr/bin/env python3
"""Run a core enrichment driver (string_anchored_rename / ctor_mine /
globals_harvest) against a program in a user's Ghidra project via pyghidra.

These drivers are game-agnostic -- they work on any MSVC-compiled
Bethesda binary (Skyrim, Fallout 4, Starfield, FNV).  String-anchored
rename mutates the program (when BGS_ENRICH_APPLY=go); the mining
drivers are read-only and write a CSV.

Usage:
  python scripts/apply_enrichment_to_user_project.py \
      --driver string_anchored_rename \
      --project-dir C:/GhidraProjects --project-name Combined \
      --program-path /Skyrim/SkyrimSE_1_5_97.exe
      [--read-only]   # don't save the program (for ctor_mine / globals_harvest)

Driver env knobs (BGS_ENRICH_APPLY=go, BGS_CTOR_*, BGS_GLOBALS_*) are
read from the environment -- set them before invoking.

pyghidra acquires an exclusive lock; the Ghidra GUI must be closed.
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = REPO_DIR / "tools" / "ghidra"
CORE_DIR   = REPO_DIR / "scripts" / "core"
sys.path.insert(0, str(CORE_DIR))
from pyghidra_result import end_outer_transaction, require_script_success
from binary_identity import (inspect_pe, verify_ghidra_program,
                             _program_executable_path)

DRIVERS = {
    'string_anchored_rename': CORE_DIR / 'string_anchored_rename.py',
    'ctor_mine':              CORE_DIR / 'ctor_mine.py',
    'globals_harvest':        CORE_DIR / 'globals_harvest.py',
    'globals_apply':          CORE_DIR / 'globals_apply.py',
    'settings_harvest':       CORE_DIR / 'settings_harvest.py',
    'console_harvest':        CORE_DIR / 'console_harvest.py',
    'console_harvest_sf':     CORE_DIR / 'console_harvest_sf.py',
    'ctor_apply':             CORE_DIR / 'ctor_apply.py',
    'havok_mine':             CORE_DIR / 'havok_mine.py',   # verifier only
    'pe_unwind_enrich':       CORE_DIR / 'pe_unwind_enrich.py',
    'registration_harvest':   CORE_DIR / 'registration_harvest.py',
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--driver', required=True, choices=sorted(DRIVERS),
                    help="Which core enrichment driver to run")
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--program-path', required=True,
                    help="Exact program path inside the project, e.g. "
                         "/Skyrim/SkyrimSE_1_5_97.exe")
    ap.add_argument('--read-only', action='store_true',
                    help="Skip saving the program (use for ctor_mine / "
                         "globals_harvest, which only write a CSV)")
    args = ap.parse_args()

    driver_path = DRIVERS[args.driver]
    if not driver_path.is_file():
        print(f"ERROR: driver {driver_path} not found")
        sys.exit(1)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        match = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                full = prefix + "/" + f.getName()
                if full == args.program_path:
                    match.append(f)
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())

        walk(root)
        if not match:
            print(f"ERROR: {args.program_path} not found in project")
            sys.exit(1)
        domain_file = match[0]
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        # read_only=False so string_anchored_rename can mutate; the mining
        # drivers simply don't write.
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            executable = _program_executable_path(program)
            verify_ghidra_program(program, [inspect_pe(executable)])
            print(f"Running {args.driver} via pyghidra...")
            tx = program.startTransaction("Atomic enrichment " + args.driver)
            commit = False
            try:
                stdout, stderr = pyghidra.ghidra_script(
                    str(driver_path), project, program,
                    echo_stdout=True, echo_stderr=True)
                require_script_success(stderr, args.driver)
                commit = True
            finally:
                end_outer_transaction(program, tx, commit, args.driver)
            if not args.read_only:
                print("Saving...")
                program.save(f"enrichment: {args.driver}", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
