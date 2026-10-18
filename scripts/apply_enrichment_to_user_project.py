#!/usr/bin/env python3
"""Run a core improvement driver (string_anchored_rename / ctor_mine /
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
      [--target-pe PATH ...]   # exact backing exe when the import path is gone

Driver env knobs (BGS_ENRICH_APPLY=go, BGS_CTOR_*, BGS_GLOBALS_*) are
read from the environment -- set them before invoking.

After ``globals_harvest`` / ``ctor_mine`` the reviewer DECISIONS csv is
(re)built next to the mined evidence exactly as discover_combined does -- the
same ``refs/`` file names, so a queue mined and reviewed through either
launcher is the one ``--driver globals_apply`` / ``ctor_apply`` reads.  The
program is committed and saved only when a MUTATING driver really applied
(``BGS_ENRICH_APPLY=go`` and no ``--read-only``); read-only miners are always
rolled back, and an applier that refuses its evidence raises, which is
reported as a failure and rolled back.

pyghidra acquires an exclusive lock; the Ghidra GUI must be closed.
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
CORE_DIR   = REPO_DIR / "scripts" / "core"
sys.path.insert(0, str(CORE_DIR))
from pyghidra_result import (end_outer_transaction,
                             require_driver_completion,
                             require_script_success)
from binary_identity import verify_ghidra_program
from ghidra_project import (UnsavedRecoveryError, find_program, open_program,
                            open_user_project)
from review_queue import (MINER_SPECS, merge_review_queue, queue_environment,
                          queue_paths)
from target_pe import ENV_TARGET_PE, select_target_pe

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
# Drivers that write to the program when BGS_ENRICH_APPLY=go -- the same set
# discover_combined commits.  ctor_mine / globals_harvest / havok_mine only
# write CSVs: they are always rolled back and never saved, whatever the env.
MUTATING = {'string_anchored_rename', 'ctor_apply', 'globals_apply',
            'settings_harvest', 'console_harvest', 'console_harvest_sf',
            'pe_unwind_enrich', 'registration_harvest'}


def run_driver(ghidra_script, project, program, driver, *, applying, monitor,
               environ=None):
    """Run one driver atomically; returns True on proven success.

    Commits (and saves) only a MUTATING driver that is ``applying``; every
    other run -- a read-only miner, a dry-run, ``--read-only`` -- is rolled
    back.  After a miner the reviewer decisions file is refreshed through the
    shared review-queue merge.
    """
    environ = os.environ if environ is None else environ
    applying = bool(applying) and driver in MUTATING
    tx = program.startTransaction("Atomic improvement " + driver)
    succeeded = False
    try:
        stdout, stderr = ghidra_script(
            str(DRIVERS[driver]), project, program,
            echo_stdout=True, echo_stderr=True)
        require_script_success(stderr, driver)
        require_driver_completion(stdout, driver)
        if driver in MINER_SPECS:
            spec = MINER_SPECS[driver]
            evidence, decisions = queue_paths(spec, program, environ)
            merge_review_queue(evidence, decisions, spec)
            if os.path.isfile(decisions):
                print("Reviewer decisions file: " + decisions)
        succeeded = True
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {type(exc).__name__}: {exc}")
    finally:
        commit = succeeded and applying
        try:
            end_outer_transaction(program, tx, commit, driver)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {type(exc).__name__}: {exc}")
            succeeded = False
    if succeeded and applying:
        print("Saving...")
        try:
            program.save(f"improvement: {driver}", monitor)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: saving failed, changes are NOT on disk: "
                  f"{type(exc).__name__}: {exc}")
            return False
    return succeeded


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--driver', required=True, choices=sorted(DRIVERS),
                    help="Which core improvement driver to run")
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--program-path', required=True,
                    help="Exact program path inside the project, e.g. "
                         "/Skyrim/SkyrimSE_1_5_97.exe")
    ap.add_argument('--read-only', action='store_true',
                    help="Skip saving the program (use for ctor_mine / "
                         "globals_harvest, which only write a CSV)")
    ap.add_argument('--target-pe', action='append', default=[], metavar='PATH',
                    help="candidate backing executable (repeatable); used when "
                         "the recorded import path is gone and its SHA-256 "
                         "equals the Program's import hash")
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
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()

        domain_file = find_program(root, args.program_path)
        if domain_file is None:
            print(f"ERROR: {args.program_path} not found in project")
            sys.exit(1)
        print(f"Found program: {domain_file.getPathname()}")
        # The same evidence/decisions paths discover_combined uses (an
        # explicit BGS_*_CSV override still wins), exported so the miner, the
        # merge after it and a later applier all touch the same two files.
        os.environ.update(queue_environment(str(domain_file.getPathname())))

        applying = (not args.read_only and args.driver in MUTATING and
                    os.environ.get('BGS_ENRICH_APPLY', '').lower() == 'go')
        consumer = java.lang.Object()
        # Refuses while unsaved crash-recovery data exists; only a run that
        # will really apply gets a writable program.
        try:
            program = open_program(domain_file, consumer, monitor,
                                   write=applying)
        except UnsavedRecoveryError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
        ok = False
        os.environ.pop(ENV_TARGET_PE, None)      # never inherited
        try:
            try:
                executable, manifest = select_target_pe(
                    program, args.target_pe)
                verify_ghidra_program(program, [manifest])
            except Exception as exc:  # noqa: BLE001
                print(f"ERROR: refusing unverifiable program: {exc}")
                sys.exit(1)
            # The in-Ghidra drivers re-verify this exact file.
            os.environ[ENV_TARGET_PE] = str(executable)
            print(f"Running {args.driver} via pyghidra "
                  f"({'APPLY' if applying else 'dry-run / read-only'})...")
            ok = run_driver(pyghidra.ghidra_script, project, program,
                            args.driver, applying=applying, monitor=monitor)
            print("Done." if ok else "FAILED.")
        finally:
            os.environ.pop(ENV_TARGET_PE, None)
            program.release(consumer)
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
