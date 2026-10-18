#!/usr/bin/env python3
"""Launcher for bsim_query_apply.py against a target program.

Usage:
  python run_bsim_query.py <target-program-name> [min_sim] [min_sig] [--dry]

Example:
  python run_bsim_query.py Starfield.exe 0.85 25.0
  python run_bsim_query.py "Fallout4 AE.exe" 0.85 25.0 --dry

Opens the BethesdaGhidraScripts project, finds the target program, runs
the bsim_query_apply.py Ghidra script against it, and saves.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_DIR     = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR   = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
PROJECT_DIR  = REPO_DIR / "ghidraprojects" / "BethesdaGhidraScripts"
PROJECT_NAME = "BethesdaGhidraScripts"
SCRIPT_PATH  = REPO_DIR / "scripts" / "commonlibsf" / "bsim_query_apply.py"
DB_URL       = "file:/" + str(REPO_DIR / "bsim" / "SF_BSim").replace("\\", "/")
sys.path.insert(0, str(REPO_DIR / "scripts" / "core"))
from ghidra_project import open_program, open_user_project  # noqa: E402
from pyghidra_result import end_outer_transaction, require_script_success
from binary_identity import verify_ghidra_program
from target_pe import select_target_pe


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    program_name = sys.argv[1]
    extra_args = sys.argv[2:]

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    project_path = PROJECT_DIR  # parent of <project_name>.gpr
    # Some Ghidra projects are at <root>/<name>.gpr; in our layout it's
    # <root>/BethesdaGhidraScripts/BethesdaGhidraScripts.gpr -- pass that dir.
    print(f"Target program: {program_name}")
    print(f"BSim DB:        {DB_URL}")
    print(f"Project:        {project_path}/{PROJECT_NAME}")
    print(f"Script:         {SCRIPT_PATH}")

    with open_user_project(project_path, PROJECT_NAME) as project:
        root = project.getProjectData().getRootFolder()

        def find(folder):
            for f in folder.getFiles():
                if f.getName() == program_name:
                    return f
            for sub in folder.getFolders():
                r = find(sub)
                if r is not None:
                    return r
            return None

        domain_file = find(root)
        if domain_file is None:
            print(f"ERROR: program {program_name!r} not found in project")
            sys.exit(2)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = open_program(domain_file, consumer, monitor, write=True)
        try:
            # Ghidra records Windows paths as /C:/...; select_target_pe
            # canonicalises that form (a raw path reads as C:\C:\...) and
            # fails with an actionable message when the file is gone.
            _executable, target_manifest = select_target_pe(program)
            verify_ghidra_program(program, [target_manifest])
            # Compose args list for the Jython/PyGhidra script
            script_args = ([DB_URL] + extra_args +
                           ['--target-sha256=' + target_manifest['sha256']])
            print(f"Script args: {script_args}")
            tx = program.startTransaction("Atomic BSim name port")
            commit = False
            try:
                stdout, stderr = pyghidra.ghidra_script(
                    SCRIPT_PATH, project, program,
                    script_args=script_args,
                    echo_stdout=True, echo_stderr=True)
                require_script_success(stderr, SCRIPT_PATH.name)
                commit = True
            finally:
                end_outer_transaction(program, tx, commit, SCRIPT_PATH.name)
            print("Saving program...")
            program.save("BSim cross-corpus name port", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
