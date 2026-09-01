#!/usr/bin/env python3
"""Apply a CommonLibImport_F4_<VER>.py script to the matching Fallout4
binary in the user's combined Ghidra project via pyghidra.

Supports every F4 variant in one place: OG (1.10.163) / NG (1.10.984) /
AE (1.11.191) / VR (1.2.72) / 1.11.221 / 1.11.240.  Pick the version with
``--version`` and the script auto-selects the matching CommonLibImport
file and disambiguates the binary inside a combined project by its
version-tagged filename.

The combined ``ExampleProject.gpr`` / ``F4VR.gpr`` projects under
``C:/GhidraProjects`` typically hold several Fallout4 binaries imported
as ``Fallout4_<VER>_<patch>.exe`` (e.g. ``Fallout4_AE_1_11_191.exe``,
``Fallout4VR_1_2_72.exe``).  ``--version`` matches the version tag.
``--program-path`` overrides the heuristic when the project uses a
different naming scheme.

pyghidra acquires an exclusive lock on the project, so the Ghidra GUI
must NOT be open while this script runs.

Headless mode -- no GUI required.
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
SCRIPTS_OUT = REPO_DIR / "ghidrascripts"
CORE_DIR    = REPO_DIR / "scripts" / "core"
sys.path.insert(0, str(CORE_DIR))
from importer_binding import ImporterBindingError, verify_importer_for_program
from pyghidra_result import end_outer_transaction, require_script_success
from ghidra_project import open_user_project

PROJECT_DIR  = Path(r"C:/GhidraProjects/Fallout")
PROJECT_NAME = "F4VR"


# Version key -> (CommonLibImport filename, default program basename,
# substrings that disambiguate the binary inside a combined project).
# `hints` is searched against the lowercase full project path; first
# match wins.  Order each list specific-to-generic.
VERSIONS = {
    'og':  ('CommonLibImport_F4_OG.py',  'Fallout4.exe',   ['_og_', '_og.', '1_10_163', '1.10.163']),
    'ng':  ('CommonLibImport_F4_NG.py',  'Fallout4.exe',   ['_ng_', '_ng.', '1_10_984', '1.10.984', '1_10_980', '1.10.980']),
    'ae':  ('CommonLibImport_F4_AE.py',  'Fallout4.exe',   ['_ae_', '_ae.', ' ae.exe', '1_11_191', '1.11.191']),
    'vr':  ('CommonLibImport_F4_VR.py',  'Fallout4VR.exe', ['fallout4vr', 'fallout4_vr', '1_2_72', '1.2.72']),
    '221': ('CommonLibImport_F4_221.py', 'Fallout4.exe',   ['_221.exe', '_221_', '1_11_221', '1.11.221']),
    '240': ('CommonLibImport_F4_240.py', 'Fallout4.exe',   ['_240.exe', '_240_', '1_11_240', '1.11.240']),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--version', required=True, choices=sorted(VERSIONS),
                    help="F4 variant to apply (og/ng/ae/vr/221/240)")
    ap.add_argument('--project-dir',  default=str(PROJECT_DIR),
                    help="Directory containing the .gpr (default: %(default)s)")
    ap.add_argument('--project-name', default=PROJECT_NAME,
                    help="Project name without .gpr (default: %(default)s)")
    ap.add_argument('--program',      default=None,
                    help="Program file basename to find inside the project "
                         "(defaults to the version's Fallout4 / Fallout4VR.exe)")
    ap.add_argument('--program-path', default=None,
                    help="Exact program path inside the project (e.g. "
                         "'/Fallout4/Fallout4_AE_1_11_191.exe'); overrides "
                         "version-hint disambiguation")
    ap.add_argument('--script',       default=None,
                    help="CommonLibImport_F4_<VER>.py path (defaults to the "
                         "matching script under ghidrascripts/)")
    args = ap.parse_args()

    ver = args.version
    script_name, default_program, hints = VERSIONS[ver]
    program_name = args.program or default_program
    target_path  = args.program_path
    script_path  = Path(args.script) if args.script else SCRIPTS_OUT / script_name
    project_dir  = Path(args.project_dir)
    project_name = args.project_name

    if not script_path.is_file():
        print(f"ERROR: {script_path} not found.  Generate it first via "
              f"scripts/commonlibf4/parse_commonlib_types.py.")
        sys.exit(1)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Opening project: {project_dir}/{project_name}.gpr")
    with open_user_project(project_dir, project_name) as project:
        root = project.getProjectData().getRootFolder()
        stem = program_name.rsplit('.', 1)[0]

        candidates = []  # list of (full_path, domain_file)

        def collect(folder, prefix=""):
            for f in folder.getFiles():
                n = f.getName()
                full = prefix + "/" + n
                if n == program_name or (n.startswith(stem) and n.lower().endswith('.exe')):
                    candidates.append((full, f))
                # Also accept any *.exe whose path mentions a version hint;
                # the combined project renames Fallout4VR binaries away from
                # the default stem (e.g. Fallout4VR_1_2_72.exe vs program=Fallout4.exe).
                elif n.lower().endswith('.exe') and any(h in full.lower() for h in hints):
                    candidates.append((full, f))
            for sub in folder.getFolders():
                collect(sub, prefix + "/" + sub.getName())

        collect(root)

        if not candidates:
            print(f"ERROR: no {program_name} found in project tree.")
            sys.exit(1)

        # Pick the target
        domain_file = None
        if target_path:
            for path, f in candidates:
                if path == target_path:
                    domain_file = f
                    break
            if domain_file is None:
                print(f"ERROR: --program-path {target_path!r} did not match any "
                      f"binary in the project.")
                print("Candidates found:")
                for path, _ in candidates:
                    print(f"  {path}")
                sys.exit(1)
        elif len(candidates) == 1:
            domain_file = candidates[0][1]
        else:
            # Prefer a candidate whose path contains one of the version hints.
            matched = [(p, f) for p, f in candidates
                       if any(h in p.lower() for h in hints)]
            if len(matched) == 1:
                domain_file = matched[0][1]
                print(f"Disambiguated to {matched[0][0]} (version hint matched)")
            else:
                print(f"ERROR: multiple {program_name} candidates, no unambiguous "
                      f"{ver} hint.  Pass --program-path to choose one.  Candidates:")
                for path, _ in candidates:
                    marker = '  * ' if any(h in path.lower() for h in hints) else '    '
                    print(f"{marker}{path}")
                sys.exit(1)

        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            try:
                verify_importer_for_program(script_path, program)
            except (ImporterBindingError, OSError, ValueError) as exc:
                print(f"\nERROR: refusing to run this import script.\n\n{exc}\n")
                sys.exit(1)
            print(f"Running {script_path.name} via pyghidra...")
            tx = program.startTransaction("Atomic " + script_path.name)
            commit = False
            try:
                stdout, stderr = pyghidra.ghidra_script(
                    script_path, project, program,
                    echo_stdout=True, echo_stderr=True)
                require_script_success(stderr, script_path.name)
                commit = True
            finally:
                end_outer_transaction(program, tx, commit, script_path.name)
            print("Saving...")
            program.save(f"CommonLibF4 {ver} import (" + script_path.name + ")", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
