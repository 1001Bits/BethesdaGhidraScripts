#!/usr/bin/env python3
"""Apply a CommonLibImport_<SE|AE|AE_1_7_104|VR>.py script to the matching Skyrim
binary in the user's Ghidra project via pyghidra.

Supports SE / AE 1.6.1170 / AE 1.7.104 / VR.  Picks the CommonLibImport file by ``--version``
and disambiguates the binary inside a combined project by its
version-tagged filename.

Defaults to the C:/GhidraProjects/Skyrim/<SkyrimSE|SkyrimAE|skyrimvr>.gpr
project layout but accepts ``--project-dir`` + ``--project-name`` for
any project, plus ``--program-path`` to bypass the heuristic when a
project uses an unusual naming scheme.

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


# Version → (CommonLibImport filename, default program basename,
# default project name, path-substring hints to disambiguate inside
# combined projects).  Order each list specific-to-generic.
VERSIONS = {
    'se':  ('CommonLibImport_SE.py',  'SkyrimSE.exe', 'SkyrimSE',
            ['skyrimse_1_5_97', '1_5_97', '1.5.97', '_se_', '_se.']),
    'ae':  ('CommonLibImport_AE.py',  'SkyrimSE.exe', 'SkyrimAE',
            ['skyrimae', '1_6_1170', '1.6.1170', 'gog edition', '_ae_', '_ae.']),
    '17104': ('CommonLibImport_AE_1_7_104.py', 'SkyrimSE.exe', 'SkyrimAE17104',
              ['skyrimae_1_7_104', '1_7_104', '1.7.104', '_17104.exe', '_17104_']),
    'vr':  ('CommonLibImport_VR.py',  'SkyrimVR.exe', 'skyrimvr',
            ['skyrimvr', 'skyrim_vr', '1_4_15', '1.4.15', '_vr_', '_vr.']),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--version', required=True, choices=sorted(VERSIONS),
                    help="Skyrim variant to apply (se/ae/17104/vr)")
    ap.add_argument('--project-dir',  default=None,
                    help="Directory containing the .gpr (default: "
                         "C:/GhidraProjects/Skyrim)")
    ap.add_argument('--project-name', default=None,
                    help="Project name without .gpr (default depends on --version)")
    ap.add_argument('--program',      default=None,
                    help="Program file basename to find inside the project "
                         "(defaults to the version's SkyrimSE/SkyrimVR.exe)")
    ap.add_argument('--program-path', default=None,
                    help="Exact program path inside the project (e.g. "
                         "'/Skyrim/SkyrimSE_1_5_97.exe'); overrides "
                         "version-hint disambiguation")
    ap.add_argument('--script',       default=None,
                    help="CommonLibImport_<VER>.py path (defaults to the "
                         "matching script under ghidrascripts/)")
    args = ap.parse_args()

    ver = args.version
    script_name, default_program, default_pname, hints = VERSIONS[ver]
    program_name = args.program or default_program
    target_path  = args.program_path
    script_path  = Path(args.script) if args.script else SCRIPTS_OUT / script_name
    project_dir  = Path(args.project_dir or "C:/GhidraProjects/Skyrim")
    project_name = args.project_name or default_pname

    if not script_path.is_file():
        print(f"ERROR: {script_path} not found.  Generate it first via "
              f"scripts/commonlibsse/parse_commonlib_types.py.")
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
                if not n.lower().endswith('.exe'):
                    continue
                if n == program_name or (n.startswith(stem)
                                          and n.lower().endswith('.exe')):
                    candidates.append((full, f))
                elif any(h in full.lower() for h in hints):
                    candidates.append((full, f))
            for sub in folder.getFolders():
                collect(sub, prefix + "/" + sub.getName())

        collect(root)

        if not candidates:
            print(f"ERROR: no Skyrim {ver.upper()} binary found in project tree.")
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
            matched = [(p, f) for p, f in candidates
                       if any(h in p.lower() for h in hints)]
            if len(matched) == 1:
                domain_file = matched[0][1]
                print(f"Disambiguated to {matched[0][0]} (version hint matched)")
            else:
                print(f"ERROR: multiple candidates, no unambiguous {ver} hint. "
                      f"Pass --program-path to choose one.  Candidates:")
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
            program.save(f"CommonLibSSE {ver} import (" + script_path.name + ")", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
