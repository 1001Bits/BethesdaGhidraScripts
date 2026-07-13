#!/usr/bin/env python3
"""Roll target-tagged Havok structs + this-typing across compatible game
program in a Ghidra project, in ONE project-open session.

For each target program, validate layout metadata, import /Havok structs,
then this-type Havok member functions.  Both x86 and x64 are supported when
the selected layout explicitly matches.

  python scripts/havok/rollout.py --project-dir <project-dir>
     --project-name F4VR --programs "/Fallout4 AE.exe" "/Fallout4.exe NG"
  # or --all-exe to auto-pick every *.exe program in the project
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GHIDRA_DIR = REPO / "tools" / "ghidra"
sys.path.insert(0, str(HERE))
import apply_structs
import apply_this


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--programs', nargs='*', default=None)
    ap.add_argument('--all-exe', action='store_true',
                    help="apply to every *.exe program in the project")
    ap.add_argument('--structs-only', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--layouts', default=str(apply_structs.LAYOUTS))
    args = ap.parse_args()

    records, metadata = apply_structs.load_document(args.layouts)
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()
        files = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                files.append((prefix + "/" + f.getName(), f))
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())
        walk(root)

        if args.all_exe:
            targets = [(p, f) for p, f in files if p.lower().endswith('.exe')]
        else:
            want = set(args.programs or [])
            targets = [(p, f) for p, f in files if p in want]
            missing = want - {p for p, _ in targets}
            for m in missing:
                print("  NOT FOUND:", m)
        print("rollout: %d target program(s) in %s/%s"
              % (len(targets), args.project_dir, args.project_name))

        for ppath, df in targets:
            consumer = java.lang.Object()
            program = df.getDomainObject(consumer, not args.dry_run, False, monitor)
            try:
                print("\n### %s" % ppath)
                apply_structs.run(program, records, args.dry_run, monitor,
                                  metadata)
                if not args.structs_only:
                    apply_this.run(program, args.dry_run, monitor)
            except Exception as e:  # noqa: BLE001
                print("  ERROR on %s: %s: %s" % (ppath, type(e).__name__, e))
            finally:
                program.release(consumer)


if __name__ == "__main__":
    main()
