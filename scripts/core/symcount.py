#!/usr/bin/env python3
"""Quick: how many functions in a program carry real (non-FUN_/sub_) names,
and sample some -- gauges whether a build shipped debug symbols.  READ-ONLY.
"""
import argparse
import os
from pathlib import Path

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program-path', required=True)
    args = ap.parse_args()
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()
    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]
    with pyghidra.open_project(pdir, pname, create=False) as project:
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
            print("not found")
            return
        consumer = java.lang.Object()
        program = match[0].getDomainObject(consumer, True, False, monitor)
        try:
            fm = program.getFunctionManager()
            total = named = 0
            samples = []
            for f in fm.getFunctions(True):
                total += 1
                nm = f.getName()
                if not (nm.startswith('FUN_') or nm.startswith('sub_')
                        or nm.startswith('thunk_FUN')):
                    named += 1
                    if len(samples) < 30 and len(nm) > 4:
                        samples.append(nm)
            print("%s: %d functions, %d named (%.1f%%)"
                  % (program.getName(), total, named,
                     100.0 * named / max(total, 1)))
            print("samples:")
            for s in samples:
                print("   " + s)
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
