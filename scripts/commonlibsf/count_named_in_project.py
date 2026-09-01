#!/usr/bin/env python3
"""Count named functions + dump exe MD5 for any Ghidra project program.

Usage:
  python count_named_in_project.py <project_dir> <project_name> [program_name]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    project_dir = sys.argv[1]
    project_name = sys.argv[2]
    program_filter = sys.argv[3] if len(sys.argv) > 3 else None

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        def walk(folder, files):
            for f in folder.getFiles():
                files.append(f)
            for sub in folder.getFolders():
                walk(sub, files)
            return files

        files = walk(root, [])
        for df in files:
            if df.getContentType() != "Program":
                continue
            if program_filter and df.getName() != program_filter:
                continue
            consumer = java.lang.Object()
            program = df.getDomainObject(consumer, False, False, monitor)
            try:
                fm = program.getFunctionManager()
                total = fm.getFunctionCount()
                n_named = 0
                n_fun = 0
                n_thunk = 0
                n_sub = 0
                for func in fm.getFunctions(True):
                    nm = func.getName()
                    if nm.startswith("FUN_"):
                        n_fun += 1
                    elif nm.startswith("thunk_FUN_"):
                        n_thunk += 1
                    elif nm.startswith("sub_"):
                        n_sub += 1
                    else:
                        n_named += 1
                md5 = program.getExecutableMD5()
                print(f"{df.getName()}  md5={md5}")
                print(f"  total funcs:    {total}")
                print(f"  named:          {n_named}")
                print(f"  FUN_:           {n_fun}")
                print(f"  thunk_FUN_:     {n_thunk}")
                print(f"  sub_:           {n_sub}")
                print(f"  named pct:      {100.0*n_named/max(total,1):.1f}%")
            finally:
                program.release(consumer)


if __name__ == "__main__":
    main()
