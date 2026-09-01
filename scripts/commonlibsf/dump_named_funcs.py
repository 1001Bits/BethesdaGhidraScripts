#!/usr/bin/env python3
"""Dump all named functions from a Ghidra Program to CSV.

Output columns: target_va, name
Skips FUN_*, thunk_FUN_*, sub_* (the noise prefixes).

Usage:
  python dump_named_funcs.py <project_dir> <project_name> <program_path> <out_csv>
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))


def is_noise(name):
    return name.startswith("FUN_") or name.startswith("thunk_FUN_") or name.startswith("sub_")


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    project_dir, project_name, program_path, out_csv = sys.argv[1:5]

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        domain_file = None
        if program_path.startswith("/"):
            domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            target = program_path.lstrip("/").split("/")[-1]
            def walk(folder):
                for f in folder.getFiles():
                    if f.getName() == target:
                        return f
                for sub in folder.getFolders():
                    r = walk(sub)
                    if r is not None:
                        return r
                return None
            domain_file = walk(root)
        if domain_file is None:
            print(f"ERROR: program not found: {program_path}")
            sys.exit(3)

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            fm = program.getFunctionManager()
            n_dumped = 0
            with open(out_csv, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name"])
                for func in fm.getFunctions(True):
                    nm = func.getName(True)  # True = include namespace path
                    leaf = func.getName()
                    if is_noise(leaf):
                        continue
                    addr_int = func.getEntryPoint().getOffset()
                    w.writerow([f"0x{addr_int:x}", nm])
                    n_dumped += 1
            print(f"Dumped {n_dumped} named functions to {out_csv}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
