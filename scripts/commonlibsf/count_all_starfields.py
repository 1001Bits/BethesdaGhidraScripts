#!/usr/bin/env python3
"""Count named funcs in every Starfield* program across all known projects."""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))


PROJECTS = [
    ("C:/GhidraProjects", "ExampleProject"),
    ("C:/GhidraProjects/Starfield", "StarfieldProject"),
    ("C:/GhidraProjects/Fallout", "F4VR"),
]


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    for project_dir, project_name in PROJECTS:
        print(f"\n=== {project_dir}/{project_name} ===")
        try:
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
                    if "Starfield" not in df.getName():
                        continue
                    consumer = java.lang.Object()
                    try:
                        program = df.getDomainObject(consumer, False, False, monitor)
                    except Exception as e:
                        print(f"  {df.getName()}: skipped ({e})")
                        continue
                    try:
                        fm = program.getFunctionManager()
                        total = fm.getFunctionCount()
                        n_named = 0
                        for func in fm.getFunctions(True):
                            nm = func.getName()
                            if not (nm.startswith("FUN_") or nm.startswith("thunk_FUN_") or nm.startswith("sub_")):
                                n_named += 1
                        md5 = program.getExecutableMD5()
                        print(f"  {df.getPathname():60s} md5={md5}")
                        print(f"    total={total}  named={n_named}  pct={100.0*n_named/max(total,1):.1f}%")
                    finally:
                        program.release(consumer)
        except Exception as e:
            print(f"  ERROR: {e}")


if __name__ == "__main__":
    main()
