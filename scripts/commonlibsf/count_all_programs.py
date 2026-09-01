#!/usr/bin/env python3
"""Count named funcs in every Program across all known Ghidra projects.

Used to find which project has the best-named copy of each binary.
"""
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
    ("C:/GhidraProjects/Skyrim", "SkyrimAE"),
    ("C:/GhidraProjects/Skyrim", "SkyrimSE"),
    (str(REPO_DIR / "ghidraprojects" / "BethesdaGhidraScripts"),
     "BethesdaGhidraScripts"),
]


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    rows = []
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
                        pct = 100.0*n_named/max(total,1)
                        print(f"  {df.getPathname():60s} md5={md5} total={total} named={n_named} ({pct:.1f}%)")
                        rows.append((project_name, df.getPathname(), md5, total, n_named, pct))
                    finally:
                        program.release(consumer)
        except Exception as e:
            print(f"  ERROR opening: {e}")

    # Group by MD5: pick best-named copy
    print("\n\n=== Best copy per MD5 ===")
    by_md5 = {}
    for row in rows:
        proj, pn, md5, total, named, pct = row
        if md5 not in by_md5 or named > by_md5[md5][4]:
            by_md5[md5] = row
    for md5, row in sorted(by_md5.items(), key=lambda r: -r[1][4]):
        proj, pn, _, total, named, pct = row
        print(f"  {md5}  named={named:>7} ({pct:.1f}%)  in {proj}{pn}")


if __name__ == "__main__":
    main()
