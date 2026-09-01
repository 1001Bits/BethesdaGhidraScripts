#!/usr/bin/env python3
"""List all programs in a Ghidra project (path, language/processor, size)."""
import argparse
import os
from pathlib import Path

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', required=True)
    args = ap.parse_args()
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]
    with pyghidra.open_project(pdir, pname, create=False) as project:
        root = project.getProjectData().getRootFolder()

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                meta = f.getMetadata() or {}
                lang = meta.get("Language ID") or meta.get("Executable Format") or "?"
                print("  %-40s  %s" % (prefix + "/" + f.getName(), lang))
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())
        print("Programs in %s/%s.gpr:" % (pdir, pname))
        walk(root)


if __name__ == "__main__":
    main()
