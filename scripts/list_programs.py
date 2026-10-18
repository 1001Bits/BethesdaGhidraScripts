#!/usr/bin/env python3
"""Print the folder/program tree of one or more Ghidra projects."""
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
_BGS_CORE_DIR = Path(__file__).resolve().parent / "core"
if str(_BGS_CORE_DIR) not in sys.path:
    sys.path.append(str(_BGS_CORE_DIR))
from ghidra_project import open_user_project  # noqa: E402


def walk(folder, prefix=""):
    for f in folder.getFiles():
        print(f"{prefix}{f.getName()}  [{f.getContentType()}]")
    for sub in folder.getFolders():
        print(f"{prefix}{sub.getName()}/")
        walk(sub, prefix + "  ")


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    for arg in sys.argv[1:]:
        project_dir, project_name = arg.rsplit("/", 1)
        print(f"\n=== {project_dir}/{project_name} ===")
        try:
            with open_user_project(project_dir, project_name) as project:
                root = project.getProjectData().getRootFolder()
                walk(root)
        except Exception as e:
            print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
