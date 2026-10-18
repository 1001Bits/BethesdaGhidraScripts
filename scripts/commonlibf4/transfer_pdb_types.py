#!/usr/bin/env python3
r"""Transfer the PDB-derived data types of one program to others.

Source: ``/Fallout4/Fallout4_1_10_155.exe`` after Ghidra's PDB Universal
analyzer applied its full compiler PDB -- exact struct layouts, enums, unions,
typedefs and function definitions for that build.  Two outputs:

* ``--archive OUT.gdt``: a Ghidra data-type archive of the source's types
  (every category except Ghidra's built-ins), reusable from the GUI.
* ``--target /Path``: the same types added to that program's data-type manager
  under the category prefix ``--category`` (default ``/PDB_1_10_155``), so a
  later prototype port can resolve them.  The WHOLE dependency graph moves
  under the prefix first (staged in a scratch data-type manager), so a member
  type is never bound to the target's different type at the original path.
  Conflicts inside the prefix KEEP the target's existing type: nothing an
  analyst or importer created is ever replaced.

Ghidra's built-ins (``/int``, ``/undefined8`` ... at the root category, not
under ``/BuiltInTypes``) and derived pointer/array types are never copied.

Read-only on the source, one transaction on the target, dry-run by default.

Usage (Ghidra GUI closed)::

    python scripts/commonlibf4/transfer_pdb_types.py --archive build/evidence/fallout4_1_10_155_pdb.gdt
    python scripts/commonlibf4/transfer_pdb_types.py --target /Fallout4/Fallout4_OG_1_10_163.exe [--apply]
"""
from __future__ import annotations

import argparse
import collections
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "core"))
from ghidra_project import find_program, open_program, open_user_project  # noqa: E402
from pyghidra_result import end_outer_transaction  # noqa: E402

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO / "tools" / "ghidra"))
SOURCE_PATH = "/Fallout4/Fallout4_1_10_155.exe"
SKIP_ROOT_CATEGORIES = {"BuiltInTypes"}


def _type_kinds():
    from ghidra.program.model.data import Array, BuiltInDataType, Pointer
    return {"array": Array, "builtin": BuiltInDataType, "pointer": Pointer}


def is_transferable(dt, kinds):
    """A named type the PDB created.  Built-ins live at the ROOT category
    (``/int`` is an IntegerDataType there), so the category filter alone
    never caught them; pointers and arrays are derived from their referents."""
    if isinstance(dt, (kinds["builtin"], kinds["pointer"], kinds["array"])):
        return False
    elements = list(dt.getCategoryPath().getPathElements())
    return not (elements and elements[0] in SKIP_ROOT_CATEGORIES)


def _pdb_types(source, kinds=None):
    """Data types the PDB analyzer created: everything outside built-ins."""
    kinds = kinds or _type_kinds()
    return [dt for dt in source.getDataTypeManager().getAllDataTypes()
            if is_transferable(dt, kinds)]


def stage_under_prefix(types, staging, prefix, monitor, handler, kinds=None):
    """Add ``types`` to the empty ``staging`` manager, then move every
    category and root-level type under ``prefix``.  Moving inside one manager
    re-homes the references with the types, so the staged graph refers only
    to prefixed types.  Returns the staged types under ``prefix``."""
    kinds = kinds or _type_kinds()
    tx = staging.startTransaction("stage PDB types under " + str(prefix))
    staged = False
    try:
        for dt in types:
            staging.addDataType(dt, handler)
        root = staging.getRootCategory()
        head = list(prefix.getPathElements())[0]
        if root.getCategory(head) is not None:
            raise SystemExit("source already has a category /{}; choose another "
                             "--category".format(head))
        prefix_category = staging.createCategory(prefix)
        for category in list(root.getCategories()):
            if category.getName() != head:
                prefix_category.moveCategory(category, monitor)
        for dt in list(root.getDataTypes()):
            if is_transferable(dt, kinds):
                prefix_category.moveDataType(dt, handler)
        staged = True
    finally:
        staging.endTransaction(tx, staged)
    return [dt for dt in staging.getAllDataTypes()
            if is_transferable(dt, kinds)
            and prefix.isAncestorOrSelf(dt.getCategoryPath())]


def transfer(staged, dtm, handler):
    """Add the staged types to ``dtm``; ``(added, kept)``.  A type counts as
    added when its path did not exist in the target BEFORE this transfer
    (a JPype proxy is never ``is`` the manager, so identity cannot tell)."""
    existed = {str(dt.getPathName()) for dt in staged
               if dtm.getDataType(dt.getCategoryPath(), dt.getName()) is not None}
    for dt in staged:
        dtm.addDataType(dt, handler)
    added = sum(1 for dt in staged if str(dt.getPathName()) not in existed)
    return added, len(staged) - added


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--source", default=SOURCE_PATH)
    ap.add_argument("--archive", help="write a .gdt archive of the source's types")
    ap.add_argument("--target", help="program path to add the types to")
    ap.add_argument("--category", default="/PDB_1_10_155",
                    help="category prefix in the target (default /PDB_1_10_155)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    if not args.archive and not args.target:
        ap.error("give --archive and/or --target")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA_DIR)
    launcher.add_vmargs("-Xmx8g")
    launcher.start()
    from ghidra.program.model.data import (CategoryPath, DataTypeConflictHandler,
                                           FileDataTypeManager,
                                           StandAloneDataTypeManager)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.io
    import java.lang

    monitor = ConsoleTaskMonitor()
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()
        consumer = java.lang.Object()
        source = open_program(find_program(root, args.source), consumer, monitor, write=False)
        try:
            types = _pdb_types(source)
            kinds = collections.Counter(type(dt).__name__ for dt in types)
            print("source {}: {} data types {}".format(
                args.source, len(types), dict(kinds.most_common(6))))
            if args.archive:
                archive_path = Path(args.archive).resolve()
                if archive_path.exists():
                    raise SystemExit("refusing to overwrite " + str(archive_path))
                archive_path.parent.mkdir(parents=True, exist_ok=True)
                archive = FileDataTypeManager.createFileArchive(java.io.File(str(archive_path)))
                tx = archive.startTransaction("import PDB types")
                filled = False
                try:
                    for dt in types:
                        archive.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
                    filled = True
                finally:
                    if not archive.endTransaction(tx, filled) and filled:
                        raise RuntimeError("transaction did not commit; nothing was saved")
                archive.save()
                archive.close()
                print("archive -> {} ({} types)".format(archive_path, len(types)))
            if args.target:
                target_file = find_program(root, args.target)
                target = open_program(target_file, consumer, monitor, write=args.apply)
                try:
                    dtm = target.getDataTypeManager()
                    before = dtm.getDataTypeCount(True)
                    if not args.apply:
                        print("DRY-RUN {}: would add up to {} types under {} "
                              "(target has {} now)".format(
                                  args.target, len(types), args.category, before))
                    else:
                        prefix = CategoryPath(args.category)
                        if prefix.isRoot():
                            raise SystemExit("--category must not be the root")
                        staging = StandAloneDataTypeManager(
                            "pdb-transfer",
                            source.getDataTypeManager().getDataOrganization())
                        try:
                            staged = stage_under_prefix(
                                types, staging, prefix, monitor,
                                DataTypeConflictHandler.DEFAULT_HANDLER)
                            tx = target.startTransaction("Add PDB-derived data types")
                            commit = False
                            try:
                                added, kept = transfer(
                                    staged, dtm, DataTypeConflictHandler.KEEP_HANDLER)
                                commit = True
                            finally:
                                end_outer_transaction(target, tx, commit,
                                                      "PDB type transfer")
                        finally:
                            staging.close()
                        target.save("PDB-derived data types from 1.10.155", monitor)
                        print("APPLIED {}: {} -> {} types ({} added, {} kept existing)".format(
                            args.target, before, dtm.getDataTypeCount(True), added, kept))
                finally:
                    target.release(consumer)
        finally:
            source.release(consumer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
