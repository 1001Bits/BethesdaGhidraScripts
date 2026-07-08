#!/usr/bin/env python3
"""Apply a community IDA OG name-port to a Ghidra Fallout 4 OG program.

Input: ``fallout4_og_funcs.json`` -- ``{image_base, functions:[{start,end,name}]}``
-- a ~266k comprehensive OG (1.10.163) function-name set with full MSVC-mangled
names (each encodes class::method + return/params).  Applied through Ghidra's
Microsoft demangler, so functions get real names AND typed signatures, far
exceeding the byte-sig port's coverage.

Dry-run by default; ``--apply`` writes + saves.  Conservative: only renames
functions whose current name is a FUN_/sub_/thunk_ placeholder unless
``--overwrite`` is given.  ``sub_``/``nullsub`` source names are skipped.

Usage:
  python apply_og_names.py <project_dir> <project_name> <program_path> \
      <funcs_json> [--apply] [--overwrite] [--max N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GHIDRA_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"

_PLACEHOLDER = ("FUN_", "sub_", "thunk_FUN_", "thunk_sub_")


def _resolve_program(project, program_path):
    pd = project.getProjectData()
    df = pd.getFile(program_path) if program_path.startswith("/") else None
    if df is None:
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

        df = walk(pd.getRootFolder())
    return df


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("program_path")
    ap.add_argument("funcs_json")
    ap.add_argument("--apply", action="store_true", help="write + save (default dry-run)")
    ap.add_argument("--overwrite", action="store_true",
                    help="replace any existing name, not just placeholders")
    ap.add_argument("--create-missing", action="store_true",
                    help="create a function where Ghidra has none (recovers "
                         "functions its analysis missed) before naming")
    ap.add_argument("--max", type=int, default=0, help="limit to first N functions")
    args = ap.parse_args()

    doc = json.load(open(args.funcs_json, encoding="utf-8"))
    json_base = int(doc["image_base"])
    funcs = doc["functions"]
    if args.max:
        funcs = funcs[:args.max]
    print("json image_base=0x%X  functions=%d" % (json_base, len(funcs)))

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.cmd.label import DemanglerCmd
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    with pyghidra.open_project(pdir, pname, create=False) as project:
        df = _resolve_program(project, args.program_path)
        if df is None:
            print("ERROR: program not found: %s" % args.program_path)
            sys.exit(3)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, True, False, monitor)
        try:
            base = program.getImageBase().getOffset()
            space = program.getAddressFactory().getDefaultAddressSpace()
            fm = program.getFunctionManager()
            mem = program.getMemory()
            st = {"total": 0, "applied": 0, "no_func": 0, "skip_named": 0,
                  "skip_noise": 0, "demangle_fail": 0, "created": 0}

            tx = program.startTransaction("apply OG names") if args.apply else None
            try:
                for f in funcs:
                    st["total"] += 1
                    name = f.get("name") or ""
                    if not name or name.startswith(("sub_", "nullsub", "j_")):
                        st["skip_noise"] += 1
                        continue
                    rva = int(f["start"]) - json_base
                    addr = space.getAddress(base + rva)
                    func = fm.getFunctionAt(addr)
                    if func is None:
                        # recover a function Ghidra's analysis missed
                        blk = mem.getBlock(addr)
                        if (args.apply and args.create_missing and blk is not None
                                and blk.isExecute() and blk.isInitialized()):
                            if CreateFunctionCmd(addr).applyTo(program, monitor):
                                func = fm.getFunctionAt(addr)
                                if func is not None:
                                    st["created"] += 1
                        if func is None:
                            st["no_func"] += 1
                            continue
                    cur = func.getName()
                    if not args.overwrite and not cur.startswith(_PLACEHOLDER):
                        st["skip_named"] += 1
                        continue
                    if not args.apply:
                        st["applied"] += 1
                        continue
                    # demangle + apply (name + signature); fall back to raw label
                    cmd = DemanglerCmd(addr, name)
                    if cmd.applyTo(program, monitor):
                        st["applied"] += 1
                    else:
                        try:
                            func.setName(name, SourceType.IMPORTED)
                            st["applied"] += 1
                        except Exception:  # noqa: BLE001
                            st["demangle_fail"] += 1
            finally:
                if tx is not None:
                    program.endTransaction(tx, True)
            if args.apply and st["applied"]:
                program.save("apply OG names", monitor)
        finally:
            program.release(consumer)

    mode = "APPLIED" if args.apply else "DRY-RUN"
    print("%s: %d/%d names placed  (created %d missing funcs, no-func %d, "
          "skip-already-named %d, skip-noise %d, fail %d)"
          % (mode, st["applied"], st["total"], st["created"], st["no_func"],
             st["skip_named"], st["skip_noise"], st["demangle_fail"]))
    if not args.apply:
        print("  re-run with --apply to write + save (and --overwrite to replace "
              "byte-sig names).")


if __name__ == "__main__":
    main()
