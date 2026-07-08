#!/usr/bin/env python3
"""Import a Caesar-ciphered IDA IDC labels file into a Ghidra program.

The community ``F4_1_10_163_IDCLabels.idc`` is ~698k ``gen_name(addr,"name")``
calls whose names are Caesar-shifted (subtract 3 per char to decode).  Decoded,
they are MSVC-mangled function / static-data names plus Hungarian-named globals.

This applies them: mangled names (``?...``) via Ghidra's demangler (name +
type/signature); plain names as labels.  The big win over the function
name-port is the ~256k named GLOBALS / static data our function-focused
pipeline misses -- so the decompiler shows ``pCurrentWarningContext`` instead of
``DAT_146a8c9c4``, which is exactly the "missing context" the analysts hit.

Dry-run by default; ``--apply`` writes + saves.  Conservative: skips addresses
that already carry a non-default name unless ``--overwrite`` (so it fills the
un-named globals without clobbering the names we already applied).

Usage:
  python apply_idc_labels.py <project_dir> <project_name> <program_path> \
      <idc_file> [--apply] [--overwrite] [--max N]
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

GHIDRA_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"
_GEN = re.compile(r'gen_name\((0x[0-9A-Fa-f]+),"([^"]*)"\)')


def _decode(s):
    return "".join(chr(ord(c) - 3) for c in s)


def parse_idc(path):
    with open(path, encoding="latin-1") as f:
        data = f.read()
    out = []
    for m in _GEN.finditer(data):
        out.append((int(m.group(1), 16), _decode(m.group(2))))
    return out


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
    ap.add_argument("idc_file")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    args = ap.parse_args()

    labels = parse_idc(args.idc_file)
    if args.max:
        labels = labels[:args.max]
    print("parsed %d labels from IDC" % len(labels))

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.cmd.label import DemanglerCmd
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
            space = program.getAddressFactory().getDefaultAddressSpace()
            mem = program.getMemory()
            symtab = program.getSymbolTable()
            st = {"total": 0, "func_demangled": 0, "data_labeled": 0,
                  "skip_named": 0, "oob": 0, "fail": 0}

            tx = program.startTransaction("apply IDC labels") if args.apply else None
            try:
                for va, name in labels:
                    st["total"] += 1
                    if not name:
                        continue
                    a = space.getAddress(va)
                    if not mem.contains(a):
                        st["oob"] += 1
                        continue
                    prim = symtab.getPrimarySymbol(a)
                    if (prim is not None and prim.getSource() != SourceType.DEFAULT
                            and not args.overwrite):
                        st["skip_named"] += 1
                        continue
                    if not args.apply:
                        key = "func_demangled" if name.startswith("?") else "data_labeled"
                        st[key] += 1
                        continue
                    try:
                        if name.startswith("?"):
                            if DemanglerCmd(a, name).applyTo(program, monitor):
                                st["func_demangled"] += 1
                            else:
                                symtab.createLabel(a, name, SourceType.IMPORTED)
                                st["data_labeled"] += 1
                        else:
                            symtab.createLabel(a, name, SourceType.IMPORTED)
                            st["data_labeled"] += 1
                    except Exception:  # noqa: BLE001
                        st["fail"] += 1
            finally:
                if tx is not None:
                    program.endTransaction(tx, True)
            placed = st["func_demangled"] + st["data_labeled"]
            if args.apply and placed:
                program.save("apply IDC labels", monitor)
        finally:
            program.release(consumer)

    mode = "APPLIED" if args.apply else "DRY-RUN"
    print("%s: demangled %d, labeled %d  (skip-already-named %d, oob %d, fail %d)"
          % (mode, st["func_demangled"], st["data_labeled"], st["skip_named"],
             st["oob"], st["fail"]))


if __name__ == "__main__":
    main()
