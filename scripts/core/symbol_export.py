#!/usr/bin/env python3
"""Export an enriched Ghidra program's symbols to distributable formats.

Produces, for a program that this pipeline (or any analysis) has already
named/typed, three sibling files in ``out_dir``:

  - ``<module>.symbols.json`` -- full map: image base + functions / data
    labels / vtables, each with module-relative RVA (and optional prototype).
  - ``<module>.map``          -- plain ``<rva>  <name>`` lines, sorted by RVA
    (human-readable; greppable; loads into many tools).
  - ``<module>.dd64``         -- x64dbg JSON database (``labels`` array, keyed
    by module + RVA) that x64dbg imports directly (File > Database > Import).

This is the LIGHT alternative to generating a real PDB (cf. alandtse/pdbgen):
no LLVM, no native toolchain, pure pyghidra read-pass. It does NOT add any
analysis -- it serializes what Ghidra already knows. READ-ONLY: the program is
opened non-upgrade, non-exclusive and never modified.

Usage:
  python symbol_export.py <project_dir> <project_name> <program_path> <out_dir>
                          [--module name.exe] [--signatures]

``program_path`` is the in-project path (e.g. ``/Starfield/Starfield 1.16.236``)
or just a program name; resolution mirrors dump_named_funcs.py.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = REPO_DIR / "tools" / "ghidra"

# Default-generated names carry no information -- drop them from every output.
# Checked against BOTH the leaf and the full (namespaced) name, so a label like
# ``switchD_1402aa534::switchdataD_...`` is caught via its namespace root.
_NOISE_PREFIXES = (
    "FUN_", "thunk_FUN_", "sub_", "LAB_", "DAT_", "UNK_", "SUB_",
    "switchD_", "switchdataD_", "caseD_", "PTR_", "u_", "s_", "j_",
)


def _is_noise(name: str) -> bool:
    return name.startswith(_NOISE_PREFIXES)


def _classify_label(name: str) -> str:
    """Bucket a non-function label for the JSON output."""
    if name.startswith("VTABLE_"):
        return "vtable"
    if name.startswith(("RTTI_", "NiRTTI_")):
        return "rtti"
    return "data"


def _resolve_program(project, program_path, monitor):
    import java.lang  # noqa: F401
    pd = project.getProjectData()
    df = None
    if program_path.startswith("/"):
        df = pd.getFile(program_path)
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


def collect(program, want_sigs=False):
    """Walk the program once; return (image_base, functions, labels)."""
    from ghidra.program.model.symbol import SourceType, SymbolType

    image_base = program.getImageBase().getOffset()
    default_space = program.getAddressFactory().getDefaultAddressSpace()

    def rva_of(addr):
        if addr is None or addr.getAddressSpace() != default_space:
            return None
        return addr.getOffset() - image_base

    # --- functions -------------------------------------------------------
    functions = []
    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):
        leaf = func.getName()
        if _is_noise(leaf):
            continue
        rva = rva_of(func.getEntryPoint())
        if rva is None or rva < 0:
            continue
        entry = {"rva": rva, "name": func.getName(True)}
        if want_sigs:
            try:
                entry["proto"] = func.getSignature().getPrototypeString(False)
            except Exception:  # noqa: BLE001
                pass
        functions.append(entry)

    # --- data / vtable / rtti labels ------------------------------------
    # Non-default symbols that are not functions: globals, VTABLE_*, RTTI_*,
    # singletons, etc.  Source==DEFAULT means Ghidra auto-named it -> skip.
    labels = []
    st = program.getSymbolTable()
    seen = set()
    for sym in st.getAllSymbols(False):  # False = exclude dynamic/default
        if sym.getSymbolType() == SymbolType.FUNCTION:
            continue
        if sym.getSource() == SourceType.DEFAULT:
            continue
        leaf = sym.getName()
        full = sym.getName(True)
        if _is_noise(leaf) or _is_noise(full):
            continue
        rva = rva_of(sym.getAddress())
        if rva is None or rva < 0:
            continue
        key = (rva, full)
        if key in seen:
            continue
        seen.add(key)
        labels.append({"rva": rva, "name": full,
                       "kind": _classify_label(leaf)})

    functions.sort(key=lambda e: e["rva"])
    labels.sort(key=lambda e: e["rva"])
    return image_base, functions, labels


def write_outputs(out_dir, module, image_base, functions, labels):
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, os.path.splitext(module)[0])

    # 1) JSON symbol map -------------------------------------------------
    vtables = [l for l in labels if l["kind"] == "vtable"]
    data_lbls = [l for l in labels if l["kind"] != "vtable"]
    doc = {
        "module": module,
        "image_base": "0x%X" % image_base,
        "counts": {"functions": len(functions),
                   "labels": len(data_lbls), "vtables": len(vtables)},
        "functions": [{"rva": "0x%X" % f["rva"], **{k: v for k, v in f.items()
                                                    if k != "rva"}}
                      for f in functions],
        "labels": [{"rva": "0x%X" % l["rva"], "name": l["name"],
                    "kind": l["kind"]} for l in data_lbls],
        "vtables": [{"rva": "0x%X" % l["rva"], "name": l["name"]}
                    for l in vtables],
    }
    json_path = stem + ".symbols.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)

    # 2) Plain .map ------------------------------------------------------
    map_path = stem + ".map"
    rows = ([(f["rva"], f["name"]) for f in functions]
            + [(l["rva"], l["name"]) for l in labels])
    rows.sort()
    with open(map_path, "w", encoding="utf-8") as fh:
        fh.write("; %s  image_base=0x%X  rva<TAB>name\n" % (module, image_base))
        for rva, name in rows:
            fh.write("0x%08X\t%s\n" % (rva, name))

    # 3) x64dbg .dd64 ----------------------------------------------------
    # x64dbg database JSON: labels keyed by (module, RVA-as-hex-string).
    # x64dbg matches the module name case-insensitively against its modules
    # list, and treats "address" as the module-relative RVA.
    mod = module.lower()
    dd_labels = [{"module": mod, "address": "0x%X" % rva,
                  "manual": True, "text": name}
                 for rva, name in rows]
    dd_path = stem + ".dd64"
    with open(dd_path, "w", encoding="utf-8") as fh:
        json.dump({"labels": dd_labels}, fh, indent=1)

    return json_path, map_path, dd_path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("program_path")
    ap.add_argument("out_dir")
    ap.add_argument("--module", default=None,
                    help="module name for x64dbg (default: program exe name)")
    ap.add_argument("--signatures", action="store_true",
                    help="include function prototypes in the JSON (slower)")
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
        df = _resolve_program(project, args.program_path, monitor)
        if df is None:
            print("ERROR: program not found: %s" % args.program_path)
            sys.exit(3)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, False, False, monitor)
        try:
            module = args.module
            if not module:
                exe = program.getExecutablePath() or program.getName()
                module = os.path.basename(exe.replace("\\", "/")) or program.getName()
                if not os.path.splitext(module)[1]:
                    module += ".exe"
            image_base, functions, labels = collect(program, args.signatures)
            jp, mp, dp = write_outputs(args.out_dir, module, image_base,
                                       functions, labels)
        finally:
            program.release(consumer)

    print("Module: %s  (image_base=0x%X)" % (module, image_base))
    print("  functions: %d   labels: %d" % (len(functions), len(labels)))
    print("  wrote:\n    %s\n    %s\n    %s" % (jp, mp, dp))


if __name__ == "__main__":
    main()
