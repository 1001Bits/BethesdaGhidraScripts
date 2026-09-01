#!/usr/bin/env python3
"""Find class constructors by locating functions that write a labeled
vtable address to the instance pointer (rcx) and emit
(target_va, name=<ClassName>::<ClassName>) for each one.

In x64 MSVC, a constructor's prologue typically contains:
    lea  rax, [vtable_va]
    mov  qword ptr [rcx], rax     ; this->__vftable = vtable
    ...
or with RIP-relative directly:
    lea  rcx, [vtable_va]
    mov  qword ptr [rdi], rcx     ; depending on alloc

A function that writes the vtable address to memory is most likely a
constructor or an init helper.  We dedup by VA: if multiple writes target
the same function, we still rename only once.

Output: scripts/commonlibsf/refs/sf116_constructors.csv
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from collections import defaultdict

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "ExampleProject"
PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

VTBL_NAMES_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
OUT_CSV        = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_constructors.csv"


def main():
    # Load (vtable VA -> class name)
    vtbl_by_va = {}
    with open(VTBL_NAMES_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                vtbl_by_va[int(row["target_va"], 16)] = row["name"]
    print(f"Loaded {len(vtbl_by_va)} vtable -> class mappings")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            fm = program.getFunctionManager()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            ref_mgr = program.getReferenceManager()

            # For each vtable VA: find all references TO it
            # Those references are from the constructor / init helpers
            n_vtables_done = 0
            n_xrefs_total = 0
            ctor_candidates = defaultdict(set)  # func_va -> set of class names

            for vt_va, cls_name in vtbl_by_va.items():
                addr = default_space.getAddress(vt_va)
                refs = ref_mgr.getReferencesTo(addr)
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    func = fm.getFunctionContaining(from_addr)
                    if func is None:
                        continue
                    fn_va = func.getEntryPoint().getOffset()
                    ctor_candidates[fn_va].add(cls_name)
                    n_xrefs_total += 1
                n_vtables_done += 1
                if n_vtables_done % 2000 == 0:
                    print(f"  {n_vtables_done}/{len(vtbl_by_va)}  xrefs={n_xrefs_total}  candidate_funcs={len(ctor_candidates)}", flush=True)

            print(f"\nTotal vtable xrefs: {n_xrefs_total}")
            print(f"Functions referencing a vtable: {len(ctor_candidates)}")

            # Many functions reference >1 vtable (multi-inheritance, helper).
            # Conservative: only emit functions that reference exactly ONE class's vtables.
            n_emitted = 0
            n_multi = 0
            with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name", "source"])
                for fn_va, classes in ctor_candidates.items():
                    if len(classes) != 1:
                        n_multi += 1
                        continue
                    cls = next(iter(classes))
                    # Use only the LEAF class name as constructor leaf
                    leaf = cls.split("::")[-1]
                    # Constructor naming: <Class>::<Class>
                    new_name = f"{cls}::{leaf}"
                    w.writerow([f"0x{fn_va:x}", new_name, "ctor-xref"])
                    n_emitted += 1

            print(f"\nEmitted {n_emitted} single-class constructor candidates")
            print(f"Skipped {n_multi} multi-class (likely helper/RTTI emit)")
            print(f"Wrote {OUT_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
