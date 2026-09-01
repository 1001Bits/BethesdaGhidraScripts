#!/usr/bin/env python3
"""Expand the new RTTI-discovered vtables (rtti-only, not in CommonLibSF)
into Class::FuncN slot labels."""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "ExampleProject"
PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

RTTI_VTBL_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_rtti_vtables.csv"
EXISTING_VTBL = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
OUT_FUNC_CSV  = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_rtti_func_names.csv"

DEFAULT_MAX_SLOTS = 1000


def main():
    # Load RTTI vtables: focus on 'rtti-only' (not in CommonLibSF).
    new_vtables = {}
    all_rtti_va = set()
    with open(RTTI_VTBL_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            va = int(row["vtable_va"], 16)
            all_rtti_va.add(va)
            if row["source"] == "rtti-only":
                new_vtables[va] = row["class_name"]

    # CommonLibSF vtable VAs (also serve as termination signal)
    commonlib_vtables = set()
    with open(EXISTING_VTBL, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                commonlib_vtables.add(int(row["target_va"], 16))

    all_vtable_set = commonlib_vtables | all_rtti_va
    print(f"New vtables to expand: {len(new_vtables)}")
    print(f"Total vtable VAs (termination set): {len(all_vtable_set)}")

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
            memory = program.getMemory()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()

            text_start = text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f".text: 0x{text_start:x} - 0x{text_end:x}")

            n_done = 0
            n_slots = 0
            n_unique = 0
            seen = set()
            with open(OUT_FUNC_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name"])
                for vt_va, cls in new_vtables.items():
                    for slot_idx in range(DEFAULT_MAX_SLOTS):
                        slot_va = vt_va + slot_idx * 8
                        try:
                            ptr_val = memory.getLong(default_space.getAddress(slot_va)) & 0xFFFFFFFFFFFFFFFF
                        except Exception:
                            break
                        if ptr_val == 0:
                            break
                        if not (text_start <= ptr_val < text_end):
                            break
                        next_va = vt_va + (slot_idx + 1) * 8
                        if slot_idx > 0 and next_va in all_vtable_set:
                            w.writerow([f"0x{ptr_val:x}", f"{cls}::Func{slot_idx}"])
                            n_slots += 1
                            if ptr_val not in seen:
                                seen.add(ptr_val); n_unique += 1
                            break
                        w.writerow([f"0x{ptr_val:x}", f"{cls}::Func{slot_idx}"])
                        n_slots += 1
                        if ptr_val not in seen:
                            seen.add(ptr_val); n_unique += 1
                    n_done += 1
                    if n_done % 500 == 0:
                        print(f"  {n_done}/{len(new_vtables)}  slots={n_slots}  unique={n_unique}", flush=True)

            print(f"\n=== Summary ===")
            print(f"  expanded vtables: {n_done}")
            print(f"  slot mappings:    {n_slots}")
            print(f"  unique targets:   {n_unique}")
            print(f"  wrote {OUT_FUNC_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
