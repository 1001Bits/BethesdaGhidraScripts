#!/usr/bin/env python3
"""Expand vtable labels into per-slot function names.

For each vtable VA from sf116_commonlib_names.csv (kind=vtbl):
  - Read consecutive 8-byte pointers from the binary memory at that VA
  - Stop when next pointer is not into .text, is zero, or is the next vtable
  - Apply name '<ClassName>::Func<N>' to each slot target

Output: scripts/commonlibsf/refs/sf116_vtable_func_names.csv
  columns: target_va, name

Requires the program to be open in pyghidra (read pointers from memory).
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import List, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "ExampleProject"
PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

IN_CSV       = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
OUT_CSV      = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_vtable_func_names.csv"

# Default max slots if we can't detect end-of-vtable.
# 1000 is well above real vtable sizes (max real in Bethesda games is ~400)
# yet termination conditions (zero, non-text, next-known-vtable) reliably
# stop us within real bounds.
DEFAULT_MAX_SLOTS = 1000


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Reading vtable rows from {IN_CSV}")
    vtable_rows: List[Tuple[int, str]] = []
    with open(IN_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                vtable_rows.append((int(row["target_va"], 16), row["name"]))
    print(f"  {len(vtable_rows)} vtables to expand")

    # Build a quick set of all "is a vtable" VAs for end-detection
    vtable_va_set = {v for v, _ in vtable_rows}

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        if domain_file is None:
            print(f"ERROR: program not found: {PROGRAM_PATH}")
            sys.exit(2)

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            memory = program.getMemory()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()

            # Determine .text bounds for "is this a function pointer?" check
            text_start = None
            text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f"  .text bounds: 0x{text_start:x} - 0x{text_end:x}")

            n_vtables_done = 0
            n_slots_named = 0
            n_unique_targets = 0
            seen_targets = set()
            OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

            with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name"])
                for vt_va, class_name in vtable_rows:
                    addr = default_space.getAddress(vt_va)
                    for slot_idx in range(DEFAULT_MAX_SLOTS):
                        try:
                            ptr_addr = default_space.getAddress(vt_va + slot_idx * 8)
                            ptr_val = memory.getLong(ptr_addr) & 0xFFFFFFFFFFFFFFFF
                        except Exception:
                            break
                        # End conditions:
                        # 1. Zero pointer
                        if ptr_val == 0:
                            break
                        # 2. Points outside .text (typically next entry is RTTI or next class data)
                        if ptr_val < text_start or ptr_val >= text_end:
                            break
                        # 3. We've hit the start of another known vtable
                        next_va = vt_va + (slot_idx + 1) * 8
                        if slot_idx > 0 and next_va in vtable_va_set:
                            # The next slot is a different vtable — stop after this slot
                            w.writerow([f"0x{ptr_val:x}", f"{class_name}::Func{slot_idx}"])
                            n_slots_named += 1
                            if ptr_val not in seen_targets:
                                seen_targets.add(ptr_val)
                                n_unique_targets += 1
                            break
                        # Valid slot
                        w.writerow([f"0x{ptr_val:x}", f"{class_name}::Func{slot_idx}"])
                        n_slots_named += 1
                        if ptr_val not in seen_targets:
                            seen_targets.add(ptr_val)
                            n_unique_targets += 1
                    n_vtables_done += 1
                    if n_vtables_done % 1000 == 0:
                        print(f"  {n_vtables_done}/{len(vtable_rows)}  slots={n_slots_named}  unique={n_unique_targets}", flush=True)
            print(f"\n=== Summary ===")
            print(f"  vtables expanded:     {n_vtables_done}")
            print(f"  total slot mappings:  {n_slots_named}")
            print(f"  unique target VAs:    {n_unique_targets}")
            print(f"  wrote {OUT_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
