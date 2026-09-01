#!/usr/bin/env python3
"""Verify each anchor in scripts/commonlibsf/anchors/sf.csv against
ExampleProject.gpr's /Starfield/Starfield 1.16.236 by walking the vtable and
naming the function at the anchor's slot.

Output: prints pass/fail per anchor.  If any drift, prints the slot index
where the expected method actually lives (best-effort by name match).
"""
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

ANCHORS_CSV   = REPO_DIR / "scripts" / "commonlibsf" / "anchors" / "sf.csv"
VTBL_NAMES_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"

MAX_SCAN_SLOTS = 600


def main():
    # Load vtables from our CSV (class -> VA)
    vtbl_by_name = {}
    with open(VTBL_NAMES_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                vtbl_by_name[row["name"]] = int(row["target_va"], 16)

    # Load anchors
    anchors = []
    with open(ANCHORS_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cls = row["class"].strip()
            method = row["method"].strip()
            slot_raw = row["slot"].strip()
            try:
                slot = int(slot_raw, 16) if slot_raw.startswith("0x") else int(slot_raw)
            except ValueError:
                continue
            anchors.append((cls, method, slot))
    print(f"Loaded {len(anchors)} anchors from {ANCHORS_CSV.name}")

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
            fm = program.getFunctionManager()

            passed = 0
            failed = 0
            drifts = []
            for cls, method, slot in anchors:
                # Find vtable VA — try several name forms
                vtbl_va = None
                for cand in (cls, f"RE::{cls}", f"{cls}", cls.replace("::", "_")):
                    if cand in vtbl_by_name:
                        vtbl_va = vtbl_by_name[cand]
                        break
                if vtbl_va is None:
                    print(f"  [SKIP] {cls}::{method} @ 0x{slot:x} — no vtable in CSV")
                    continue
                slot_va = vtbl_va + slot * 8
                try:
                    ptr_val = memory.getLong(default_space.getAddress(slot_va)) & 0xFFFFFFFFFFFFFFFF
                except Exception:
                    print(f"  [SKIP] {cls}::{method} — cannot read 0x{slot_va:x}")
                    continue
                func = fm.getFunctionContaining(default_space.getAddress(ptr_val))
                if func is None:
                    print(f"  [FAIL] {cls}::{method} @ slot 0x{slot:x} -> 0x{ptr_val:x} (no function)")
                    failed += 1
                    continue
                actual_leaf = func.getName()
                expected_leaf = method
                if actual_leaf == expected_leaf:
                    print(f"  [PASS] {cls}::{method} @ slot 0x{slot:x} -> {actual_leaf} ✓")
                    passed += 1
                else:
                    # Scan nearby slots to find the expected method
                    found_at = None
                    for s in range(MAX_SCAN_SLOTS):
                        try:
                            ptr2 = memory.getLong(default_space.getAddress(vtbl_va + s * 8)) & 0xFFFFFFFFFFFFFFFF
                        except Exception:
                            break
                        f2 = fm.getFunctionContaining(default_space.getAddress(ptr2))
                        if f2 is not None and f2.getName() == expected_leaf:
                            found_at = s
                            break
                    delta = (found_at - slot) if found_at is not None else None
                    drift_note = f"(expected at slot 0x{found_at:x}, delta={delta:+d})" if found_at is not None else "(expected not found nearby)"
                    print(f"  [DRIFT] {cls}::{method} @ slot 0x{slot:x} -> {actual_leaf}  {drift_note}")
                    failed += 1
                    drifts.append((cls, method, slot, found_at, actual_leaf))

            print(f"\nSummary: {passed} pass, {failed} drift/fail")
            if drifts:
                print("\nDrift detail:")
                for cls, method, slot, found, actual in drifts:
                    print(f"  {cls}::{method}: anchor slot 0x{slot:x} actually has {actual}; expected at slot {hex(found) if found else '?'}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
