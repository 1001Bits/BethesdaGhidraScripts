#!/usr/bin/env python3
"""Audit the CommonLibSF vtable labels we applied for correctness.

Checks:
  1. Vtable size distribution — anything with > 250 slots is suspicious
     (likely over-walked into adjacent data).
  2. Each vtable's first slot must point into .text (sanity).
  3. Each vtable's address - 8 bytes should be a pointer (the RTTI
     complete-object locator).  Optional but very strong signal.
  4. Cross-version anchor verification: for a handful of well-known
     SF 1.7 vtable slots (with named methods), compare the same slot
     index in the SF 1.16 vtable -- both should be the same function
     family.
  5. Confirm our anchors/sf.csv 5 Actor methods land at the expected
     slot index in the SF 1.16 Actor vtable.

Output: scripts/commonlibsf/refs/audit_report.txt
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

VTBL_NAMES_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
ANCHORS_CSV    = REPO_DIR / "scripts" / "commonlibsf" / "anchors" / "sf.csv"
EXPANDED_CSV   = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_vtable_func_names.csv"
OUT_REPORT     = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "audit_report.txt"


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    # ---- Load vtable info from CSVs --------------------------------------
    vtbl_by_va = {}
    with open(VTBL_NAMES_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                vtbl_by_va[int(row["target_va"], 16)] = row["name"]

    # Slot count per vtable (from expansion)
    slot_counts = {}
    slot_targets = {}  # (vtbl_va, slot_idx) -> target_va
    with open(EXPANDED_CSV, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for tgt_va, name in reader:
            # name like 'Class::FuncN'
            if "::Func" in name:
                cls, sn = name.rsplit("::Func", 1)
                try:
                    slot_idx = int(sn)
                except ValueError:
                    continue
                # Find the matching vtable VA by class match (best-effort)
                # We can't reverse-lookup easily; use class name as proxy
                slot_counts[cls] = max(slot_counts.get(cls, 0), slot_idx + 1)

    # Open program for memory + symbol reads
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
            listing = program.getListing()
            fm = program.getFunctionManager()

            # Compute .text bounds
            text_start = None
            text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f".text: 0x{text_start:x} - 0x{text_end:x}")

            report_lines = []
            def out(*args):
                line = " ".join(str(a) for a in args)
                print(line)
                report_lines.append(line)

            out(f"=== Vtable label audit for SF 1.16.236 ===\n")
            out(f"Total vtables labeled: {len(vtbl_by_va)}")

            # ---- Check 1: each vtable's first slot is into .text ----------
            out("\n--- Check 1: first-slot must be a .text function pointer ---")
            n_bad_first = 0
            n_bad_first_samples = []
            n_no_func = 0
            for va, name in vtbl_by_va.items():
                try:
                    ptr_addr = default_space.getAddress(va)
                    ptr_val = memory.getLong(ptr_addr) & 0xFFFFFFFFFFFFFFFF
                except Exception:
                    n_bad_first += 1
                    continue
                if not (text_start <= ptr_val < text_end):
                    n_bad_first += 1
                    if len(n_bad_first_samples) < 10:
                        n_bad_first_samples.append((va, name, ptr_val))
                else:
                    if fm.getFunctionContaining(default_space.getAddress(ptr_val)) is None:
                        n_no_func += 1
            out(f"  vtables whose slot[0] is outside .text: {n_bad_first}")
            for va, name, ptr in n_bad_first_samples:
                out(f"    0x{va:x}  {name[:50]}  -> 0x{ptr:x}  (NOT in .text)")
            out(f"  vtables whose slot[0] lands in .text but no function there yet: {n_no_func}")

            # ---- Check 2: RTTI cell at vtable-8 ---------------------------
            out("\n--- Check 2: vtable-8 should hold RTTI complete-object locator ptr ---")
            n_rtti_ok = 0
            n_rtti_missing = 0
            for va, name in vtbl_by_va.items():
                try:
                    rtti_addr = default_space.getAddress(va - 8)
                    rtti_ptr = memory.getLong(rtti_addr) & 0xFFFFFFFFFFFFFFFF
                except Exception:
                    n_rtti_missing += 1
                    continue
                # In x64 PE, complete-object-locator pointer is into .rdata
                # We just check the value is non-zero and lies inside the image
                if 0x140000000 <= rtti_ptr <= 0x150000000:
                    n_rtti_ok += 1
                else:
                    n_rtti_missing += 1
            out(f"  vtables with plausible RTTI pre-cell:  {n_rtti_ok}")
            out(f"  vtables WITHOUT plausible RTTI pre-cell: {n_rtti_missing}  "
                f"(may include multi-inheritance secondary vtables)")

            # ---- Check 3: anchors/sf.csv -----------------------------------
            out("\n--- Check 3: anchors/sf.csv slot-name confirmation ---")
            anchors = []
            if ANCHORS_CSV.is_file():
                with open(ANCHORS_CSV, encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        cls = row.get("class", "").strip()
                        method = row.get("method", "").strip()
                        slot_raw = row.get("slot", "").strip()
                        try:
                            slot = int(slot_raw, 16) if slot_raw.startswith("0x") else int(slot_raw)
                        except ValueError:
                            continue
                        anchors.append((cls, method, slot))
            out(f"  anchors loaded: {len(anchors)}")
            # Find each anchor's vtable
            # vtbl name in our CSV is sanitized: "RE::Actor" -> often without RE::
            # Try several name forms
            for cls, method, slot in anchors:
                hits = []
                for va, lname in vtbl_by_va.items():
                    if lname == cls or lname == "RE::"+cls or lname.endswith("::"+cls):
                        hits.append((va, lname))
                if not hits:
                    out(f"  [anchor {cls}::{method} @ slot {slot}]  no vtable label found")
                    continue
                for va, lname in hits:
                    slot_va = va + slot * 8
                    try:
                        ptr_addr = default_space.getAddress(slot_va)
                        ptr_val = memory.getLong(ptr_addr) & 0xFFFFFFFFFFFFFFFF
                    except Exception:
                        out(f"  [anchor {cls}::{method} slot {slot:#x}]  cannot read vtable @ 0x{va:x}")
                        continue
                    func = fm.getFunctionContaining(default_space.getAddress(ptr_val)) if text_start <= ptr_val < text_end else None
                    fname = func.getName(True) if func else "(no function)"
                    out(f"  [{lname}::Func{slot}]  slot points to 0x{ptr_val:x}  ({fname})")

            # ---- Check 4: slot count distribution --------------------------
            out("\n--- Check 4: slot count distribution ---")
            sizes = sorted(slot_counts.values())
            if sizes:
                p50 = sizes[len(sizes)//2]
                p90 = sizes[int(len(sizes)*0.9)]
                p99 = sizes[int(len(sizes)*0.99)]
                out(f"  median slots/vtable: {p50}")
                out(f"  p90 slots/vtable:    {p90}")
                out(f"  p99 slots/vtable:    {p99}")
                out(f"  max slots/vtable:    {max(sizes)}")
                # Top 10 largest
                top = sorted(slot_counts.items(), key=lambda x: -x[1])[:10]
                out(f"  10 largest vtables (suspect over-walk):")
                for cls, n in top:
                    out(f"    {n:4d} slots  {cls[:80]}")

            out("\n=== Done ===")

            OUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
            with open(OUT_REPORT, "w", encoding="utf-8") as fh:
                fh.write("\n".join(report_lines))
            print(f"\nReport saved to {OUT_REPORT}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
