#!/usr/bin/env python3
"""Offline verification of sf.csv anchors.

Reads:
  - scripts/commonlibsf/refs/sf116_commonlib_names.csv  (vtable VAs per class)
  - scripts/commonlibsf/refs/sf116_named_from_combined_final.csv (VA -> name dump)
  - Starfield.exe binary (to read vtable slot pointers directly)

For each anchor (class, method, slot):
  - Look up vtable VA from class name
  - Read 8-byte pointer at vtable VA + slot*8 in the binary
  - Look up that pointer's function name in the named-funcs CSV
  - Compare to expected method name

Result: pass/drift per anchor.
"""
from __future__ import annotations

import csv
import struct
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent

SF_EXE        = Path(r"C:/Games/Starfield 1.16.236/Starfield.exe")
ANCHORS_CSV   = REPO_DIR / "scripts" / "commonlibsf" / "anchors" / "sf.csv"
VTBL_NAMES    = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
NAMED_DUMP    = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_named_from_combined_final.csv"

MAX_SCAN_SLOTS = 600


def parse_pe(path):
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    opt_sz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    sects_off = opt + opt_sz
    n_sec = struct.unpack_from("<H", data, coff + 2)[0]
    sects = []
    for i in range(n_sec):
        so = sects_off + i * 40
        vaddr = struct.unpack_from("<I", data, so + 12)[0]
        vsize = struct.unpack_from("<I", data, so + 8)[0]
        rsize = struct.unpack_from("<I", data, so + 16)[0]
        rptr  = struct.unpack_from("<I", data, so + 20)[0]
        sects.append((vaddr, max(vsize, rsize), rptr))
    return image_base, sects, data


def va_to_file(sects, va, image_base):
    rva = va - image_base
    for vaddr, size, rptr in sects:
        if vaddr <= rva < vaddr + size:
            return rptr + (rva - vaddr)
    return None


def read_q(data, sects, va, image_base):
    f = va_to_file(sects, va, image_base)
    if f is None:
        return None
    return struct.unpack_from("<Q", data, f)[0]


def main():
    # Load named-functions dump (VA -> name)
    name_by_va = {}
    with open(NAMED_DUMP, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                name_by_va[int(row["target_va"], 16)] = row["name"]
            except (KeyError, ValueError):
                continue
    print(f"Loaded {len(name_by_va)} named functions from dump")

    # Load vtable VAs (class -> VA)
    vtbl_by_name = {}
    with open(VTBL_NAMES, encoding="utf-8") as f:
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
    print(f"Loaded {len(anchors)} anchors\n")

    # Parse PE
    image_base, sects, data = parse_pe(SF_EXE)

    passed = 0
    drifts = []
    for cls, method, slot in anchors:
        vtbl_va = vtbl_by_name.get(cls) or vtbl_by_name.get(f"RE::{cls}")
        if vtbl_va is None:
            print(f"  [SKIP] {cls}::{method} — no vtable in CSV")
            continue
        slot_va = vtbl_va + slot * 8
        ptr = read_q(data, sects, slot_va, image_base)
        if ptr is None:
            print(f"  [SKIP] {cls}::{method} — slot 0x{slot:x} unreadable")
            continue
        actual_full = name_by_va.get(ptr, f"<unnamed @ 0x{ptr:x}>")
        actual_leaf = actual_full.split("::")[-1]
        if actual_leaf == method:
            print(f"  [PASS] {cls}::{method} @ slot 0x{slot:x} -> {actual_full}")
            passed += 1
            continue
        # Drift: scan nearby slots for the method
        found_at = None
        for s in range(MAX_SCAN_SLOTS):
            p2 = read_q(data, sects, vtbl_va + s * 8, image_base)
            if p2 is None:
                continue
            n = name_by_va.get(p2)
            if n and n.split("::")[-1] == method:
                found_at = s
                break
        delta = (found_at - slot) if found_at is not None else None
        marker = f"(expected at slot 0x{found_at:x}, delta={delta:+d})" if found_at is not None else "(expected not found)"
        print(f"  [DRIFT] {cls}::{method} @ slot 0x{slot:x} -> {actual_full}  {marker}")
        drifts.append((cls, method, slot, found_at, actual_full))

    print(f"\nSummary: {passed} pass, {len(drifts)} drift")
    if drifts:
        print("\nDrift details (could indicate need for SF shift map):")
        for cls, method, slot, found, actual in drifts:
            delta = (found - slot) if found is not None else None
            print(f"  {cls}::{method}: anchor 0x{slot:x} = {actual}; "
                  f"expected at {hex(found) if found is not None else '?'} (delta {delta:+d})" if found is not None
                  else f"  {cls}::{method}: anchor 0x{slot:x} = {actual}; expected not found in first {MAX_SCAN_SLOTS} slots")


if __name__ == "__main__":
    main()
