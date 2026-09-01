#!/usr/bin/env python3
"""Scan SF 1.16.236 .rdata for MSVC RTTI structures, identify EVERY
vtable in the binary, and emit a CSV of (vtable_va, class_name) that
extends beyond what CommonLibSF documents.

MSVC x64 RTTI layout (validated against the binary directly):

  CompleteObjectLocator (24 bytes, lives in .rdata):
    +0x00 u32 signature      == 1
    +0x04 u32 offset         (offset of subobject from complete object base)
    +0x08 u32 cdOffset       (constructor displacement offset)
    +0x0C u32 pTypeDescriptor   image-relative RVA -> TypeDescriptor
    +0x10 u32 pClassDescriptor  image-relative RVA -> ClassHierarchyDescriptor
    +0x14 u32 pSelf             image-relative RVA == this COL's own RVA
                                ^^^ self-reference is the strongest validator

  Vtable layout:
    [vtable_va - 8] -> CompleteObjectLocator
    [vtable_va + 0] -> first virtual fn ptr
    [vtable_va + 8] -> second ...

  TypeDescriptor:
    +0x00 ptr to type_info::vftable (same for all)
    +0x08 spare (hash, often 0)
    +0x10 char[]  mangled name, null-terminated
                  Class:  ".?AV" + reversed-namespace-parts + "@@\0"
                  Struct: ".?AU" + ... + "@@\0"

We do a brute-force scan over .rdata at 8-byte alignment, validate COL
self-pointer, and dedupe.  Then for every 8-byte aligned address q in
.rdata where (*q) points to a known COL, we treat q+8 as a vtable.

Output: scripts/commonlibsf/refs/sf116_rtti_vtables.csv
  columns: vtable_va, class_name, source

Then a second pass expands each new (not in CommonLibSF) vtable's slots
into Class::FuncN labels, producing
  scripts/commonlibsf/refs/sf116_rtti_func_names.csv
"""
from __future__ import annotations

import csv
import os
import re
import struct
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

SF_EXE        = Path(r"C:/Games/Starfield 1.16.236/Starfield.exe")
EXISTING_VTBL = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
OUT_VTBL_CSV  = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_rtti_vtables.csv"
OUT_FUNC_CSV  = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_rtti_func_names.csv"

DEFAULT_MAX_SLOTS = 1000


def parse_pe(path):
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe+4] == b"PE\x00\x00"
    coff = pe + 4
    n_sec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_sz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic == 0x20B
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    sects_off = opt + opt_sz
    sects = []
    for i in range(n_sec):
        so = sects_off + i * 40
        name = data[so:so+8].rstrip(b"\x00").decode("latin-1")
        vsize = struct.unpack_from("<I", data, so + 8)[0]
        vaddr = struct.unpack_from("<I", data, so + 12)[0]
        rsize = struct.unpack_from("<I", data, so + 16)[0]
        rptr  = struct.unpack_from("<I", data, so + 20)[0]
        chars = struct.unpack_from("<I", data, so + 36)[0]
        is_exec = bool(chars & 0x20000000)
        sects.append({
            "name": name, "vaddr": vaddr, "vsize": vsize, "rsize": rsize,
            "rptr": rptr, "exec": is_exec,
        })
    return image_base, sects, data


def find_section(sects, name):
    for s in sects:
        if s["name"] == name:
            return s
    return None


def demangle_class(mangled: str) -> str:
    """Quick MSVC class-type-descriptor demangler.

    Handles non-template names directly.  For templates (.?AV?$Foo@...),
    we fall back to a lightweight recursive parser that handles the
    common cases.
    """
    if mangled.startswith(".?AV"):
        rest = mangled[4:]
    elif mangled.startswith(".?AU"):
        rest = mangled[4:]
    elif mangled.startswith(".?AW"):  # enum class
        rest = mangled[4:]
    else:
        return mangled
    # rest should end with "@@"
    if rest.endswith("@@"):
        rest = rest[:-2]
    # Split by '@', reverse for namespace order
    parts = rest.split("@")
    # Filter empty parts (which can happen for trailing @)
    parts = [p for p in parts if p]
    if not parts:
        return "UnknownClass"
    # Names like 'BSTArray@?$@VFoo' become awkward; for non-template we just reverse.
    # Templates have '?$' inside parts which our naive split breaks.  Detect
    # and fall back to leaving the raw mangled body as a sanitized blob.
    if any("?$" in p for p in parts):
        # Template: keep raw mangled body, sanitized
        flat = rest.replace("@", "::").replace("?$", "T_").replace("?", "_")
        return flat
    return "::".join(reversed(parts))


def rva_to_file(sects, rva):
    """Map an image RVA to a file offset (or None if out of any section)."""
    for s in sects:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["rptr"] + (rva - s["vaddr"])
    return None


def scan_rtti(image_base, sects, data):
    rdata = find_section(sects, ".rdata")
    if rdata is None:
        print("No .rdata section?")
        sys.exit(2)
    rd_va = image_base + rdata["vaddr"]
    rd_size = rdata["vsize"]
    rd_rptr = rdata["rptr"]
    print(f".rdata: VA=0x{rd_va:x}  size=0x{rd_size:x}")

    # Build image-RVA bounds (any section)
    image_rva_max = max(s["vaddr"] + max(s["vsize"], s["rsize"]) for s in sects)

    # Pass 1: find every CompleteObjectLocator
    # Walk .rdata at 4-byte alignment (COL header alignment) checking signature
    cols = {}   # rva -> (signature, offset, cdOffset, pTypeDescriptor, pClassDescriptor)
    n_cols = 0
    for p in range(0, rd_size - 24, 4):
        sig = struct.unpack_from("<I", data, rd_rptr + p)[0]
        if sig != 1:
            continue
        # Read full COL
        off, cd, ptd, pcd, pself = struct.unpack_from("<IIIII", data, rd_rptr + p + 4)
        col_rva = rdata["vaddr"] + p
        if pself != col_rva:
            continue
        # Validate ptd, pcd are inside the image (any section).
        if ptd >= image_rva_max or pcd >= image_rva_max:
            continue
        cols[col_rva] = (off, cd, ptd, pcd)
        n_cols += 1
    print(f"Found {n_cols} CompleteObjectLocators")

    # Pass 2: read TypeDescriptors to get class names.
    # MSVC TypeDescriptor layout varies; the reliable trick is to scan the
    # bytes immediately after the pVFTable pointer for the ".?A" prefix.
    # In this Starfield PE, name starts at +0x08 (no `spare` field) AND
    # TypeDescriptors live in .data rather than .rdata.
    name_by_col = {}
    for col_rva, (off, cd, ptd, pcd) in cols.items():
        tdesc_file = rva_to_file(sects, ptd)
        if tdesc_file is None or tdesc_file + 8 >= len(data):
            continue
        # Scan for the ".?A" prefix within the next 24 bytes of the TypeDescriptor
        prefix_pos = None
        for off2 in (0x08, 0x10):
            if data[tdesc_file + off2:tdesc_file + off2 + 3] == b".?A":
                prefix_pos = tdesc_file + off2
                break
        if prefix_pos is None:
            continue
        end = data.find(b"\x00", prefix_pos)
        if end == -1 or end - prefix_pos > 4096:
            continue
        mangled = data[prefix_pos:end].decode("latin-1", errors="replace")
        if not mangled.startswith(".?A"):
            continue
        cls = demangle_class(mangled)
        name_by_col[col_rva] = cls
    print(f"Demangled {len(name_by_col)} class names")

    # Pass 3: find every vtable by scanning for q where (*q) points to a COL
    vtables = {}    # vtable_va -> class_name
    for p in range(0, rd_size - 8, 8):
        ptr64 = struct.unpack_from("<Q", data, rd_rptr + p)[0]
        if ptr64 == 0:
            continue
        # ptr64 should be image_base + col_rva
        col_rva = ptr64 - image_base
        if col_rva not in name_by_col:
            continue
        # vtable starts at p+8
        vt_rva = rdata["vaddr"] + p + 8
        vt_va = image_base + vt_rva
        cls = name_by_col[col_rva]
        # First COL for this vtable wins (avoid overwriting from later ambiguity)
        if vt_va not in vtables:
            vtables[vt_va] = cls
    print(f"Found {len(vtables)} vtables")

    return vtables


def main():
    print(f"Reading {SF_EXE}")
    image_base, sects, data = parse_pe(SF_EXE)
    print(f"Image base: 0x{image_base:x}")

    vtables_from_rtti = scan_rtti(image_base, sects, data)

    # Cross-reference with CommonLibSF's set
    commonlib_vtables = set()
    commonlib_names = {}
    with open(EXISTING_VTBL, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                va = int(row["target_va"], 16)
                commonlib_vtables.add(va)
                commonlib_names[va] = row["name"]

    new_vtables = {v: n for v, n in vtables_from_rtti.items() if v not in commonlib_vtables}
    overlap = len(commonlib_vtables & vtables_from_rtti.keys())
    cl_only = len(commonlib_vtables - vtables_from_rtti.keys())
    print(f"Vtables in both CommonLibSF & RTTI scan: {overlap}")
    print(f"CommonLibSF-only vtables (not found in RTTI):    {cl_only}")
    print(f"RTTI-only vtables (new):                          {len(new_vtables)}")

    OUT_VTBL_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_VTBL_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["vtable_va", "class_name", "source"])
        # Emit all RTTI-found vtables (their names from RTTI may differ slightly
        # from CommonLibSF; favor RTTI as authoritative).
        for va, name in sorted(vtables_from_rtti.items()):
            src = "rtti" + ("+commonlib" if va in commonlib_vtables else "-only")
            w.writerow([f"0x{va:x}", name, src])
    print(f"Wrote {OUT_VTBL_CSV} ({len(vtables_from_rtti)} rows)")

    # ----- Expand new vtables to slot function names via pyghidra ----------
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project("C:/GhidraProjects", "ExampleProject", create=False) as project:
        domain_file = project.getProjectData().getFile("/Starfield/Starfield 1.16.236")
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            memory = program.getMemory()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            fm = program.getFunctionManager()

            text_start = text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f".text: 0x{text_start:x} - 0x{text_end:x}")

            # Complete termination set: ALL vtables we know about
            all_vtable_set = set(commonlib_vtables) | set(vtables_from_rtti.keys())

            n_vtables_done = 0
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
                    n_vtables_done += 1
                    if n_vtables_done % 2000 == 0:
                        print(f"  {n_vtables_done}/{len(new_vtables)}  slots={n_slots}  unique={n_unique}", flush=True)

            print(f"\nExpanded {n_vtables_done} new vtables")
            print(f"  slot mappings: {n_slots}")
            print(f"  unique targets: {n_unique}")
            print(f"  wrote {OUT_FUNC_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
