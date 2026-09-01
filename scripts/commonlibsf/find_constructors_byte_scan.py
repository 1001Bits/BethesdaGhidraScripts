#!/usr/bin/env python3
"""Find class constructors by scanning .text for rip-rel LEA instructions
targeting each labeled vtable address.

x64 MSVC constructor prologue typical pattern:
  48 8D 05 XX XX XX XX   lea  rax, [rip+disp32]   ; target = vtable
  48 89 01               mov  [rcx], rax         ; this->vftable = vtable

We scan for `48 8d ?5 XX XX XX XX` where ?5 = 05/0d/15/1d/25/2d/35/3d
(ModR/M for rip-rel with 8 dest regs).  Compute target = next_instr + disp32.
If target matches a vtable VA, the containing .text function is a constructor
candidate.

Output: scripts/commonlibsf/refs/sf116_constructors.csv
  columns: target_va, name, source
"""
from __future__ import annotations

import csv
import os
import struct
import sys
from pathlib import Path
from collections import defaultdict

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

SF_EXE = Path(r"C:/Games/Starfield 1.16.236/Starfield.exe")
VTBL_NAMES_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_commonlib_names.csv"
OUT_CSV        = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_constructors.csv"


def parse_pe_text(path):
    """Return (image_base, [(virtual_addr, raw_offset, size, name)]) for executable sections."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off:pe_off+4] == b"PE\x00\x00"
    coff = pe_off + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic == 0x20B  # PE32+
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    sections_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        soff = sections_off + i * 40
        name = data[soff:soff+8].rstrip(b"\x00").decode("latin-1")
        vsize = struct.unpack_from("<I", data, soff + 8)[0]
        vaddr = struct.unpack_from("<I", data, soff + 12)[0]
        rsize = struct.unpack_from("<I", data, soff + 16)[0]
        rptr  = struct.unpack_from("<I", data, soff + 20)[0]
        chars = struct.unpack_from("<I", data, soff + 36)[0]
        is_exec = bool(chars & 0x20000000)
        sections.append((vaddr, rptr, min(vsize, rsize), name, is_exec))
    return image_base, sections, data


def main():
    # Load vtables
    vtbl_by_va = {}
    with open(VTBL_NAMES_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"] == "vtbl":
                vtbl_by_va[int(row["target_va"], 16)] = row["name"]
    vtable_va_set = set(vtbl_by_va.keys())
    print(f"Loaded {len(vtbl_by_va)} vtable VAs")

    image_base, sections, data = parse_pe_text(SF_EXE)
    print(f"Image base: 0x{image_base:x}")
    text_sections = [(va, rptr, sz, nm) for (va, rptr, sz, nm, ex) in sections if ex]
    for va, rptr, sz, nm in text_sections:
        print(f"  exec: {nm}  VA=0x{image_base+va:x}  size=0x{sz:x}")

    # Scan each .text for `48 8D ?5 ?? ?? ?? ??` patterns
    # ?5 = 05, 0d, 15, 1d, 25, 2d, 35, 3d  (modr/m mod=00, rm=101)
    valid_modrm = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}

    func_to_vtables = defaultdict(set)  # ip_va -> set of vtable VAs referenced
    # We don't know function boundaries yet; we'll collect (instruction_va, target_vtbl_va)
    # then later group by containing function via Ghidra.
    refs = []
    n_lea_total = 0
    n_lea_match = 0

    for sec_va, rptr, sz, nm in text_sections:
        sec_data = data[rptr:rptr+sz]
        sec_va_abs = image_base + sec_va
        # Sliding scan: at each offset, check the 7-byte LEA pattern
        i = 0
        n = len(sec_data) - 7
        while i < n:
            if sec_data[i] == 0x48 and sec_data[i+1] == 0x8D and sec_data[i+2] in valid_modrm:
                n_lea_total += 1
                disp = struct.unpack_from("<i", sec_data, i + 3)[0]
                instr_va = sec_va_abs + i
                target_va = instr_va + 7 + disp
                if target_va in vtable_va_set:
                    refs.append((instr_va, target_va))
                    n_lea_match += 1
                i += 1  # don't skip; overlapping LEA possible
            else:
                i += 1
        print(f"  scanned {nm}: matches so far = {n_lea_match}")

    print(f"\nTotal LEA matches: {n_lea_match} / {n_lea_total} total LEAs scanned")

    # Now we have (instruction_va, vtable_va) pairs.  Use Ghidra to find
    # containing functions.
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    PROJECT_DIR  = "C:/GhidraProjects"
    PROJECT_NAME = "ExampleProject"
    PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            fm = program.getFunctionManager()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            func_to_vtables = defaultdict(set)
            for instr_va, vt_va in refs:
                func = fm.getFunctionContaining(default_space.getAddress(instr_va))
                if func is None:
                    continue
                func_to_vtables[func.getEntryPoint().getOffset()].add(vt_va)
            print(f"Functions referencing >=1 vtable: {len(func_to_vtables)}")

            n_single = 0
            n_multi = 0
            with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name", "source"])
                for fn_va, vts in func_to_vtables.items():
                    classes = {vtbl_by_va[v] for v in vts}
                    if len(classes) != 1:
                        n_multi += 1
                        continue
                    cls = next(iter(classes))
                    leaf = cls.split("::")[-1]
                    w.writerow([f"0x{fn_va:x}", f"{cls}::{leaf}", "ctor-leascan"])
                    n_single += 1
            print(f"\nSingle-class constructor candidates: {n_single}")
            print(f"Multi-class (skipped): {n_multi}")
            print(f"Wrote {OUT_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
