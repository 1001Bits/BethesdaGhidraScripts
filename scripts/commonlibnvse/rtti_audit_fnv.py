#!/usr/bin/env python3
"""RTTI COL discovery + vtable audit for PC FalloutNV.exe (32-bit x86).

Two passes:

  1. **Discover** every CompleteObjectLocator (COL) in .rdata:
       struct COL { DWORD sig; DWORD off; DWORD cdOff;
                    PTR pTypeDescriptor; PTR pClassDescriptor; };
     For 32-bit MSVC, ``sig == 0`` (vs ``1`` for 64-bit).  Validate by
     reading the TypeDescriptor and checking for the ``.?A`` mangled
     class prefix.

  2. **Audit** the existing fnv_pc_vtables.txt against what RTTI says:
       - vtables NOT in our list (Ghidra missed them)
       - vtables in our list NOT in RTTI (likely false positives)
       - vtables with class-name mismatches

Output: ``fnv_rtti_audit.txt`` with sections for each finding.

Run:
    python rtti_audit_fnv.py
"""
from __future__ import annotations

import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
from paths import PC_EXE as EXE_PATH


def parse_pe_x86(path: Path):
    data = path.read_bytes()
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    coff = pe_off + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt = coff + 20
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    image_base = struct.unpack_from('<I', data, opt + 28)[0]
    sect_off = opt + opt_sz
    sects = []
    for i in range(nsec):
        so = sect_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin-1', 'replace')
        vsize = struct.unpack_from('<I', data, so + 8)[0]
        vaddr = struct.unpack_from('<I', data, so + 12)[0]
        rsize = struct.unpack_from('<I', data, so + 16)[0]
        rptr  = struct.unpack_from('<I', data, so + 20)[0]
        chars = struct.unpack_from('<I', data, so + 36)[0]
        sects.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                       'rptr': rptr, 'rsize': rsize, 'chars': chars})
    return data, image_base, sects


def rva_to_file(sects, rva):
    for s in sects:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize']):
            return s['rptr'] + (rva - s['vaddr'])
    return None


def find_section(sects, name):
    for s in sects:
        if s['name'] == name:
            return s
    return None


def demangle_class(mangled):
    """``.?AVClassName@@`` -> ``ClassName``.

    Strips the leading ``.?A[VU]`` (V=class, U=struct) and trailing
    ``@@`` namespace terminator.  Doesn't handle nested classes or
    templates -- returns the simplified base name.
    """
    if not mangled.startswith('.?A'):
        return mangled
    body = mangled[3:]  # drop .?A
    if body and body[0] in 'VUW':
        body = body[1:]
    if body.endswith('@@'):
        body = body[:-2]
    # Handle nested ``X@Y@@`` -> ``Y::X``
    parts = body.split('@')
    parts = [p for p in parts if p]
    parts.reverse()
    return '::'.join(parts) if parts else body


def scan_rtti_x86(image_base, sects, data):
    """Find every COL in .rdata, then walk to find vtables.

    32-bit COL layout (20 bytes):
        DWORD signature        // 0
        DWORD offset
        DWORD cdOffset
        DWORD pTypeDescriptor  // RVA-relative? No, absolute VA in x86
        DWORD pClassDescriptor
    """
    rdata = find_section(sects, '.rdata')
    assert rdata is not None
    rd_va    = image_base + rdata['vaddr']
    rd_size  = rdata['vsize']
    rd_rptr  = rdata['rptr']
    print(f'.rdata: VA=0x{rd_va:x} size=0x{rd_size:x}')

    image_max_rva = max(s['vaddr'] + max(s['vsize'], s['rsize']) for s in sects)
    image_max_va  = image_base + image_max_rva

    # Pass 1: scan for COLs.  sig==0 for 32-bit, pTypeDescriptor and
    # pClassDescriptor must be in-image absolute VAs.
    cols = {}  # col_va -> (sig, off, cd, ptd_va, pcd_va)
    for p in range(0, rd_size - 20, 4):
        off = rd_rptr + p
        sig = struct.unpack_from('<I', data, off)[0]
        if sig != 0:
            continue
        offval = struct.unpack_from('<I', data, off + 4)[0]
        cdoff  = struct.unpack_from('<I', data, off + 8)[0]
        ptd    = struct.unpack_from('<I', data, off + 12)[0]
        pcd    = struct.unpack_from('<I', data, off + 16)[0]
        if not (image_base <= ptd < image_max_va):
            continue
        if not (image_base <= pcd < image_max_va):
            continue
        # offval should be small (object-to-vtable byte offset, typically 0-256)
        if offval > 0x100:
            continue
        col_va = image_base + rdata['vaddr'] + p
        cols[col_va] = (offval, cdoff, ptd, pcd)
    print(f'Candidate COLs: {len(cols)}')

    # Pass 2: read TypeDescriptors, validate via .?A prefix
    name_by_col = {}
    for col_va, (offval, cd, ptd, pcd) in cols.items():
        ptd_rva = ptd - image_base
        tdesc_file = rva_to_file(sects, ptd_rva)
        if tdesc_file is None:
            continue
        # TypeDescriptor: pVFTable, spare, name string starts at offset 8
        if tdesc_file + 8 >= len(data):
            continue
        name_start = tdesc_file + 8
        if data[name_start:name_start + 3] != b'.?A':
            continue
        end = data.find(b'\x00', name_start)
        if end == -1 or end - name_start > 4096:
            continue
        mangled = data[name_start:end].decode('latin-1', errors='replace')
        cls = demangle_class(mangled)
        if cls:
            name_by_col[col_va] = (cls, mangled)
    print(f'Demangled COLs: {len(name_by_col)}')

    # Pass 3: find vtables -- 4-byte pointer in .rdata whose value points
    # to a known COL (the entry IMMEDIATELY BEFORE a vtable's slots).
    vtables = {}  # vtable_va -> (class, mangled)
    for p in range(0, rd_size - 4, 4):
        ptr = struct.unpack_from('<I', data, rd_rptr + p)[0]
        if ptr not in name_by_col:
            continue
        # Vtable starts 4 bytes after the COL pointer
        vt_va = image_base + rdata['vaddr'] + p + 4
        if vt_va not in vtables:
            vtables[vt_va] = name_by_col[ptr]
    print(f'Vtables via RTTI: {len(vtables)}')
    return vtables


def load_existing_vtables(path: Path) -> Dict[int, Tuple[str, int]]:
    """``VTABLE|0x<va>|<class>|<N> vfuncs`` -> {va: (class, n_funcs)}"""
    out = {}
    rx = re.compile(r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|(\d+)\s+vfuncs')
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = rx.match(ln)
        if m:
            out[int(m.group(1), 16)] = (m.group(2).strip(), int(m.group(3)))
    return out


def main():
    print(f'Reading {EXE_PATH}')
    data, image_base, sects = parse_pe_x86(EXE_PATH)
    print(f'Image base: 0x{image_base:x}')

    rtti_vtables = scan_rtti_x86(image_base, sects, data)

    print('Loading existing fnv_pc_vtables.txt...')
    existing = load_existing_vtables(REFS_DIR / 'fnv_pc_vtables.txt')
    print(f'  existing: {len(existing)}')

    # Compare
    rtti_vas      = set(rtti_vtables.keys())
    existing_vas  = set(existing.keys())

    new_via_rtti = rtti_vas - existing_vas
    missing_in_rtti = existing_vas - rtti_vas
    in_both = rtti_vas & existing_vas

    mismatches = []
    for va in in_both:
        rtti_cls, _ = rtti_vtables[va]
        ex_cls, _   = existing[va]
        if rtti_cls != ex_cls:
            mismatches.append((va, rtti_cls, ex_cls))

    print(f'\n=== AUDIT ===')
    print(f'  vtables in both: {len(in_both)}')
    print(f'  RTTI-found, NOT in existing (new): {len(new_via_rtti)}')
    print(f'  existing, NOT found by RTTI: {len(missing_in_rtti)}')
    print(f'  class-name mismatches: {len(mismatches)}')

    out_path = REFS_DIR / 'fnv_rtti_audit.txt'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write(f'# RTTI audit for FalloutNV.exe\n')
        f.write(f'# in_both={len(in_both)}  '
                f'new_via_rtti={len(new_via_rtti)}  '
                f'missing_in_rtti={len(missing_in_rtti)}  '
                f'mismatches={len(mismatches)}\n\n')
        f.write('=== Vtables RTTI found but NOT in fnv_pc_vtables.txt ===\n')
        for va in sorted(new_via_rtti):
            cls, mangled = rtti_vtables[va]
            f.write(f'0x{va:08X}|{cls}|{mangled}\n')
        f.write('\n=== Vtables in fnv_pc_vtables.txt but NOT found by RTTI ===\n')
        for va in sorted(missing_in_rtti):
            cls, n = existing[va]
            f.write(f'0x{va:08X}|{cls}|{n} vfuncs\n')
        f.write('\n=== Class-name mismatches ===\n')
        for va, rcls, ecls in sorted(mismatches):
            f.write(f'0x{va:08X}|RTTI={rcls}|existing={ecls}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
