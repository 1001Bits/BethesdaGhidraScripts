#!/usr/bin/env python3
"""Read 825 RTTI-discovered new vtables, dump their slots from .rdata,
emit fnv_pc_vtables.txt-compatible entries, and rebuild the xbox_vtable
fallback names.

For each new vtable VA (from fnv_rtti_audit.txt):
  1. Compute class join-key from TypeDescriptor mangled name (strip
     ``.?AV`` / ``.?AU`` prefix, take prefix before first ``@@``).
     This matches Xbox PDB's primary-vftable class encoding exactly.
  2. Scan .rdata starting at the vtable VA, reading 4-byte LE function
     pointers until hitting NULL, a non-.text VA, or another COL slot.
  3. Emit both table and function addresses as explicitly tagged RVAs.

Output: ``fnv_pc_vtables_rtti_extra.txt`` -- appended to fnv_pc_vtables
data in the pdb_naming step (or merged on demand).

Run:
    python extend_pc_vtables_from_rtti.py
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
AUDIT      = REFS_DIR / 'fnv_rtti_audit.txt'
from paths import PC_EXE as EXE_PATH
OUT_PATH   = REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'


sys.path.insert(0, str(SCRIPT_DIR))
from rtti_audit_fnv import parse_pe_x86, rva_to_file, find_section


_NEW_RE = re.compile(r'^0x([0-9A-Fa-f]+)\|([^|]+)\|(.+)$')


def load_new_vtables() -> List[Tuple[int, str, str]]:
    """[(va, primitive_demangle, type_descriptor_mangled), ...]"""
    out = []
    in_section = False
    for ln in AUDIT.read_text(encoding='utf-8', errors='replace').splitlines():
        if ln.startswith('=== Vtables RTTI found'):
            in_section = True; continue
        if ln.startswith('===') and in_section:
            break
        if in_section:
            m = _NEW_RE.match(ln)
            if m:
                out.append((int(m.group(1), 16),
                            m.group(2).strip(),
                            m.group(3).strip()))
    return out


def class_key_from_typedesc(mangled: str) -> str:
    """``.?AV<class>@@``-form -> ``<class>`` (same encoding Xbox PDB uses
    between ``??_7`` and ``@@`` for primary vftables).

    Mirrors ``extract_xbox_vtables.vftable_class_name`` exactly so the
    key string matches verbatim.
    """
    if not mangled.startswith('.?A'):
        return ''
    body = mangled[3:]
    if body and body[0] in 'VUW':
        body = body[1:]
    end = body.find('@@')
    return body[:end] if end > 0 else body


def main():
    new_vts = load_new_vtables()
    print(f'Loaded {len(new_vts)} RTTI-discovered new vtables')

    print(f'Reading {EXE_PATH}')
    data, image_base, sects = parse_pe_x86(EXE_PATH)

    # Build text VA range -- a slot pointer must land in .text
    text = next(s for s in sects if s['chars'] & 0x20000000)
    text_start = image_base + text['vaddr']
    text_end   = text_start + max(text['vsize'], text['rsize'])

    # All vtable VAs (existing + new) -- a slot read must stop if it
    # would cross into another vtable
    all_vt_vas = set(va for va, _, _ in new_vts)
    # Also include existing vtables to cap reads
    pcv = REFS_DIR / 'fnv_pc_vtables.txt'
    for ln in pcv.read_text(encoding='utf-8', errors='replace').splitlines():
        m = re.match(r'^VTABLE\|0x([0-9A-Fa-f]+)\|', ln)
        if m:
            all_vt_vas.add(int(m.group(1), 16))
    all_vt_vas_sorted = sorted(all_vt_vas)

    written_entries = 0
    written_slots = 0
    skipped_no_slots = 0
    skipped_no_key = 0

    out_lines = []
    out_lines.append('# RTTI-discovered vtables not in fnv_pc_vtables.txt\n')
    out_lines.append('# ADDRESS_COORDINATE=RVA\n')
    out_lines.append('# format mirrors fnv_pc_vtables.txt for downstream consumption\n')

    import bisect

    for va, _demangled, typedesc in new_vts:
        key = class_key_from_typedesc(typedesc)
        if not key:
            skipped_no_key += 1
            continue
        rva = va - image_base
        file_off = rva_to_file(sects, rva)
        if file_off is None:
            continue
        # Determine next vtable boundary (cap reads)
        idx = bisect.bisect_right(all_vt_vas_sorted, va)
        next_vt_va = all_vt_vas_sorted[idx] if idx < len(all_vt_vas_sorted) else va + 0x4000
        max_slots = min(256, (next_vt_va - va) // 4)
        slots: List[int] = []
        for s in range(max_slots):
            off = file_off + s * 4
            if off + 4 > len(data):
                break
            ptr = struct.unpack_from('<I', data, off)[0]
            if ptr == 0:
                break
            if not (text_start <= ptr < text_end):
                break
            slots.append(ptr - image_base)
        if not slots:
            skipped_no_slots += 1
            continue

        out_lines.append(f'VTABLE|0x{rva:08X}|{key}|{len(slots)} vfuncs\n')
        for s, slot_rva in enumerate(slots):
            out_lines.append(f'  VFUNC|0x{slot_rva:08X}|{key}::vf{s:03d}\n')
        written_entries += 1
        written_slots += len(slots)

    OUT_PATH.write_text(''.join(out_lines), encoding='utf-8')
    print(f'  vtables written: {written_entries}')
    print(f'  total slots written: {written_slots}')
    print(f'  skipped (no class key): {skipped_no_key}')
    print(f'  skipped (no readable slots): {skipped_no_slots}')
    print(f'Wrote {OUT_PATH}')


if __name__ == '__main__':
    main()
