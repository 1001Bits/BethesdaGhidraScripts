#!/usr/bin/env python3
"""Dump every known PC FNV function-start RVA to a flat anchor list.

Sources combined:
  - PC vtable corpora (every VFUNC, normalized from its declared coordinate)
  - fnv_pc_symbols.txt (NVSE/JIP-LN known)
  - fnv_pdb_matched_classes.txt (legacy)
  - existing string_anchored.csv if present

Output: one hex VA per line.  Consumed by extract_pc_fnv_string_xrefs.py
to snap xrefs back to the true function entry.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from addressing import FNV_IMAGE_BASE, load_vtable_records

REFS = Path(__file__).resolve().parent / 'refs'
IMAGE_BASE = 0x00400000


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
               (REFS / 'fnv_pc_anchors.txt')

    anchors = set()

    # 1. PC vtables -- normalize both legacy mixed-coordinate corpora, then
    # emit the absolute VAs expected by the anchor snapper.
    paths = [REFS / 'fnv_pc_vtables.txt',
             REFS / 'fnv_pc_vtables_rtti_extra.txt']
    if any(p.is_file() for p in paths):
        for table in load_vtable_records(paths):
            for _slot, rva in table.slots:
                anchors.add(FNV_IMAGE_BASE + rva)
        print(f'  + vtables: {len(anchors):,}')

    # 2. NVSE-known
    p = REFS / 'fnv_pc_symbols.txt'
    if p.is_file():
        n0 = len(anchors)
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            parts = ln.split('|', 2)
            if len(parts) < 2:
                continue
            try:
                va = int(parts[0], 16)
                # NVSE addresses are already absolute VAs
                if va > IMAGE_BASE:
                    anchors.add(va)
            except ValueError:
                continue
        print(f'  + nvse_known: +{len(anchors) - n0}')

    # 3. legacy matched-class
    p = REFS / 'fnv_pdb_matched_classes.txt'
    if p.is_file():
        n0 = len(anchors)
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            m = re.match(r'\s+PC\s+0x([0-9A-Fa-f]+)\s*=', ln)
            if m:
                anchors.add(int(m.group(1), 16))
        print(f'  + pdb_matched: +{len(anchors) - n0}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        for va in sorted(anchors):
            f.write(f'0x{va:08X}\n')
    print(f'Wrote {out_path}: {len(anchors):,} anchors')


if __name__ == '__main__':
    main()
