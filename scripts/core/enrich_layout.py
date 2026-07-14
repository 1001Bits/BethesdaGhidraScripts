"""Improve a per-binary vtable layout CSV with PDB names from an on-disk symbol file.

Useful when the legacy importer produced a layout CSV with addresses but
no function names (the ``f4vr_vtables.txt`` format auto-labels every slot
as ``<Class>::vfNNN`` rather than the PDB symbol).  Joins each slot's
``func_addr`` against a symbol file to populate ``func_name`` -- no Ghidra
needed.

Supported symbol file format::

    # comment lines start with #
    0xVA|name|source
    0x140F58870|PlayerCharacter::ResetSomething|F4VR_PDB

Usage::

    python -m enrich_layout \
        --in scripts/commonlibf4/refs/f4_vr_vtables.csv \
        --symbols /path/to/f4vr_all_symbols.txt \
        --out scripts/commonlibf4/refs/f4_vr_vtables.csv
"""
from __future__ import annotations

import argparse
import sys

from vtable_layout import load_csv, save_csv


def load_symbols(path: str, image_base: int = 0x140000000) -> dict:
    """Return {address_int: name} from a pipe-delimited symbol file.

    Two formats supported:

      1. ``0xVA|name[|source]`` (e.g. ``f4vr_all_symbols.txt``).  Address
         is the full virtual address; image_base is unused.
      2. ``seg1:0xRVA|name`` (e.g. F4 OG ``f4_pdb_pub_functions.txt`` /
         FNV ``pdb_all_function_names.txt``).  Address is an RVA into
         the .text section; we add ``image_base`` to get the full VA.

    Format is detected per-line so heterogeneous files merge cleanly.
    """
    out = {}
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|', 2)
            if len(parts) < 2:
                continue
            addr_str = parts[0].strip()
            name = parts[1].strip()
            addr = None
            # Form 1: full VA "0x140xxxxxxx"
            if addr_str.lower().startswith('0x'):
                try:
                    addr = int(addr_str, 16)
                except ValueError:
                    pass
            # Form 2: "seg1:0xRVA" -- treat as image-base relative
            elif addr_str.lower().startswith('seg1:0x'):
                try:
                    rva = int(addr_str[len('seg1:0x'):], 16)
                    addr = rva + image_base
                except ValueError:
                    pass
            if addr is None:
                continue
            # First-write wins (multiple sources may map to same address)
            out.setdefault(addr, name)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--in', dest='inp', required=True, help='input vtable layout CSV')
    p.add_argument('--symbols', required=True, help='address|name|source symbol file')
    p.add_argument('--label', default='', help="binary label (default: inferred from input filename)")
    p.add_argument('--out', required=True, help='output CSV (may be same as input)')
    p.add_argument('--keep-existing-names', action='store_true',
                   help="don't overwrite slots that already have a non-empty name")
    args = p.parse_args()

    label = args.label or '<enriched>'
    layout = load_csv(args.inp, label)
    print(f'Loaded layout: {len(layout.classes)} classes, '
          f'{sum(len(c.slots) for c in layout.classes.values())} slots')

    syms = load_symbols(args.symbols)
    print(f'Loaded symbol table: {len(syms):,} entries')

    improved = 0
    addr_misses = 0
    for cv in layout.classes.values():
        for e in cv.slots.values():
            if args.keep_existing_names and e.func_name:
                continue
            name = syms.get(e.func_addr)
            if name:
                if name != e.func_name:
                    e.func_name = name
                    improved += 1
            else:
                addr_misses += 1

    n = save_csv(layout, args.out)
    print(f'Improved {improved:,} slots with PDB names')
    print(f'Address misses: {addr_misses:,} (no symbol entry for that address)')
    print(f'Wrote {n:,} rows -> {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
