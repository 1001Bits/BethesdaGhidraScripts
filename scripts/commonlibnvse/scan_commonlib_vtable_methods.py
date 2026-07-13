#!/usr/bin/env python3
"""Parse CommonLibSSE / CommonLibF4 headers for vtable method names.

CommonLib documents each vtable method with:
    virtual <ret>   <Method>(<args>);   // <slot_hex> - <comment>

For each class with a matching FNV vtable, emit ``Class::method`` at
the slot's PC FNV RVA.

This fills in slots that the Xbox PDB demangled as
``Class::vfNNN_<dtor_kind>`` placeholders or where Xbox PDB had no
public symbol for that slot.

Run:
    python scan_commonlib_vtable_methods.py <commonlib_include_root> [out.csv]
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
sys.path.insert(0, str(SCRIPT_DIR))
from addressing import load_vtable_records  # noqa: E402


# Match ``class Foo : public Bar`` or ``class Foo`` (capture class name)
_CLASS_RX = re.compile(r'^\s*(?:class|struct)\s+(\w+)(?:\s*:|.*\{)')

# Match a virtual method with slot-index hex comment
#   virtual void   ClearData();   // 05 - { return; }
# We capture the method name and slot index.
_VIRTUAL_RX = re.compile(
    r'^\s*(?:\[\[nodiscard\]\]\s*)?virtual\s+'
    r'(?:[\w:<>\*&\s]+?\s+)?'          # return type (best-effort)
    r'([A-Za-z_]\w*)\s*\([^)]*\)'      # method name + args
    r'[^;]*;\s*'                        # body
    r'//\s*([0-9A-Fa-f]+)'              # slot index hex
)


def parse_headers(root: Path) -> Dict[str, List[tuple]]:
    """Return ``{class_name: [(slot_idx, method_name), ...]}``."""
    out: Dict[str, List[tuple]] = {}
    n_files = 0
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if not fname.endswith('.h'):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                src = Path(fpath).read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            n_files += 1
            # Scan for ``class Foo`` then collect virtual methods up to next ``};``
            lines = src.splitlines()
            cur_class = None
            for ln in lines:
                m_cls = _CLASS_RX.match(ln)
                if m_cls:
                    cur_class = m_cls.group(1)
                    out.setdefault(cur_class, [])
                    continue
                # Closing brace exits the class scope
                if cur_class and ln.startswith('}'):
                    cur_class = None
                    continue
                if cur_class:
                    m_v = _VIRTUAL_RX.match(ln)
                    if m_v:
                        method = m_v.group(1)
                        try:
                            slot = int(m_v.group(2), 16)
                        except ValueError:
                            continue
                        # Skip too-large slot indices (clearly comment-mismatches)
                        if slot > 0xFF:
                            continue
                        out[cur_class].append((slot, method))
    return out, n_files


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    roots = [Path(r) for r in sys.argv[1:-1]] if len(sys.argv) > 2 else \
        [Path(sys.argv[1])]
    out_path = Path(sys.argv[-1]) if len(sys.argv) > 2 else \
        REFS_DIR / 'fnv_commonlib_vtable_methods.csv'

    all_class_methods: Dict[str, List[tuple]] = {}
    total_files = 0
    for root in roots:
        print(f'Scanning {root}...')
        result, n = parse_headers(root)
        total_files += n
        for cls, methods in result.items():
            if cls in all_class_methods:
                # Merge: prefer first source's methods (later sources fill gaps)
                existing_slots = {s for s, _ in all_class_methods[cls]}
                for s, m in methods:
                    if s not in existing_slots:
                        all_class_methods[cls].append((s, m))
            else:
                all_class_methods[cls] = methods

    n_classes = sum(1 for ms in all_class_methods.values() if ms)
    n_methods = sum(len(ms) for ms in all_class_methods.values())
    print(f'Scanned {total_files} files')
    print(f'  classes with vtable methods: {n_classes:,}')
    print(f'  total documented (class, slot, method) entries: {n_methods:,}')

    # Now match against FNV's vtables: for each (class, slot), look up
    # the slot RVA in fnv_pc_vtables.txt + RTTI extras.
    records = load_vtable_records(
        [REFS_DIR / 'fnv_pc_vtables.txt',
         REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'])
    tables_by_class = {}
    for rec in records:
        tables_by_class.setdefault(rec.class_name, []).append(rec)

    # A source-level Class::slot list describes the primary table.  The
    # legacy PC corpus does not identify primary vs secondary subobjects, so
    # applying it to a repeated class would silently cross-wire tables.  Skip
    # such classes until the RTTI dumper emits explicit subobject identities.
    pc_slots: Dict[str, Dict[int, int]] = {}
    ambiguous_classes = set()
    for cls, tables in tables_by_class.items():
        if len(tables) != 1:
            ambiguous_classes.add(cls)
            continue
        pc_slots[cls] = dict(tables[0].slots)

    # Pair: CommonLib (class, slot, method) -> PC FNV slot RVA
    out_rows = []
    n_matched_classes = 0
    n_emitted = 0
    for cls, methods in all_class_methods.items():
        if cls not in pc_slots:
            continue
        n_matched_classes += 1
        for slot, method in methods:
            rva = pc_slots[cls].get(slot)
            if rva is None:
                continue
            out_rows.append((rva, f'{cls}::{method}'))
            n_emitted += 1

    print(f'  classes also in FNV vtables: {n_matched_classes:,}')
    print(f'  ambiguous repeated-table classes skipped: {len(ambiguous_classes):,}')
    print(f'  total method names emittable: {n_emitted:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# CommonLib-documented vtable methods: 0xRVA|Class::method\n')
        f.write('# ADDRESS_COORDINATE=RVA\n')
        for rva, name in sorted(set(out_rows)):
            f.write(f'0x{rva:08X}|{name}\n')
    print(f'Wrote {out_path}: {len(set(out_rows)):,} unique entries')


if __name__ == '__main__':
    main()
