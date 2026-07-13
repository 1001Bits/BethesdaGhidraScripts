#!/usr/bin/env python3
"""Merge per-PDB vtable extracts into one master, picking the richest source.

For each class, pick the PDB extract that has the most slots AND the
greatest naming diversity (fewest ICF-folded duplicates).  Debug build
typically wins -- less ICF folding because identical-body virtuals stay
distinct (separate debug symbols).

Run:
    python merge_xbox_vtables.py <out.json> <in1.json> <in2.json> ...
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vtable_schema import load_xbox_tables, make_document  # noqa: E402


def _score(slots):
    """Higher is better: more named slots + more distinct names = richer."""
    named = [s for s in slots if not s.get('m', '').startswith('__unnamed_')]
    distinct = len({s.get('d') or s.get('m') for s in named})
    return (distinct, len(named), len(slots))


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    out_path = Path(sys.argv[1])
    inputs = [Path(p) for p in sys.argv[2:]]

    pick_count = Counter()
    best = {}
    for p in inputs:
        tables = load_xbox_tables(p)
        ordinals = Counter()
        for table in sorted(tables, key=lambda t: (t.class_name, t.subobject,
                                                   t.rva or -1, t.identity)):
            logical = (table.class_name, table.subobject)
            ordinal = ordinals[logical]
            ordinals[logical] += 1
            key = logical + (ordinal,)
            prev = best.get(key)
            if prev is None or _score(table.slots) > _score(prev['table'].slots):
                best[key] = {'table': table, 'src': p.stem}
    for _key, entry in best.items():
        pick_count[entry['src']] += 1

    merged_tables = []
    for (cls, subobject, ordinal), entry in sorted(best.items()):
        table = entry['table']
        merged_tables.append({
            'id': 'merged:%s:%s:%d' % (cls, subobject or 'primary', ordinal),
            'class': cls,
            'subobject': subobject,
            'rva': table.rva,
            'mangled': table.mangled,
            'slots': table.slots,
            'source': entry['src'],
        })
    merged = make_document(merged_tables, address_coordinate='RVA',
                           merged_from=[p.name for p in inputs])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged), encoding='utf-8')

    total_slots = sum(len(t['slots']) for t in merged_tables)
    distinct = len({s.get('d') or s.get('m')
                    for table in merged_tables for s in table['slots']})
    print(f'Merged: {len(merged_tables)} physical tables, {total_slots} slots, '
          f'{distinct} distinct method names')
    print('Class source breakdown:')
    for src, n in pick_count.most_common():
        print(f'  {src:35s} {n}')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
