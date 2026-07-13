"""CLI: build a per-version shift map from two ``vtable_layout`` CSVs.

Use after running ``vtable_dumper.py`` on both a reference binary
(canonical version that CommonLib's headers describe) and a target
binary (the version whose script we want to ship).

Example::

    python -m build_shift_map \
        --ref scripts/commonlibsse/refs/se_vtables.csv \
        --ref-label se \
        --target scripts/commonlibsse/refs/svr_vtables.csv \
        --target-label svr \
        --out scripts/commonlibsse/refs/shift_svr.json
"""
from __future__ import annotations

import argparse
import sys

from vtable_layout import load_csv
from vtable_matcher import build_shift_map, save_json


def _quality_reasons(ref, tgt, shift, min_match_ratio=0.50):
    ref_tables = len(ref.vtables)
    tgt_tables = len(tgt.vtables)
    ref_slots = sum(len(table.slots) for table in ref.vtables.values())
    tgt_slots = sum(len(table.slots) for table in tgt.vtables.values())
    matched = sum(len(item.ref_to_target) for item in shift.vtables.values())
    reasons = []
    if not ref_tables or not ref_slots:
        reasons.append('reference layout is empty')
    if not tgt_tables or not tgt_slots:
        reasons.append('target layout is empty')
    if ref_tables and not (0.25 <= tgt_tables / float(ref_tables) <= 4.0):
        reasons.append('target/reference vtable count ratio is implausible')
    if ref_slots and not (0.25 <= tgt_slots / float(ref_slots) <= 4.0):
        reasons.append('target/reference slot count ratio is implausible')
    if ref_slots and matched / float(ref_slots) < min_match_ratio:
        reasons.append('only {:.1%} of reference slots matched (need {:.0%})'.format(
            matched / float(ref_slots), min_match_ratio))
    return reasons


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref', required=True, help='reference layout CSV')
    p.add_argument('--ref-label', required=True)
    p.add_argument('--target', required=True, help='target layout CSV')
    p.add_argument('--target-label', required=True)
    p.add_argument('--out', required=True, help='output shift map JSON')
    p.add_argument('--allow-low-coverage', action='store_true',
                   help='research only: write a map that fails coverage gates')
    args = p.parse_args()

    ref = load_csv(args.ref, args.ref_label)
    tgt = load_csv(args.target, args.target_label)
    print('Reference: {} classes ({} slots)'.format(
        len(ref.vtables), sum(len(c.slots) for c in ref.vtables.values())))
    print('Target:    {} classes ({} slots)'.format(
        len(tgt.vtables), sum(len(c.slots) for c in tgt.vtables.values())))

    sm = build_shift_map(ref, tgt)

    quality_reasons = _quality_reasons(ref, tgt, sm)
    if quality_reasons:
        for reason in quality_reasons:
            print('ERROR: ' + reason)
        if not args.allow_low_coverage:
            print('Refusing to write an unsafe shift map.')
            return 2
        print('WARNING: writing low-coverage research map by explicit request')

    # Brief diagnostic
    n_matched = sum(len(c.ref_to_target) for c in sm.vtables.values())
    n_unmatched_ref = sum(len(c.unmatched_ref_slots) for c in sm.vtables.values())
    n_target_only = sum(len(c.target_only_slots) for c in sm.vtables.values())
    print('Matched ref->target slots: {}'.format(n_matched))
    print('Unmatched ref slots:       {}'.format(n_unmatched_ref))
    print('Target-only slots:         {}'.format(n_target_only))

    save_json(sm, args.out)
    print('Wrote shift map: {}'.format(args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
