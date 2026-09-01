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
from versionlib_map import (
    DEFAULT_IMAGE_BASE,
    VersionlibError,
    build_va_translation,
    read_versionlib,
    verify_image_base,
)


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


def _slot_function_addresses(layout):
    tables = layout.vtables or layout.classes
    return [entry.func_addr
            for table in tables.values()
            for entry in table.slots.values()]


def _load_translation(ref, tgt, args):
    """Build the reference->target address map, refusing an unverified base.

    A wrong image base still yields plausible-looking RVAs, and every mapping
    derived from them would be confidently wrong, so the base is checked
    against real slot addresses before any of it is trusted.
    """
    reference_db = read_versionlib(args.ref_versionlib)
    target_db = read_versionlib(args.target_versionlib)

    for label, flag, layout, database, base in (
            ('reference', '--ref-image-base', ref, reference_db, args.ref_image_base),
            ('target', '--target-image-base', tgt, target_db, args.target_image_base)):
        rate, ok = verify_image_base(
            _slot_function_addresses(layout), database, base)
        print('  {} image base 0x{:X}: {:.1%} of slot functions resolve to an '
              'Address Library ID'.format(label, base, rate))
        if not ok:
            raise VersionlibError(
                '{} image base 0x{:X} does not fit its address library -- only '
                '{:.1%} of slot functions resolve to an ID.  Pass the real base '
                'with {}.'.format(label, base, rate, flag))

    return build_va_translation(reference_db, target_db,
                                args.ref_image_base, args.target_image_base)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref', required=True, help='reference layout CSV')
    p.add_argument('--ref-label', required=True)
    p.add_argument('--target', required=True, help='target layout CSV')
    p.add_argument('--target-label', required=True)
    p.add_argument('--out', required=True, help='output shift map JSON')
    p.add_argument('--allow-low-coverage', action='store_true',
                   help='research only: write a map that fails coverage gates')
    p.add_argument('--ref-versionlib',
                   help='reference build address library; with --target-versionlib '
                        'enables exact Address Library ID slot matching')
    p.add_argument('--target-versionlib', help='target build address library')
    p.add_argument('--ref-image-base', type=lambda v: int(v, 0),
                   default=DEFAULT_IMAGE_BASE)
    p.add_argument('--target-image-base', type=lambda v: int(v, 0),
                   default=DEFAULT_IMAGE_BASE)
    args = p.parse_args()

    ref = load_csv(args.ref, args.ref_label)
    tgt = load_csv(args.target, args.target_label)
    print('Reference: {} classes ({} slots)'.format(
        len(ref.vtables), sum(len(c.slots) for c in ref.vtables.values())))
    print('Target:    {} classes ({} slots)'.format(
        len(tgt.vtables), sum(len(c.slots) for c in tgt.vtables.values())))

    va_translation = None
    if bool(args.ref_versionlib) != bool(args.target_versionlib):
        print('ERROR: --ref-versionlib and --target-versionlib must be given together')
        return 2
    if args.ref_versionlib:
        try:
            va_translation = _load_translation(ref, tgt, args)
        except VersionlibError as exc:
            print('ERROR: ' + str(exc))
            return 2
        print('Address Library IDs: {} reference functions translate to the '
              'target build'.format(len(va_translation)))

    sm = build_shift_map(ref, tgt, va_translation)

    # Print the breakdown before deciding, not after.  A bare percentage tells
    # nobody whether the target drifted or the reference is simply unmatchable.
    n_matched = sum(len(c.ref_to_target) for c in sm.vtables.values())
    n_unmatched_ref = sum(len(c.unmatched_ref_slots) for c in sm.vtables.values())
    n_target_only = sum(len(c.target_only_slots) for c in sm.vtables.values())
    print('Matched ref->target slots: {}'.format(n_matched))
    print('Unmatched ref slots:       {}'.format(n_unmatched_ref))
    print('Target-only slots:         {}'.format(n_target_only))
    by_method = {}
    for table in sm.vtables.values():
        for evidence in table.match_evidence.values():
            key = evidence.get('method', 'unknown')
            by_method[key] = by_method.get(key, 0) + 1
        for rejected in table.ambiguous_matches:
            key = 'rejected:' + rejected.get('method', 'unknown')
            by_method[key] = by_method.get(key, 0) + 1
    for key in sorted(by_method):
        print('  {:<28} {}'.format(key, by_method[key]))

    quality_reasons = _quality_reasons(ref, tgt, sm)
    if quality_reasons:
        for reason in quality_reasons:
            print('ERROR: ' + reason)
        if not args.allow_low_coverage:
            print('Refusing to write an unsafe shift map.')
            return 2
        print('WARNING: writing low-coverage research map by explicit request')

    save_json(sm, args.out)
    print('Wrote shift map: {}'.format(args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
