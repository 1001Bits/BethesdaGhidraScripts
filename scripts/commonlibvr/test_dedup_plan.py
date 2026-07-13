#!/usr/bin/env python3
"""Unit tests for dedup_plan (duplicate-type deduper logic).

Run: python -m pytest test_dedup_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dedup_plan as dp  # noqa: E402


def _v(key, name, category, size, ndefined):
    return {'key': key, 'name': name, 'category': category, 'size': size, 'ndefined': ndefined}


def test_base_name():
    assert dp.base_name('TESForm.conflict') == 'TESForm'
    assert dp.base_name('TESForm.conflict1') == 'TESForm'
    assert dp.base_name('TESForm') == 'TESForm'
    assert dp.base_name('BSTArray<RE::TESForm>') == 'BSTArray<RE::TESForm>'


def test_no_dup_and_empty():
    assert dp.plan_merge([]) == (None, [], False, 'empty')
    assert dp.plan_merge([_v('a', 'X', '/types.h', 8, 2)]) == ('a', [], False, 'no-dup')


def test_same_size_keeps_typesh_regardless_of_population():
    # /types.h clean type is the keeper; pdb + conflict merge into it EVEN WHEN they
    # have more defined members -- those extra members are the PDB-flattened base class
    # (same 0x10 bytes), so no RE is lost. This is the TESBoundObject case.
    variants = [_v('pdb', 'X', '/SkyrimSE.pdb', 16, 9),
                _v('th', 'X', '/types.h', 16, 3),
                _v('cf', 'X.conflict', '/types.h', 16, 9)]
    keeper, merges, conflict, reason = dp.plan_merge(variants)
    assert not conflict and reason == 'same-size'
    assert keeper == 'th'                       # clean /types.h wins despite fewest members
    assert set(merges) == {'pdb', 'cf'}


def test_same_size_conflict_merges_into_clean_name():
    # a more-populated .conflict still merges INTO the clean (non-.conflict) name -- we
    # never strand references on a `.conflict` copy, and never flag on population alone.
    variants = [_v('cf', 'X.conflict', '/SkyrimSE.pdb', 8, 9),
                _v('pdb', 'X', '/SkyrimSE.pdb', 8, 3)]
    keeper, merges, conflict, reason = dp.plan_merge(variants)
    assert not conflict and reason == 'same-size'
    assert keeper == 'pdb'                       # clean name beats .conflict
    assert merges == ['cf']


def test_size_conflict_refuses():
    variants = [_v('th', 'X', '/types.h', 24, 4),
                _v('pdb', 'X', '/SkyrimSE.pdb', 32, 6)]
    keeper, merges, conflict, reason = dp.plan_merge(variants)
    assert conflict and keeper is None and merges == [] and reason == 'size-conflict'


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
