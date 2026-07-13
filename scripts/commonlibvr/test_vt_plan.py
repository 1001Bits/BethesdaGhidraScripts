#!/usr/bin/env python3
"""Unit tests for vt_plan (CommonLib-driven Version Tracking planning).

Run: python -m pytest test_vt_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_plan  # noqa: E402


def test_plan_classifies_three_ways():
    expected = {
        0x100: (0x200, 'func'),   # no existing -> seed
        0x110: (0x210, 'func'),   # existing matches -> confirmed
        0x120: (0x220, 'label'),  # existing differs -> conflict
    }
    existing = {0x110: 0x210, 0x120: 0x999}
    out = vt_plan.plan_vt(expected, existing)
    assert out['seed'] == [(0x100, 0x200, 'func')]
    assert out['confirmed'] == [(0x110, 0x210, 'func')]
    assert out['conflict'] == [(0x120, 0x220, 0x999, 'label')]


def test_plan_empty_existing_all_seed():
    expected = {1: (2, 'func'), 3: (4, 'label')}
    out = vt_plan.plan_vt(expected, {})
    assert sorted(out['seed']) == [(1, 2, 'func'), (3, 4, 'label')]
    assert out['confirmed'] == [] and out['conflict'] == []


def test_build_expected_requires_both_offsets():
    syms = [
        {'n': 'A::f', 't': 'func', 's': 10, 'a': 20, 'v': 30},
        {'n': 'B::g', 't': 'func', 's': 11, 'v': 31},          # no 'a'
        {'n': 'RTTI_C', 't': 'label', 's': 12, 'a': 22, 'v': 32},
        {'n': 'D::h', 't': 'func', 'a': 21, 'v': 33},          # no 's'
    ]
    # SE->VR (s->v): A, B, RTTI_C qualify (all have s and v); D has no s
    se_vr = vt_plan.build_expected(syms, 's', 'v')
    assert se_vr == {10: (30, 'func'), 11: (31, 'func'), 12: (32, 'label')}
    # SE->AE (s->a): A and RTTI_C qualify; B has no a, D has no s
    se_ae = vt_plan.build_expected(syms, 's', 'a')
    assert se_ae == {10: (20, 'func'), 12: (22, 'label')}


def test_build_expected_kind_func_vs_label():
    syms = [{'n': 'X', 't': 'label', 's': 1, 'v': 2},
            {'n': 'Y::m', 't': 'func', 's': 3, 'v': 4}]
    out = vt_plan.build_expected(syms, 's', 'v')
    assert out[1] == (2, 'label')
    assert out[3] == (4, 'func')


def test_build_expected_stable_on_duplicate_src():
    syms = [{'n': 'first', 't': 'func', 's': 5, 'v': 50},
            {'n': 'second', 't': 'func', 's': 5, 'v': 99}]
    out = vt_plan.build_expected(syms, 's', 'v')
    assert out[5] == (50, 'func')   # first wins, not overwritten


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
