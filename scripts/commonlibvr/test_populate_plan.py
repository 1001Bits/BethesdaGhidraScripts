#!/usr/bin/env python3
"""Unit tests for populate_plan (population-cycle decision logic).

Run: python -m pytest test_populate_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import populate_plan as pp  # noqa: E402


def test_is_generic_type():
    assert pp.is_generic_type('undefined8')
    assert pp.is_generic_type('longlong')
    assert pp.is_generic_type('void *')
    assert pp.is_generic_type('void *64')      # decorated bare-void pointer
    assert pp.is_generic_type('void*')
    assert pp.is_generic_type('undefined8 *')
    assert pp.is_generic_type('')
    assert pp.is_generic_type(None)
    assert not pp.is_generic_type('Actor *')
    assert not pp.is_generic_type('NiNode *')
    assert not pp.is_generic_type('BSTArray<void *>')   # named structural type is a gain
    assert not pp.is_generic_type('AITimer')


def test_should_apply_field_accepts_named_same_size_into_unknown():
    ok, why = pp.should_apply_field('unk88', 'undefined8', 'Actor *', 8, 8, 'high')
    assert ok and why == 'ok'
    ok, _ = pp.should_apply_field('pad40', 'undefined4', 'NiNode *', 8, 8, 'high')
    assert ok
    # undefined-typed slot with a non-unk name still counts as unknown
    ok, _ = pp.should_apply_field('field_x', 'undefined8', 'TESForm *', 8, 8, 'high')
    assert ok


def test_should_apply_field_refuses_clobber_generic_lowconf_mismatch():
    # existing real RE -> never overwrite
    assert not pp.should_apply_field('flags', 'NiNode *', 'Actor *', 8, 8, 'high')[0]
    # size-only generic inference -> not worth writing
    assert pp.should_apply_field('unk88', 'undefined8', 'longlong', 8, 8, 'high') == \
        (False, 'generic-size-only')
    # low confidence -> hold
    assert pp.should_apply_field('unk88', 'undefined8', 'Actor *', 8, 8, 'low') == \
        (False, 'low-confidence')
    # size mismatch -> would shift/overlap the next member
    assert pp.should_apply_field('unk88', 'undefined8', 'Actor', 16, 8, 'high') == \
        (False, 'size-mismatch')
    # a bare-void pointer is no better than the unk it would replace
    assert pp.should_apply_field('unk88', 'undefined8', 'void *64', 8, 8, 'high') == \
        (False, 'generic-size-only')


def test_coverage_delta_and_progress():
    before = {'thiscall': 100, 'named_field_bytes': 500, 'unk_field_bytes': 2000, 'typed_params': 30}
    after = {'thiscall': 110, 'named_field_bytes': 524, 'unk_field_bytes': 1976, 'typed_params': 34}
    d = pp.coverage_delta(before, after)
    assert d == {'thiscall': 10, 'named_field_bytes': 24, 'unk_field_bytes': -24, 'typed_params': 4}
    # progress = thiscall 10 + typed_params 4 - unk_field_bytes(-24) = 38 (named not scored)
    assert pp.progress(d) == 38


def test_is_converged():
    big = pp.coverage_delta(
        {'thiscall': 0, 'unk_field_bytes': 1000, 'typed_params': 0},
        {'thiscall': 5, 'unk_field_bytes': 900, 'typed_params': 5})
    assert not pp.is_converged(big)            # progress 5 + 100 = 110 >= 5
    tiny = pp.coverage_delta(
        {'thiscall': 10, 'unk_field_bytes': 1000, 'typed_params': 10},
        {'thiscall': 11, 'unk_field_bytes': 997, 'typed_params': 10})
    assert pp.is_converged(tiny)               # progress 1 + 3 = 4 in [0,5)
    # exact fixpoint
    same = pp.coverage_delta({'thiscall': 1}, {'thiscall': 1})
    assert pp.is_converged(same)


def test_byte_metric_no_false_regression_on_fragmentation():
    # The bug we caught: applying 2 NiColor fields cleanly resolved 24 bytes, but the
    # COMPONENT count rose (fragmentation) and read as a regression. In BYTES the same
    # apply is unambiguous forward progress -- unknown bytes strictly fell.
    d = pp.coverage_delta(
        {'thiscall': 9909, 'named_field_bytes': 1000000, 'unk_field_bytes': 9024, 'typed_params': 17974},
        {'thiscall': 9909, 'named_field_bytes': 1000024, 'unk_field_bytes': 9000, 'typed_params': 17974})
    assert pp.progress(d) == 24                 # +24 bytes resolved, not -12
    assert not pp.is_regression(d)


def test_is_struct_change_safe():
    # good apply: unknown slot -> named field, same length, more protected bytes
    assert pp.is_struct_change_safe((0x100, 200), (0x100, 208))
    # nop: nothing changed
    assert pp.is_struct_change_safe((0x100, 200), (0x100, 200))
    # GROWTH (the MapMenu 0x30560->0x60880 bug) -> unsafe, even if protected rose
    assert not pp.is_struct_change_safe((0x30560, 200), (0x60880, 9999))
    # shrink -> unsafe
    assert not pp.is_struct_change_safe((0x100, 200), (0xF0, 200))
    # clobbered existing RE (protected dropped) at same length -> unsafe
    assert not pp.is_struct_change_safe((0x100, 200), (0x100, 192))


def test_regression_is_not_convergence():
    # A genuine regression: unknown bytes ROSE (something added undefined) -> not a fixpoint
    reg = pp.coverage_delta(
        {'thiscall': 100, 'unk_field_bytes': 1127, 'typed_params': 18282},
        {'thiscall': 100, 'unk_field_bytes': 1227, 'typed_params': 18282})
    assert pp.progress(reg) == -100
    assert pp.is_regression(reg)
    assert not pp.is_converged(reg)


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
