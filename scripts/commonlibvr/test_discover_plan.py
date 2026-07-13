#!/usr/bin/env python3
"""Unit tests for discover_plan (CommonLib<->Ghidra discovery aggregation).

Run: python -m pytest test_discover_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import discover_plan as dp  # noqa: E402


def test_named_type_beats_generic():
    obs = [('Actor', 0x88, 'ulonglong'),
           ('Actor', 0x88, 'NiNode *'),
           ('Actor', 0x88, 'ulonglong')]
    agg = dp.aggregate_inferences(obs)
    info = agg[('Actor', 0x88)]
    assert info['type'] == 'NiNode *'   # named wins even though ulonglong has more votes
    assert info['named'] and info['confidence'] == 'high'


def test_generic_needs_consensus_for_high_confidence():
    # single generic inference -> low confidence
    agg = dp.aggregate_inferences([('C', 0x10, 'ulonglong')])
    assert agg[('C', 0x10)]['confidence'] == 'low'
    # two functions agree on the generic -> high
    agg2 = dp.aggregate_inferences([('C', 0x10, 'ulonglong'), ('C', 0x10, 'ulonglong')])
    assert agg2[('C', 0x10)]['confidence'] == 'high'
    assert agg2[('C', 0x10)]['votes'] == 2


def test_single_named_is_high_confidence():
    agg = dp.aggregate_inferences([('C', 0x20, 'BSTArray<RE::TESForm *>')])
    info = agg[('C', 0x20)]
    assert info['named'] and info['confidence'] == 'high' and info['votes'] == 1


def test_empty_and_blank_types_ignored():
    agg = dp.aggregate_inferences([('C', 0x0, ''), ('C', 0x0, None)])
    assert agg == {}


def test_to_rows_sorts_high_confidence_first():
    obs = [('Z', 0x8, 'ulonglong'),            # low
           ('A', 0x10, 'CombatEquipment'),     # high (named)
           ('A', 0x18, 'ulonglong'), ('A', 0x18, 'ulonglong')]  # high (consensus)
    agg = dp.aggregate_inferences(obs)
    rows = dp.to_rows(agg, lambda c, o: 'unk%X' % o)
    # high-confidence rows come first
    assert rows[0][4] == 'high'
    assert rows[-1][:2] == ('Z', 0x8) and rows[-1][4] == 'low'
    # current-name column populated from the callback
    assert rows[0][2].startswith('unk')


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
