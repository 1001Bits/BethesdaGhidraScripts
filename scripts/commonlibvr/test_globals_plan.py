#!/usr/bin/env python3
"""Unit tests for globals_plan (globals harvester consensus logic).

Run: python -m pytest test_globals_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import globals_plan as gp  # noqa: E402


def test_aggregate_consensus_single_class():
    obs = [(0x100, 'PlayerCharacter', 'FnA'),
           (0x100, 'PlayerCharacter', 'FnB'),
           (0x100, 'PlayerCharacter', 'FnA')]   # dup caller collapses in callers list
    agg = gp.aggregate_global_types(obs)
    info = agg[0x100]
    assert info['type'] == 'PlayerCharacter'
    assert info['votes'] == 3 and info['total'] == 3 and info['distinct'] == 1
    assert info['callers'] == ['FnA', 'FnB']
    assert gp.global_confidence(info) == 'high'


def test_single_observation_is_medium():
    agg = gp.aggregate_global_types([(0x200, 'Sky', 'FnX')])
    assert gp.global_confidence(agg[0x200]) == 'medium'


def test_conflicting_classes_low_confidence():
    obs = [(0x300, 'TESForm', 'A'), (0x300, 'BGSKeyword', 'B'),
           (0x300, 'TESObjectREFR', 'C')]
    info = gp.aggregate_global_types(obs)[0x300]
    assert info['distinct'] == 3
    assert gp.global_confidence(info) == 'low'


def test_dominant_class_is_medium():
    obs = [(0x400, 'Main', 'A'), (0x400, 'Main', 'B'),
           (0x400, 'Main', 'C'), (0x400, 'Other', 'D')]   # 3 vs 1
    info = gp.aggregate_global_types(obs)[0x400]
    assert info['distinct'] == 2
    assert gp.global_confidence(info) == 'medium'


def test_blank_and_none_ignored():
    obs = [(0x500, '', 'A'), (None, 'Sky', 'B'), (0x500, 'Sky', 'C')]
    agg = gp.aggregate_global_types(obs)
    assert set(agg) == {0x500}
    assert agg[0x500]['type'] == 'Sky' and agg[0x500]['total'] == 1


def test_to_rows_orders_high_confidence_first():
    obs = ([(0x1, 'A', 'f')]                                  # medium (single)
           + [(0x2, 'B', 'f'), (0x2, 'B', 'g')]               # high (consensus)
           + [(0x3, 'C', 'f'), (0x3, 'D', 'g')])              # low (conflict)
    rows = gp.to_rows(gp.aggregate_global_types(obs))
    confidences = [r[2] for r in rows]
    assert confidences == ['high', 'medium', 'low']
    assert rows[0][0] == 0x2                                  # the consensus global first


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
