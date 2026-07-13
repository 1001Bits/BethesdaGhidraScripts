#!/usr/bin/env python3
"""Unit tests for writeback_aggregate (cross-runtime delta triage).

Run: python -m pytest test_writeback_aggregate.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import writeback_aggregate as wa  # noqa: E402


def test_reconcile_when_delta_in_all_mapped():
    # mapped in all three, NAME_DELTA everywhere -> one CommonLib name fix
    v, st = wa.classify_symbol({'se', 'ae', 'vr'},
                               {'se': 'NAME_DELTA', 'ae': 'NAME_DELTA', 'vr': 'NAME_DELTA'})
    assert v == 'RECONCILE'
    assert wa.absent_runtimes(st) == []


def test_runtime_specific_points_at_diverging_runtime():
    # SE/AE match, VR disagrees -> VR address suspect (e.g. an iteratively-added
    # VR offset pointing at the wrong function)
    v, st = wa.classify_symbol({'se', 'ae', 'vr'}, {'vr': 'NAME_DELTA'})
    assert v == 'RUNTIME_SPECIFIC'
    delta, trusted = wa.suspect_runtimes(st)
    assert delta == ['vr'] and trusted == ['se', 'ae']


def test_iterative_coverage_se_ae_only():
    # CommonLib mapped SE+AE only (VR not yet added); both match -> nothing to fix,
    # but VR is an open coverage candidate
    v, st = wa.classify_symbol({'se', 'ae'}, {})
    assert v == 'MATCH'
    assert wa.absent_runtimes(st) == ['vr']


def test_runtime_specific_with_partial_coverage():
    # mapped SE+VR only; SE matches, VR disagrees -> VR suspect, AE simply unmapped
    v, st = wa.classify_symbol({'se', 'vr'}, {'vr': 'NAME_DELTA'})
    assert v == 'RUNTIME_SPECIFIC'
    delta, trusted = wa.suspect_runtimes(st)
    assert delta == ['vr'] and trusted == ['se']
    assert wa.absent_runtimes(st) == ['ae']


def test_apply_gap_only():
    v, st = wa.classify_symbol({'se', 'ae', 'vr'}, {'ae': 'MISSING_IN_GHIDRA'})
    assert v == 'APPLY_GAP'


def test_name_delta_beats_missing_for_runtime_specific():
    # a name delta in one runtime + a generic miss in another -> still surfaced as
    # the higher-signal RUNTIME_SPECIFIC, not APPLY_GAP
    v, st = wa.classify_symbol({'se', 'ae', 'vr'},
                               {'vr': 'NAME_DELTA', 'ae': 'MISSING_IN_GHIDRA'})
    assert v == 'RUNTIME_SPECIFIC'


def test_aggregate_joins_by_name():
    present = {'se': {'A::f', 'B::g'}, 'ae': {'A::f', 'B::g'}, 'vr': {'A::f'}}
    delta = {'se': {}, 'ae': {}, 'vr': {'A::f': 'NAME_DELTA'}}
    out = wa.aggregate({'A::f', 'B::g'}, present, delta)
    assert out['A::f'][0] == 'RUNTIME_SPECIFIC'   # VR-only delta
    assert out['B::g'][0] == 'MATCH'              # SE/AE match, VR unmapped
    assert wa.absent_runtimes(out['B::g'][1]) == ['vr']


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
