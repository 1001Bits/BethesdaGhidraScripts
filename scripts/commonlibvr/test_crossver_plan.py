#!/usr/bin/env python3
"""Unit tests for crossver_plan (cross-version field propagation logic).

Run: python -m pytest test_crossver_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crossver_plan as cv  # noqa: E402


def test_field_key():
    assert cv.field_key('fld30580') == 0x30580
    assert cv.field_key('unk0B0') == 0xB0
    assert cv.field_key('pad2C8') == 0x2C8
    assert cv.field_key('off_40') == 0x40
    # semantic names carry no cross-version offset key
    assert cv.field_key('worldSpace') is None
    assert cv.field_key('mapMovie') is None
    assert cv.field_key('') is None
    assert cv.field_key(None) is None


def test_is_concrete():
    assert cv.is_concrete('Actor *')
    assert cv.is_concrete('BSTArray<RE::TESForm *>')
    assert not cv.is_concrete('undefined8')
    assert not cv.is_concrete('ulonglong')
    assert not cv.is_concrete('void *')
    assert not cv.is_concrete('')


def test_is_resolved_and_unknown_target():
    # a runtime that resolved a field -> exportable
    assert cv.is_resolved('fld0B0', 'TESForm *')
    assert not cv.is_resolved('fld0B0', 'undefined8')      # offset-keyed but not typed
    assert not cv.is_resolved('worldSpace', 'TESForm *')   # semantic name, not keyed
    # a field that can receive knowledge -> offset-keyed and still unknown
    assert cv.is_unknown_target('unk0B0', 'undefined8')
    assert cv.is_unknown_target('pad0B0', 'undefined')
    assert not cv.is_unknown_target('fld0B0', 'TESForm *')  # already resolved
    assert not cv.is_unknown_target('worldSpace', 'undefined8')  # not keyed


def test_pick_best_type():
    # consensus wins
    assert cv.pick_best_type(['TESForm *', 'TESForm *', 'undefined8']) == ('TESForm *', False)
    # generics ignored when a concrete type exists
    assert cv.pick_best_type(['undefined8', 'Actor *']) == ('Actor *', False)
    # genuine conflict between concrete types -> flagged; deterministic winner
    best, conflict = cv.pick_best_type(['Actor *', 'TESForm *'])
    assert conflict and best in ('Actor *', 'TESForm *')
    assert cv.pick_best_type(['Actor *', 'Actor *', 'TESForm *'])[0] == 'Actor *'
    # all generic -> returns one, no conflict
    assert cv.pick_best_type(['undefined8', 'ulonglong'])[1] is False
    assert cv.pick_best_type([]) == (None, False)


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
