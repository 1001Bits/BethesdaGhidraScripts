#!/usr/bin/env python3
"""Unit tests for propagate_plan (call-graph type-propagation decision logic).

Run: python -m pytest test_propagate_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import propagate_plan as pp  # noqa: E402


def test_is_generic():
    assert pp.is_generic(None)
    assert pp.is_generic('')
    assert pp.is_generic('undefined8')
    assert pp.is_generic('undefined *')
    assert pp.is_generic('void')
    assert pp.is_generic('void *')
    assert pp.is_generic('longlong')
    assert pp.is_generic('ulonglong *')
    assert pp.is_generic('uint')
    assert not pp.is_generic('Actor *')
    assert not pp.is_generic('NiNode *64')
    assert not pp.is_generic('Stream *')


def test_is_concrete_named():
    assert pp.is_concrete_named('Actor *')
    assert pp.is_concrete_named('TESForm *64')
    assert not pp.is_concrete_named('undefined8')
    assert not pp.is_concrete_named('longlong')
    assert not pp.is_concrete_named('')
    assert not pp.is_concrete_named(None)


def test_safe_refinement_accepts_real_gain():
    # the one kind we DO commit: generic -> concrete named pointer
    assert pp.safe_refinement('undefined8', 'Stream *')
    assert pp.safe_refinement('undefined *', 'Actor *')
    assert pp.safe_refinement('void *', 'TESObjectREFR *')
    assert pp.safe_refinement('', 'NiNode *')


def test_safe_refinement_refuses_noise_and_clobber():
    # generic -> generic (the dominant decompiler output) is noise
    assert not pp.safe_refinement('undefined8', 'longlong')
    assert not pp.safe_refinement('undefined8', 'ulonglong *')
    # concrete -> void / generic is a downgrade (protect existing RE)
    assert not pp.safe_refinement('undefined', 'void')
    assert not pp.safe_refinement('Actor *', 'void')
    assert not pp.safe_refinement('Actor *', 'longlong')
    # concrete -> different concrete: do NOT overwrite existing RE automatically
    assert not pp.safe_refinement('Actor *', 'TESForm *')
    # no-op
    assert not pp.safe_refinement('Actor *', 'Actor *')
    assert not pp.safe_refinement('undefined8', 'undefined8')


def test_is_protected():
    assert pp.is_protected('IMPORTED')
    assert pp.is_protected('USER_DEFINED')
    assert not pp.is_protected('ANALYSIS')
    assert not pp.is_protected('DEFAULT')


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
