#!/usr/bin/env python3
"""Unit tests for ctor_plan (constructor-mining review aid logic).

Run: python -m pytest test_ctor_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctor_plan as cm  # noqa: E402


def test_is_ctor():
    assert cm.is_ctor('Crime_ctor', 'Crime')
    assert cm.is_ctor('Actor::Actor', 'Actor')
    assert cm.is_ctor('TESObjectREFR_ctor', 'TESObjectREFR')
    assert cm.is_ctor('SomeClass_Constructor', 'SomeClass')
    # not constructors
    assert not cm.is_ctor('IsCrimeViolent', 'Crime')
    assert not cm.is_ctor('DoActor', 'Actor')          # 'ctor' substring must NOT match
    assert not cm.is_ctor('~Crime', 'Crime')           # destructor
    assert not cm.is_ctor('', 'Crime')


def test_field_label():
    assert cm.field_label('a_object') == 'object'
    assert cm.field_label('a_crimeType') == 'crimeType'
    assert cm.field_label('p_owner') == 'owner'
    assert cm.field_label('victim') == 'victim'        # no prefix, kept
    # noise / empty -> None (keep the type, not a meaningless name)
    assert cm.field_label('a_param') is None
    assert cm.field_label('this') is None
    assert cm.field_label('') is None
    assert cm.field_label(None) is None


def test_best_ctor():
    assert cm.best_ctor([('a', 3), ('b', 7), ('c', 1)]) == 'b'
    assert cm.best_ctor([('a', 0), ('b', 0)]) is None   # none assign anything
    assert cm.best_ctor([]) is None
    assert cm.best_ctor([('a', 2), ('b', 2)]) == 'a'    # tie -> first


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
