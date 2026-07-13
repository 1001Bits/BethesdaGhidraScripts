#!/usr/bin/env python3
"""Unit tests for seed_plan (this-pointer seeder decision logic).

Run: python -m pytest test_seed_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seed_plan as sp  # noqa: E402


def test_is_untyped():
    assert sp.is_untyped(None)
    assert sp.is_untyped('')
    assert sp.is_untyped('undefined8')
    assert sp.is_untyped('undefined *')
    assert sp.is_untyped('void *')
    assert sp.is_untyped('void *64')
    assert not sp.is_untyped('Actor *')
    assert not sp.is_untyped('NiNode *64')


def test_set_thiscall_when_unprotected_non_thiscall():
    assert sp.should_set_thiscall(True, 'ClearData', '__fastcall', 'ANALYSIS', False, False)[0] == 'set'
    assert sp.should_set_thiscall(True, 'ClearData', '__cdecl', 'DEFAULT', False, False)[0] == 'set'
    # constructors/destructors take a this too
    assert sp.should_set_thiscall(True, '~Actor', '__fastcall', 'ANALYSIS', False, False)[0] == 'set'


def test_skip_imported_pdb_only():
    # PDB convention may be deliberate / non-member -> skip
    assert sp.should_set_thiscall(True, 'ClearData', '__fastcall', 'IMPORTED', False, False) == \
        ('skip', 'imported-pdb')
    # but USER_DEFINED members ARE convertible (thiscall is the right convention)
    assert sp.should_set_thiscall(True, 'ClearData', '__fastcall', 'USER_DEFINED', False, True)[0] == 'convert'


def test_convert_when_explicit_this():
    # already has an explicit typed this under the wrong convention -> remove+set
    assert sp.should_set_thiscall(True, 'ClearData', '__fastcall', 'ANALYSIS', False, True) == \
        ('convert', 'has-explicit-this')
    assert sp.should_set_thiscall(True, 'ClearData', '__fastcall', 'USER_DEFINED', False, True)[0] == 'convert'


def test_skip_already_thiscall():
    assert sp.should_set_thiscall(True, 'ClearData', '__thiscall', 'ANALYSIS', False, False) == \
        ('skip', 'already-thiscall')


def test_skip_static_operator_unknown_class():
    assert sp.should_set_thiscall(True, 'GetSingleton', '__fastcall', 'ANALYSIS', True, False)[0] == 'skip'
    assert sp.should_set_thiscall(True, 'operator==', '__fastcall', 'ANALYSIS', False, False)[0] == 'skip'
    assert sp.should_set_thiscall(False, 'ClearData', '__fastcall', 'ANALYSIS', False, False) == \
        ('skip', 'class-type-not-found')


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
