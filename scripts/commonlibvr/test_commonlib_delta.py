#!/usr/bin/env python3
"""Unit tests for commonlib_delta (Ghidra -> CommonLib write-back detection).

Run: python -m pytest test_commonlib_delta.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commonlib_delta as cd  # noqa: E402


def test_is_generic():
    assert cd.is_generic('FUN_140abc')
    assert cd.is_generic('sub_140abc')
    assert cd.is_generic('')
    assert cd.is_generic(None)
    assert not cd.is_generic('Actor::ClearData')
    assert not cd.is_generic('ClearData')


def test_missing_in_ghidra():
    k = cd.classify_delta('Actor::ClearData', 'FUN_140abc', True, '', '', 'DEFAULT')
    assert k == 'MISSING_IN_GHIDRA'


def test_name_delta_on_leaf_mismatch():
    # Ghidra/PDB calls it something else -> write-back candidate
    k = cd.classify_delta('Actor::ClearData', 'TESForm::Reset', False, '', '', 'IMPORTED')
    assert k == 'NAME_DELTA'


def test_dup_address_suffix_is_not_a_name_delta():
    # the classes-phase _<addr> disambiguation suffix must not read as a difference
    assert cd.classify_delta('ActiveEffect::Dispel', 'Dispel_14053E380', False,
                             '', '', 'USER_DEFINED') == 'MATCH'
    assert cd.classify_delta('Actor::GetMagnitude',
                             'GetMagnitude_14053E120_140540EA0', False,
                             '', '', 'USER_DEFINED') == 'MATCH'
    # but a genuinely different base name still reports
    assert cd.classify_delta('Actor::DoDamage', 'TakeDamage_1405D6300', False,
                             '', '', 'IMPORTED') == 'NAME_DELTA'


def test_name_match_ignores_class_prefix():
    # same leaf, different/absent class qualifier -> not a name delta
    k = cd.classify_delta('Actor::ClearData', 'ClearData', False, '', '', 'IMPORTED')
    assert k == 'MATCH'


def test_sig_delta_only_when_trusted():
    # names agree, sigs differ, Ghidra source trusted -> SIG_DELTA
    k = cd.classify_delta('Actor::SetScale', 'SetScale', False,
                          'void(float)', 'bool(float, int)', 'IMPORTED')
    assert k == 'SIG_DELTA'
    # same but Ghidra sig is an analyzer guess -> not evidence, MATCH
    k2 = cd.classify_delta('Actor::SetScale', 'SetScale', False,
                           'void(float)', 'bool(float, int)', 'ANALYSIS')
    assert k2 == 'MATCH'


def test_sig_match_when_equal():
    k = cd.classify_delta('A::f', 'f', False, 'void(int)', 'void(int)', 'IMPORTED')
    assert k == 'MATCH'


def test_summarize():
    out = cd.summarize(['MATCH', 'NAME_DELTA', 'MATCH', 'SIG_DELTA', 'NAME_DELTA'])
    assert out == {'MATCH': 2, 'NAME_DELTA': 2, 'SIG_DELTA': 1}


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
