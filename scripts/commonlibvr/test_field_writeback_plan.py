#!/usr/bin/env python3
"""Unit tests for field_writeback_plan (CommonLib field write-back logic).

Run: python -m pytest test_field_writeback_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import field_writeback_plan as wp  # noqa: E402


def test_pointer_is_safe():
    assert wp.demangle_type('Actor *') == ('Actor*', 'pointer', True)
    assert wp.demangle_type('TESFaction *64') == ('TESFaction*', 'pointer', True)
    assert wp.demangle_type('NiAVObject *64') == ('NiAVObject*', 'pointer', True)


def test_primitive_mapped():
    assert wp.demangle_type('uint') == ('std::uint32_t', 'primitive', True)
    assert wp.demangle_type('byte') == ('std::uint8_t', 'primitive', True)
    assert wp.demangle_type('ulonglong') == ('std::uint64_t', 'primitive', True)
    assert wp.demangle_type('bool') == ('bool', 'primitive', True)


def test_array_safe_when_base_safe():
    cpp, kind, safe = wp.demangle_type('byte[3]')
    assert kind == 'array' and safe is True
    assert wp.cpp_member(cpp, kind, 'fld13D') == 'std::uint8_t fld13D[3]'


def test_bitfield_skipped():
    assert wp.demangle_type('byte:2') == (None, 'bitfield', False)
    assert wp.demangle_type('uint:18') == (None, 'bitfield', False)


def test_smart_pointer_is_safe_both_forms():
    # proper C++ form Ghidra also emits: strip RE::, treat as an 8-byte slot
    cpp, kind, safe = wp.demangle_type('NiPointer<RE::NiAVObject>')
    assert kind == 'smartptr' and safe is True and cpp == 'NiPointer<NiAVObject>'
    # mangled form -> same
    cpp2, kind2, safe2 = wp.demangle_type('NiPointer_NiSourceTexture_')
    assert kind2 == 'smartptr' and safe2 is True and cpp2 == 'NiPointer<NiSourceTexture>'
    cpp3, _k, safe3 = wp.demangle_type('BSTSmartPointer<RE::MapCameraStates::Exit>')
    assert safe3 is True and cpp3 == 'BSTSmartPointer<MapCameraStates::Exit>'


def test_container_template_reported_not_safe():
    # sized containers are spelled but not auto-safe (size varies / may need a merge)
    cpp, kind, safe = wp.demangle_type('BSTArray<RE::NiPointer<RE::NiAVObject>>')
    assert kind == 'template' and safe is False
    assert cpp == 'BSTArray<NiPointer<NiAVObject>>'


def test_inline_class_not_auto_safe():
    # a bare class name as a non-pointer member needs the full definition -> not safe
    assert wp.demangle_type('CRITICAL_SECTION') == ('CRITICAL_SECTION', 'class', False)


def test_pointer_member_format():
    cpp, kind, _ = wp.demangle_type('Actor *')
    assert wp.cpp_member(cpp, kind, 'fld10') == 'Actor* fld10'


def test_reconcile_agreement_is_safe():
    rows = {
        'se': [('Crime', '0x58', 'TESFaction *64')],
        'ae': [('Crime', '0x58', 'TESFaction *')],
        'vr': [('Crime', '0x58', 'TESFaction *64')],
    }
    out = wp.reconcile(rows)
    rec = out[('Crime', '0x58')]
    assert rec['cpp'] == 'TESFaction*' and rec['safe'] is True
    assert rec['conflict'] is False and rec['runtimes'] == ['ae', 'se', 'vr']


def test_reconcile_conflict_not_safe():
    rows = {
        'se': [('X', '0x10', 'Actor *')],
        'ae': [('X', '0x10', 'TESObjectREFR *')],
    }
    out = wp.reconcile(rows)
    rec = out[('X', '0x10')]
    assert rec['conflict'] is True and rec['safe'] is False


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
