from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_pdb_layouts
import parse_layouts
from apply_structs import (anonymous_union_name, checked_place,
                           normalize_legacy_field, prepare_field_groups,
                           unique_component_name)
from apply_this import is_safe_this_type
from layout_schema import load_document, make_document, validate_program


class _Program:
    def __init__(self, name, ptr):
        self.name = name
        self.ptr = ptr

    def getName(self):
        return self.name

    def getExecutablePath(self):
        return self.name

    def getDefaultPointerSize(self):
        return self.ptr


def test_clang_layout_parser_preserves_union_overlap_and_kind():
    text = '''
*** Dumping AST Record Layout
         0 | union hkValue
         0 |   hkInt32 m_int
         0 |   hkReal m_real
           | [sizeof=4, align=4,
'''
    record = parse_layouts.parse(text)['hkValue']
    assert record['kind'] == 'union'
    assert [(f['offset'], f['name']) for f in record['fields']] == [
        (0, 'm_int'), (0, 'm_real')]


def test_pdb_layout_parser_preserves_union_and_array_type():
    text = '''union hkValue [sizeof = 8] {
  data +0x00 [sizeof=4] int m_int
  data +0x00 [sizeof=8] float m_values[2]
}
'''
    record = build_pdb_layouts.parse(text)['hkValue']
    assert record['kind'] == 'union'
    assert record['fields'][1] == {
        'offset': 0, 'type': 'float[2]', 'name': 'm_values'}


def test_layout_document_is_target_and_architecture_bound(tmp_path):
    p = tmp_path / 'custom.json'
    doc = make_document(
        {'hkFoo': {'size': 4, 'align': 4, 'kind': 'struct', 'fields': []}},
        pointer_size=4, havok_version='7.1.0', targets=['FalloutNV.exe'],
        source='unit test')
    p.write_text(json.dumps(doc), encoding='utf-8')
    records, meta = load_document(p)
    assert 'hkFoo' in records
    validate_program(_Program('FalloutNV.exe', 4), meta)
    with pytest.raises(ValueError, match='64-bit'):
        validate_program(_Program('FalloutNV.exe', 8), meta)
    with pytest.raises(ValueError, match='targets'):
        validate_program(_Program('Fallout4.exe', 4), meta)


def test_unknown_legacy_layout_is_rejected(tmp_path):
    p = tmp_path / 'unknown.json'
    p.write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='reviewed manifest'):
        load_document(p)


def test_legacy_array_declarator_moves_from_name_to_type_once():
    normalized = normalize_legacy_field({
        'offset': 0, 'name': 'u[4]', 'type': 'unsigned int'})
    assert normalized['name'] == 'u'
    assert normalized['type'] == 'unsigned int[4]'

    already_typed = normalize_legacy_field({
        'offset': 0, 'name': 'u[4]', 'type': 'unsigned int[4]'})
    assert already_typed['name'] == 'u'
    assert already_typed['type'] == 'unsigned int[4]'


def test_equal_offset_fields_form_one_bounded_anonymous_union_group():
    groups = prepare_field_groups([
        {'offset': 0, 'name': 'as_u32[2]', 'type': 'unsigned int'},
        {'offset': 0, 'name': 'as_u64', 'type': 'unsigned long long'},
        {'offset': 8, 'name': 'tail', 'type': 'unsigned int'},
    ], 16)
    assert [(offset, span, len(members))
            for offset, span, members in groups] == [(0, 8, 2), (8, 8, 1)]
    assert groups[0][2][0]['name'] == 'as_u32'
    assert groups[0][2][0]['type'] == 'unsigned int[2]'
    assert anonymous_union_name('A::B', 0) == anonymous_union_name('A::B', 0)
    assert anonymous_union_name('A::B', 0) != anonymous_union_name('A/B', 0)


def test_tracked_sf_overlap_preserves_every_json_node_alternative():
    path = HERE / 'refs' / 'havok_layouts_sf_2018.json'
    records, _meta = load_document(path)
    record = records['hkJsonNode']
    groups = prepare_field_groups(record['fields'], record['size'])
    overlap = next(members for offset, _span, members in groups if offset == 8)
    assert {member['name'] for member in overlap} == {
        'm_compound', 'm_element', 'm_string', 'm_boolean', 'm_number',
        'm_invalid'}


def test_unexpected_havok_placement_failure_is_fatal():
    def fail():
        raise RuntimeError('Ghidra rejected component')

    with pytest.raises(RuntimeError, match=r'hkFoo.*\+0x8'):
        checked_place(fail, 'hkFoo', 8, 'field value')


def test_duplicate_flattened_component_names_are_preserved_deterministically():
    used = set()
    assert unique_component_name('m_value', used) == 'm_value'
    assert unique_component_name('m_value_2', used) == 'm_value_2'
    assert unique_component_name('m_value', used) == 'm_value_3'
    assert unique_component_name('', used) == 'member'
    assert unique_component_name('', used) == 'member_2'


def test_reviewed_legacy_filename_cannot_launder_changed_content(tmp_path):
    p = tmp_path / 'havok_layouts.json'
    p.write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='content hash mismatch'):
        load_document(p)


def test_this_typing_never_overwrites_integer_or_typed_pointer():
    assert is_safe_this_type('undefined4')
    assert is_safe_this_type('void *')
    assert not is_safe_this_type('int')
    assert not is_safe_this_type('hkWorld *')
