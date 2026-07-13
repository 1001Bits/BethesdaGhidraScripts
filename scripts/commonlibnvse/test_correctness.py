from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pytest

from addressing import (AddressError, FNV_IMAGE_BASE, VTableRecord,
                        load_vtable_records, normalize_address)
from extract_pc_fnv_string_xrefs import find_function_start_for_offset
from extract_xbox_rare_immediates import scan_all_ppc_immediates
from extract_xbox_string_xrefs import scan_ppc_string_xrefs
from pdb_naming import (_load_constructor_names, _verified_entry_source)
from pdb_signatures import load_sigs
from paths import (FNVLayoutError, _normalized_vtable_digest,
                   _validate_fnv_manifest, attest_pc_corpus_layout)
from vtable_schema import load_xbox_tables, make_document


def _ppc_dform(op, rt_or_rs, ra, imm):
    return ((op << 26) | (rt_or_rs << 21) | (ra << 16) |
            (imm & 0xFFFF))


def test_address_coordinates_are_explicit_and_bounded():
    assert normalize_address(0x00401234, 'VA') == 0x1234
    assert normalize_address(0x1234, 'RVA') == 0x1234
    with pytest.raises(AddressError):
        normalize_address(0x1234, 'VA')
    with pytest.raises(AddressError):
        normalize_address(0x02000000, 'RVA')
    with pytest.raises(AddressError):
        normalize_address(1, 'guess')


def test_vtable_parser_preserves_duplicate_physical_tables(tmp_path):
    p = tmp_path / 'tables.txt'
    p.write_text(
        '# ADDRESS_COORDINATE=RVA\n'
        'VTABLE|0x00100000|Foo|1 vfuncs|primary\n'
        '  VFUNC|0x00001000|Foo::vf000\n'
        'VTABLE|0x00100100|Foo|1 vfuncs|Base\n'
        '  VFUNC|0x00002000|Foo::vf000\n', encoding='utf-8')
    tables = load_vtable_records([p])
    assert len(tables) == 2
    assert len({t.identity for t in tables}) == 2
    assert [t.subobject for t in tables] == ['primary', 'Base']
    assert [t.slots[0][1] for t in tables] == [0x1000, 0x2000]


def test_committed_mixed_coordinate_vtables_normalize_without_negatives():
    tables = load_vtable_records([
        HERE / 'refs' / 'fnv_pc_vtables.txt',
        HERE / 'refs' / 'fnv_pc_vtables_rtti_extra.txt'])
    assert tables
    assert all(0 < t.table_rva < 0x02000000 for t in tables)
    assert all(0 < rva < 0x02000000 for t in tables for _, rva in t.slots)


def test_nearest_padding_transition_wins():
    code = bytearray(b'\x55' * 80)
    code[10:12] = b'\xCC\xCC'
    code[30:32] = b'\x90\x90'
    assert find_function_start_for_offset(bytes(code), 0x401000, 60) == 0x401020


def test_constructor_corpus_requires_fixed_evidence_marker(tmp_path):
    p = tmp_path / 'ctors.csv'
    p.write_text('0x1000|Foo::Foo|0x500000\n', encoding='utf-8')
    evidence = 'nearest-start;max-distance=256;opcode=C7'
    assert _load_constructor_names(p, required_evidence=evidence) == []
    p.write_text('# EVIDENCE=' + evidence + '\n'
                 '0x1000|Foo::Foo|0x500000\n', encoding='utf-8')
    assert _load_constructor_names(p, required_evidence=evidence) == [
        (0x1000, 'Foo::Foo')]


def test_ppc_ori_uses_rs_bits21_and_ra_destination_bits16():
    target = 0x12345678
    code = struct.pack('>II',
                       _ppc_dform(15, 3, 0, 0x1234),   # lis r3,0x1234
                       _ppc_dform(24, 3, 4, 0x5678))   # ori r4,r3,0x5678
    assert scan_ppc_string_xrefs(code, 0x82000000, {target}) == [
        (0x82000004, target)]
    assert list(scan_all_ppc_immediates(code, 0x82000000))[-1] == (
        0x82000004, target)


def test_overload_signatures_are_not_first_wins(tmp_path):
    p = tmp_path / 'funcs.json'
    p.write_text(json.dumps({'Foo': [
        {'name': 'Foo::Bar', 'sig': 'void __thiscall Foo::Bar(int)'},
        {'name': 'Foo::Bar', 'sig': 'void __thiscall Foo::Bar(float)'},
    ]}), encoding='utf-8')
    index = load_sigs(p)
    assert index.get('Foo::Bar') is None
    assert index.resolve('Foo::Bar', 'void Foo::Bar(int)') == \
        'void Foo::Bar(int)'
    assert index.resolve('Foo::Bar') is None


def test_xbox_v2_schema_retains_same_class_tables():
    doc = make_document([
        {'id': 'a', 'class': 'Foo', 'subobject': '', 'rva': 1, 'slots': []},
        {'id': 'b', 'class': 'Foo', 'subobject': 'Base', 'rva': 2, 'slots': []},
    ], address_coordinate='RVA')
    tables = load_xbox_tables(doc)
    assert [t.identity for t in tables] == ['a', 'b']
    assert [t.subobject for t in tables] == ['', 'Base']


def test_x86_function_creation_evidence_is_fail_closed(tmp_path):
    from addresses import _scan_header, load_overlay_csv

    header = tmp_path / 'symbols.h'
    header.write_text(
        'class Foo { DEFINE_MEMBER_FN(Bar, void, 0x00401000); };\n'
        'static void (*RealProc)(int) = (void (*)(int))0x00402000;\n',
        encoding='utf-8')
    rows = _scan_header(str(header))
    funcs = [row for row in rows if row['kind'] == 'func']
    assert funcs and all(row.get('verified_entry') is True for row in funcs)

    overlay = tmp_path / 'names.csv'
    overlay.write_text(
        'name,rva,coordinate,kind,class,verified_entry\n'
        'Guess,0x3000,RVA,func,,false\n'
        'PdbProc,0x4000,RVA,func,,true\n', encoding='utf-8')
    loaded = {row['name']: row for row in load_overlay_csv(str(overlay))}
    assert loaded['Guess']['verified_entry'] is False
    assert loaded['PdbProc']['verified_entry'] is True

    assert _verified_entry_source('xbox_vtable')
    assert _verified_entry_source('xbox_pdb_matched')
    assert not _verified_entry_source('ctor_byte_scan')
    assert not _verified_entry_source('thunk_jmp')
    assert not _verified_entry_source('string_xref')


def test_fnv_fixed_address_corpus_requires_exact_semantic_target():
    valid = {
        'machine': 0x14C,
        'pointer_size': 4,
        'image_base': 0x00400000,
        'image_size': 0x01000000,
        'file_version': [1, 4, 0, 525],
    }
    assert _validate_fnv_manifest(valid) is valid
    for changed in (
            dict(valid, machine=0x8664),
            dict(valid, image_base=0x140000000),
            dict(valid, file_version=[1, 4, 0, 526]),
            dict(valid, image_size=0x03000000)):
        with pytest.raises(ValueError, match='not the reviewed'):
            _validate_fnv_manifest(changed)


def _synthetic_fnv_layout(tmp_path):
    target = tmp_path / 'FalloutNV.exe'
    blob = bytearray(0x200)
    table_rva = 0x1010
    function_rvas = (0x2000, 0x2010)
    struct.pack_into('<II', blob, 0x10,
                     FNV_IMAGE_BASE + function_rvas[0],
                     FNV_IMAGE_BASE + function_rvas[1])
    target.write_bytes(blob)
    manifest = {
        'machine': 0x14C,
        'pointer_size': 4,
        'image_base': FNV_IMAGE_BASE,
        'image_size': 0x4000,
        'file_version': [1, 4, 0, 525],
        'sections': [
            {'name': '.rdata', 'rva': 0x1000, 'virtual_size': 0x100,
             'raw_size': 0x100, 'raw_offset': 0,
             'readable': True, 'executable': False},
            {'name': '.text', 'rva': 0x2000, 'virtual_size': 0x100,
             'raw_size': 0x100, 'raw_offset': 0x100,
             'readable': True, 'executable': True},
        ],
    }
    record = VTableRecord(
        table_rva=table_rva, class_name='ReviewedClass', declared_slots=2,
        source='synthetic', occurrence=0,
        slots=[(0, function_rvas[0]), (1, function_rvas[1])])
    return target, manifest, record


def test_fnv_layout_attestation_accepts_every_exact_slot(tmp_path):
    target, manifest, record = _synthetic_fnv_layout(tmp_path)
    digest = _normalized_vtable_digest([record])
    assert attest_pc_corpus_layout(
        target, manifest, [record], expected_tables=1, expected_slots=2,
        expected_digest=digest) is manifest


def test_fnv_layout_attestation_rejects_one_pointer_mismatch(tmp_path):
    target, manifest, record = _synthetic_fnv_layout(tmp_path)
    blob = bytearray(target.read_bytes())
    struct.pack_into('<I', blob, 0x14, FNV_IMAGE_BASE + 0x2020)
    target.write_bytes(blob)
    with pytest.raises(FNVLayoutError, match='pointer mismatch'):
        attest_pc_corpus_layout(
            target, manifest, [record], expected_tables=1,
            expected_slots=2, expected_digest=None)


def test_fnv_layout_attestation_rejects_unbacked_table(tmp_path):
    target, manifest, record = _synthetic_fnv_layout(tmp_path)
    manifest['sections'][0]['raw_size'] = 0x10
    with pytest.raises(FNVLayoutError, match='file-backed'):
        attest_pc_corpus_layout(
            target, manifest, [record], expected_tables=1,
            expected_slots=2, expected_digest=None)


def test_fnv_layout_attestation_rejects_section_role_inversion(tmp_path):
    target, manifest, record = _synthetic_fnv_layout(tmp_path)
    manifest['sections'][0]['executable'] = True
    with pytest.raises(FNVLayoutError, match='readable data'):
        attest_pc_corpus_layout(
            target, manifest, [record], expected_tables=1,
            expected_slots=2, expected_digest=None)


def test_fnv_layout_attestation_rejects_reduced_or_changed_corpus(tmp_path):
    target, manifest, record = _synthetic_fnv_layout(tmp_path)
    with pytest.raises(FNVLayoutError, match='coverage changed'):
        attest_pc_corpus_layout(
            target, manifest, [record], expected_tables=2,
            expected_slots=2, expected_digest=None)
    with pytest.raises(FNVLayoutError, match='identity changed'):
        attest_pc_corpus_layout(
            target, manifest, [record], expected_tables=1,
            expected_slots=2, expected_digest='0' * 64)
