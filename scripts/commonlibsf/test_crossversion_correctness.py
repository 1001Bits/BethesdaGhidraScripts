from __future__ import annotations

from collections import defaultdict
import csv
import gzip
import hashlib
import json
from pathlib import Path
import struct

import pytest

from address_library import AddressLibrary
from bsim_offline_match import best_match, is_noise
from ids_parser import parse_ids_h, parse_vtable_h
from extract_sf17_vtable_names import _placeholder_slot
from parse_commonlib_types import _make_symbols
from pe_layout import PELayout, attach_section
from port_sf17_to_sf116 import (
    _reconcile_proposals,
    parse_text_section,
    stream_function_entries,
)
from sf_shift_manifest import (
    ANCHOR_VERSION,
    bind_generated_map,
    _rebuild_semantic_map,
    _write_json_atomic,
    load_layout_identity,
    load_validated,
    map_path,
    read_json_maybe_gzip,
    write_layout_identity,
)
from sf_vtable_policy import strict_patch_vtable_structs


def _v5(version=(1, 16, 236, 0), entries=(0, 0x1000, 0x2000)):
    return (struct.pack('<I4I64sQI', 5, *version, b'Starfield.exe', 8,
                        len(entries)) + struct.pack('<{}I'.format(len(entries)),
                                                    *entries))


def _v1(entries, pointer_size=8, trailing=b''):
    name = b'Starfield.exe'
    blob = bytearray(struct.pack('<I4I', 1, 1, 16, 236, 0))
    blob += struct.pack('<I', len(name)) + name
    blob += struct.pack('<II', pointer_size, len(entries))
    for relocation_id, offset in entries:
        blob += b'\x00' + struct.pack('<QQ', relocation_id, offset)
    return bytes(blob) + trailing


def _minimal_pe(path: Path):
    pe_off = 0x80
    opt_size = 0xF0
    sec_off = pe_off + 24 + opt_size
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, pe_off)
    data[pe_off:pe_off + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, pe_off + 4, 0x8664, 2, 1234,
                     0, 0, opt_size, 0)
    opt = pe_off + 24
    struct.pack_into('<H', data, opt, 0x20B)
    struct.pack_into('<Q', data, opt + 24, 0x140000000)
    struct.pack_into('<I', data, opt + 56, 0x4000)
    for index, (name, rva, chars, raw) in enumerate((
            (b'.text', 0x1000, 0x60000020, 0x400),
            (b'.data', 0x2000, 0xC0000040, 0x600))):
        off = sec_off + index * 40
        data[off:off + len(name)] = name
        struct.pack_into('<IIII', data, off + 8, 0x100, rva, 0x100, raw)
        struct.pack_into('<I', data, off + 36, chars)
    path.write_bytes(data)


def test_address_library_rejects_truncation_and_wrong_version():
    blob = _v5()
    assert AddressLibrary._parse_bytes(blob, (1, 16, 236, 0))[1] == 0x1000
    with pytest.raises(ValueError, match='version mismatch'):
        AddressLibrary._parse_bytes(blob, (1, 16, 244, 0))
    with pytest.raises(ValueError, match='truncated'):
        AddressLibrary._parse_bytes(blob[:-1], (1, 16, 236, 0))
    with pytest.raises(ValueError, match='trailing'):
        AddressLibrary._parse_bytes(blob + b'x', (1, 16, 236, 0))
    wrong_abi = bytearray(blob)
    struct.pack_into('<Q', wrong_abi, 84, 4)
    with pytest.raises(ValueError, match='pointer size'):
        AddressLibrary._parse_bytes(bytes(wrong_abi), (1, 16, 236, 0))


def test_sf_legacy_address_library_rejects_ambiguous_encodings():
    assert AddressLibrary._parse_bytes(
        _v1([(1, 0x1000), (2, 0x2000)]), (1, 16, 236, 0)) == {
            1: 0x1000, 2: 0x2000}
    with pytest.raises(ValueError, match='duplicate relocation ID'):
        AddressLibrary._parse_bytes(
            _v1([(1, 0x1000), (1, 0x2000)]), (1, 16, 236, 0))
    malformed = bytearray(_v1([(1, 0x1000)]))
    malformed[-17] = 0x08
    with pytest.raises(ValueError, match='relocation-ID encoding'):
        AddressLibrary._parse_bytes(bytes(malformed), (1, 16, 236, 0))
    with pytest.raises(ValueError, match='trailing'):
        AddressLibrary._parse_bytes(
            _v1([(1, 0x1000)], trailing=b'x'), (1, 16, 236, 0))
    with pytest.raises(ValueError, match='pointer size'):
        AddressLibrary._parse_bytes(
            _v1([(1, 0x1000)], pointer_size=4), (1, 16, 236, 0))


def test_qualified_namespace_is_preserved(tmp_path):
    (tmp_path / 'IDs.h').write_text(
        'namespace RE::ID::Outer::Inner\n{\n'
        'inline constexpr REL::ID Method{ 7 };\n}\n', encoding='utf-8')
    holder = type('L', (), {'sf_db': {7: 0x1234}})()
    rows = parse_ids_h(str(tmp_path), holder)
    assert [(r['class_'], r['name']) for r in rows] == [('Outer::Inner', 'Method')]


def test_pe_section_kind_is_attached(tmp_path):
    pe = tmp_path / 'sample.exe'
    _minimal_pe(pe)
    layout = PELayout.read(str(pe))
    code = {'t': 'func', 'sf': 0x1010}
    data = {'t': 'func', 'sf': 0x2010}
    assert attach_section(code, 'sf', layout, 'func') and code['t'] == 'func'
    assert attach_section(data, 'sf', layout, 'func') and data['t'] == 'label'
    assert data['kind_mismatch']['sf']['actual'] == 'label'


def test_msvc_col_selects_primary_and_numeric_class_suffix_is_preserved(tmp_path):
    pe = tmp_path / 'sample.exe'
    _minimal_pe(pe)
    blob = bytearray(pe.read_bytes())
    image_base = 0x140000000
    # .data RVA 0x2000 is file offset 0x600.
    struct.pack_into('<Q', blob, 0x678, image_base + 0x2040)
    struct.pack_into('<6I', blob, 0x640, 1, 0, 0, 0x2050, 0x2060, 0x2040)
    pe.write_bytes(blob)
    assert PELayout.read(str(pe)).msvc_vtable_subobject_offset(0x2080) == 0

    (tmp_path / 'IDs_VTABLE.h').write_text(
        'inline constexpr std::array<REL::ID, 2> '
        'hkImageConversion_FLOAT16_to_32{ REL::ID(7), REL::ID(8) };',
        encoding='utf-8')
    holder = type('L', (), {'sf_db': {7: 0x2080, 8: 0x2090}})()
    rows = parse_vtable_h(str(tmp_path), holder)
    assert [row['vtable_class'] for row in rows] == [
        'hkImageConversion_FLOAT16_to_32'] * 2


def test_duplicate_physical_vtable_identity_is_omitted():
    class Layout:
        @staticmethod
        def msvc_vtable_subobject_offset(_rva):
            return 0

        @staticmethod
        def classify_rva(_rva):
            return 'label', '.rdata'

    labels = [
        {'name': 'VTABLE_Actor', 'n': 'VTABLE_Actor', 'sf_off': 0x2000,
         'vtable_class': 'Actor'},
        {'name': 'VTABLE_Actor_1', 'n': 'VTABLE_Actor_1', 'sf_off': 0x2100,
         'vtable_class': 'Actor'},
    ]
    assert not [symbol for symbol in _make_symbols([], labels, Layout())
                if symbol['n'].startswith('VTABLE_Actor')]


def test_nonanchor_vtables_are_strictly_omitted_and_races_rejected():
    def struct(name):
        return {'class_full_name': name, 'vtable_kind': 'primary',
                'subobject_offset': 0, 'slots': [
                    (slot * 8, 'F{}'.format(slot), None, None)
                    for slot in range(4)], 'size': 32}

    structs = {'A': struct('A'), 'B': struct('B'), 'C': struct('C')}
    shift = {'vtables': {
        'A-id': {'class_name': 'A', 'is_primary': True,
                 'subobject_offset': 0, 'reference_slot_count': 4,
                 'ref_to_target': {'0x0': '0x0', '0x1': '0x2', '0x2': '0x3'},
                 'unmatched_ref_slots': ['0x3']},
        'C-id': {'class_name': 'C', 'is_primary': True,
                 'subobject_offset': 0, 'reference_slot_count': 4,
                 'ref_to_target': {'0x0': '0x0', '0x1': '0x1'},
                 'unmatched_ref_slots': ['0x2', '0x3']},
    }}
    strict_patch_vtable_structs(structs, shift, 'sf_test', verbose=False)
    assert set(structs) == {'A'}
    assert [slot[0] for slot in structs['A']['slots']] == [0, 16, 24]

    racing = {'A': struct('A')}
    duplicate = dict(shift)
    duplicate['vtables'] = dict(shift['vtables'])
    duplicate['vtables']['A-other'] = dict(shift['vtables']['A-id'])
    with pytest.raises(ValueError, match='multiple physical'):
        strict_patch_vtable_structs(racing, duplicate, 'sf_test', verbose=False)


def test_tracked_sf_anchor_preserves_physical_vtable_identities():
    path = Path(__file__).with_name('refs') / 'sf_1-16-236-0_vtables.csv.gz'
    tables = {}
    table_slots = defaultdict(int)
    addresses = set()
    rows = 0
    named_rows = 0
    fingerprint_rows = 0
    with gzip.open(path, 'rt', encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            rows += 1
            named_rows += bool((row.get('func_name') or '').strip())
            fingerprint_rows += bool((row.get('fingerprint') or '').strip())
            tables.setdefault(row['vtable_id'], (
                row['class'], int(row['subobject_offset'], 0),
                row['is_primary'], int(row['vtable_addr'], 0)))
            addresses.add(int(row['vtable_addr'], 0))
            table_slots[row['vtable_id']] += 1
    sidecar = json.loads(Path(str(path) + '.identity.json').read_text(
        encoding='utf-8'))
    assert sidecar['layout_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    repo = Path(__file__).parents[2]
    validated = load_layout_identity(
        path, ANCHOR_VERSION,
        '1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351',
        versionlib_path=(repo / 'addresslibrary' / 'starfield' /
                         'versionlib-1-16-236-0.bin'),
        require_function_names_included=True,
        require_fingerprint_mode='raw-bytes-32')
    assert validated['schema_version'] == 2
    assert rows == 232962
    assert named_rows == 232873
    assert fingerprint_rows == 232962
    assert len(tables) == 27648
    assert len(addresses) == 27648
    assert sum(value[2] == '1' for value in tables.values()) == 23479
    assert sum(value[2] == '0' for value in tables.values()) == 4169
    assert len({value[0] for value in tables.values()}) == 23491
    assert len({(value[0], value[2], value[1])
                for value in tables.values()}) == 27648
    assert not any('__sub_' in value[0] for value in tables.values())
    critical = {}
    for identity, value in tables.items():
        if value[2] == '1' and value[0] in {
                'Actor', 'TESForm', 'PlayerCharacter'}:
            critical[value[0]] = table_slots[identity]
    assert critical == {'Actor': 417, 'TESForm': 98,
                        'PlayerCharacter': 421}


def test_shift_map_is_version_hash_and_layout_bound(tmp_path):
    ref = tmp_path / 'ref.csv.gz'
    target = tmp_path / 'target.csv.gz'
    header = ['class', 'vtable_id', 'subobject_offset', 'is_primary',
              'vtable_addr', 'slot', 'func_addr', 'func_name', 'fingerprint']
    def write_layout(path, address_delta, include_names):
        with gzip.open(path, 'wt', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            tables = [
                ('Actor', 1, 0x140010000),
                ('TESForm', 1, 0x140100000),
                ('PlayerCharacter', 1, 0x140110000),
            ] + [
                ('Synthetic{}'.format(index), 10,
                 0x141000000 + index * 0x100)
                for index in range(1000)
            ]
            for cls, count, vt in tables:
                for slot in range(count):
                    fingerprint = ' '.join(
                        '{:02X}'.format(value)
                        for value in (struct.pack('<I', slot) * 8))
                    writer.writerow([
                        cls, cls + '|primary|0x0', '0x0', 1,
                        hex(vt + address_delta), slot,
                        hex(0x140200000 + address_delta + slot * 0x20),
                        ('{}::Method{}'.format(cls, slot)
                         if include_names else ''), fingerprint])
    write_layout(ref, 0, True)
    write_layout(target, 0x100000, False)
    out = tmp_path / 'shift.json'
    out.write_text(json.dumps(
        _rebuild_semantic_map(ref, target, (1, 16, 244, 0))),
        encoding='utf-8')
    sha = 'a' * 64
    write_layout_identity(
        ref, ANCHOR_VERSION, 'c' * 64,
        function_names_included=True,
        fingerprint_mode='raw-bytes-32')
    write_layout_identity(
        target, (1, 16, 244, 0), sha,
        function_names_included=False,
        fingerprint_mode='raw-bytes-32')
    bind_generated_map(out, (1, 16, 244, 0), sha, ref, target)
    assert load_validated(out, (1, 16, 244, 0), sha, ref, target)['classes']
    write_layout(target, 0x100000, True)
    write_layout_identity(
        target, (1, 16, 244, 0), sha,
        function_names_included=True,
        fingerprint_mode='raw-bytes-32')
    with pytest.raises(ValueError, match='function-name policy'):
        load_validated(out, (1, 16, 244, 0), sha, ref, target)
    write_layout(target, 0x100000, False)
    write_layout_identity(
        target, (1, 16, 244, 0), sha,
        function_names_included=False,
        fingerprint_mode='raw-bytes-32')
    bind_generated_map(out, (1, 16, 244, 0), sha, ref, target)
    with pytest.raises(ValueError, match='SHA-256'):
        load_validated(out, (1, 16, 244, 0), 'b' * 64, ref, target)
    bound = json.loads(out.read_text(encoding='utf-8'))
    tampered = json.loads(json.dumps(bound))
    tampered['classes']['Actor']['ref_to_target']['0x0'] = '0x1'
    out.write_text(json.dumps(tampered), encoding='utf-8')
    with pytest.raises(ValueError, match='semantic content'):
        load_validated(out, (1, 16, 244, 0), sha, ref, target)
    out.write_text(json.dumps(bound), encoding='utf-8')
    target.write_bytes(b'changed')
    with pytest.raises(ValueError, match='layout content'):
        load_validated(out, (1, 16, 244, 0), sha, ref, target)


def test_shift_map_ships_compressed_and_reproducibly(tmp_path):
    """The map is stored gzipped, because plain JSON is too big to ship.

    A full Starfield map carries per-slot evidence for ~233k slots and reaches
    ~111 MB uncompressed -- over the 100 MB file limit GitHub enforces, so the
    pre-built map could not be distributed at all.  Only the container changes.
    """
    assert map_path(tmp_path, (1, 16, 244, 0)).name == \
        'shift_sf_1-16-244-0.json.gz'

    doc = {'schema_version': 3, 'classes': {'Actor': {'ref_to_target': {}}}}
    compressed = tmp_path / 'shift.json.gz'
    plain = tmp_path / 'shift.json'
    _write_json_atomic(compressed, doc)
    _write_json_atomic(plain, doc)

    # Same document either way.
    assert read_json_maybe_gzip(compressed) == doc
    assert read_json_maybe_gzip(plain) == doc
    assert gzip.decompress(compressed.read_bytes()) == plain.read_bytes()

    # The artifact is hashed by its consumers, so writing it twice must produce
    # identical bytes -- gzip stores an mtime unless told not to.
    first = compressed.read_bytes()
    _write_json_atomic(compressed, doc)
    assert compressed.read_bytes() == first


def test_id_matched_map_binds_and_revalidates(tmp_path):
    """A map built with Address Library ID matching must survive binding.

    ``_rebuild_semantic_map`` independently re-runs the matcher to prove the
    stored map really is the deterministic diff of the two bound layouts.  It
    therefore has to reproduce what the builder actually did: rebuilding
    without the version libraries yields only the weaker fingerprint-only
    result and rejects an honest map.  This is the real 1.16.244 case -- every
    function moved, so no prologue matches and ID identity is the only signal.
    """
    header = ['class', 'vtable_id', 'subobject_offset', 'is_primary',
              'vtable_addr', 'slot', 'func_addr', 'func_name', 'fingerprint']
    tables = [
        ('Actor', 1, 0x140010000),
        ('TESForm', 1, 0x140100000),
        ('PlayerCharacter', 1, 0x140110000),
    ] + [
        ('Synthetic{}'.format(index), 10, 0x141000000 + index * 0x100)
        for index in range(1000)
    ]

    def write_layout(path, base_rva, include_names, fill):
        """Write a layout where every slot holds a distinct function."""
        rvas = [0]                      # index 0 == "no address for this ID"
        with gzip.open(path, 'wt', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            index = 0
            for cls, count, vt in tables:
                for slot in range(count):
                    rva = base_rva + index * 0x20
                    rvas.append(rva)
                    writer.writerow([
                        cls, cls + '|primary|0x0', '0x0', 1, hex(vt), slot,
                        hex(0x140000000 + rva),
                        ('{}::Method{}'.format(cls, slot) if include_names else ''),
                        ' '.join(['{:02X}'.format(fill)] * 32)])
                    index += 1
        return rvas

    ref = tmp_path / 'ref.csv.gz'
    target = tmp_path / 'target.csv.gz'
    # Target: every function relocated, no names, and different prologue bytes.
    # Neither the name stage nor the fingerprint stage can match anything.
    ref_rvas = write_layout(ref, 0x200000, True, 0xAA)
    target_rvas = write_layout(target, 0x500000, False, 0xBB)

    ref_bin = tmp_path / 'versionlib-1-16-236-0.bin'
    target_bin = tmp_path / 'versionlib-1-16-244-0.bin'
    ref_bin.write_bytes(_v5((1, 16, 236, 0), tuple(ref_rvas)))
    target_bin.write_bytes(_v5((1, 16, 244, 0), tuple(target_rvas)))

    without_ids = _rebuild_semantic_map(ref, target, (1, 16, 244, 0))
    assert not any(item['ref_to_target']
                   for item in without_ids['vtables'].values())

    built = _rebuild_semantic_map(ref, target, (1, 16, 244, 0),
                                  ref_bin, target_bin)
    matched = sum(len(item['ref_to_target'])
                  for item in built['vtables'].values())
    assert matched == len(ref_rvas) - 1 == 10003
    assert {evidence['method']
            for item in built['vtables'].values()
            for evidence in item['match_evidence'].values()} == {
                'address_library_id'}

    out = tmp_path / 'shift.json'
    out.write_text(json.dumps(built), encoding='utf-8')
    sha = 'a' * 64
    write_layout_identity(ref, ANCHOR_VERSION, 'c' * 64,
                          versionlib_path=ref_bin,
                          function_names_included=True,
                          fingerprint_mode='raw-bytes-32')
    write_layout_identity(target, (1, 16, 244, 0), sha,
                          versionlib_path=target_bin,
                          function_names_included=False,
                          fingerprint_mode='raw-bytes-32')

    # Without the version libraries the rebuild cannot reproduce the map, and
    # must say so rather than blame the map's contents.
    with pytest.raises(ValueError, match='Address Library ID matching'):
        bind_generated_map(out, (1, 16, 244, 0), sha, ref, target)

    bind_generated_map(out, (1, 16, 244, 0), sha, ref, target,
                       reference_versionlib=ref_bin,
                       target_versionlib=target_bin)
    assert load_validated(out, (1, 16, 244, 0), sha, ref, target,
                          reference_versionlib=ref_bin,
                          target_versionlib=target_bin)['classes']

    # Tampering must still be caught with the ID stage active.
    bound = json.loads(out.read_text(encoding='utf-8'))
    tampered = json.loads(json.dumps(bound))
    tampered['classes']['Actor']['ref_to_target']['0x0'] = '0x9'
    out.write_text(json.dumps(tampered), encoding='utf-8')
    with pytest.raises(ValueError, match='semantic content'):
        load_validated(out, (1, 16, 244, 0), sha, ref, target,
                       reference_versionlib=ref_bin,
                       target_versionlib=target_bin)


def test_same_version_layout_from_another_binary_is_rejected(tmp_path):
    layout = tmp_path / 'target.csv.gz'
    layout.write_bytes(b'layout')
    version = (1, 16, 244, 0)
    write_layout_identity(layout, version, 'a' * 64)
    assert load_layout_identity(layout, version, 'a' * 64)
    with pytest.raises(ValueError, match='another executable'):
        load_layout_identity(layout, version, 'b' * 64)


def test_offline_bsim_requires_consensus_and_name_margin():
    hashes = frozenset(range(20))
    f1, f2 = ('a' * 32, 1), ('b' * 32, 2)
    index = defaultdict(list)
    for h in hashes:
        index[h].extend((f1, f2))
    names = {f1: ('RE::Actor::Update', 20, 'sf-old.exe'),
             f2: ('RE::Actor::Update', 20, 'sf-new.exe')}
    assert best_match(hashes, index, names)[4] == 2

    names[f2] = ('RE::Actor::Delete', 20, 'sf-new.exe')
    assert best_match(hashes, index, names) is None
    assert is_noise('RE::Actor::Func3')


def test_sf17_slot_zero_maps_to_generated_func1():
    assert _placeholder_slot(0) == 1
    assert _placeholder_slot(416) == 417


def test_bsim_mutation_is_one_cancel_safe_transaction():
    source = Path(__file__).with_name('bsim_query_apply.py').read_text(
        encoding='utf-8')
    assert 'currentProgram.startTransaction(' in source
    assert 'currentProgram.endTransaction(transaction, commit)' in source
    assert 'if monitor.isCancelled()' in source
    assert 'rolling back all renames' in source


def test_generated_versionlib_requires_matching_target_identity(tmp_path):
    name = b'Starfield test generated'.ljust(64, b'\0')
    blob = (struct.pack('<I4I64sQI', 5, 1, 16, 300, 0, name, 8, 2) +
            struct.pack('<2I', 0, 0x1000))
    path = tmp_path / 'versionlib-1-16-300-0.bin'
    path.write_bytes(blob)
    sidecar = Path(str(path) + '.identity.json')
    sidecar.write_text(json.dumps({
        'schema_version': 2, 'artifact': path.name,
        'artifact_sha256': hashlib.sha256(blob).hexdigest(),
        'target_sha256': 'a' * 64,
    }), encoding='utf-8')
    assert AddressLibrary().load_bin(
        str(path), (1, 16, 300, 0), expected_sha256='a' * 64)[1] == 0x1000
    with pytest.raises(ValueError, match='identity mismatch'):
        AddressLibrary().load_bin(
            str(path), (1, 16, 300, 0), expected_sha256='b' * 64)


def test_sf17_xml_parser_is_attribute_order_independent(tmp_path):
    xml = tmp_path / 'source.xml'
    xml.write_text(
        '<PROGRAM><MEMORY_MAP>'
        '<MEMORY_SECTION LENGTH="16" START_ADDR="140001000" NAME=".text">'
        '<MEMORY_CONTENTS FILE_OFFSET="32" FILE_NAME="source.bytes" />'
        '</MEMORY_SECTION></MEMORY_MAP><FUNCTIONS>'
        '<FUNCTION NAME="RE::Actor::Update" ENTRY_POINT="140001000" />'
        '<FUNCTION ENTRY_POINT="140001010" NAME="FUN_140001010" />'
        '</FUNCTIONS></PROGRAM>', encoding='utf-8')
    assert parse_text_section(str(xml)) == (
        0x140001000, 16, 32, 'source.bytes')
    assert list(stream_function_entries(str(xml))) == [
        (0x140001000, 'RE::Actor::Update')]


def test_sf17_port_quarantines_duplicate_names_sources_and_targets():
    proposals = [
        ('0', 0x1000, 'exact32'),  # duplicate semantic name
        ('1', 0x2000, 'exact32'),
        ('2', 0x3000, 'exact32'),  # same source RVA as token 3
        ('3', 0x4000, 'exact32'),
        ('4', 0x5000, 'exact32'),  # duplicate target with token 5
        ('5', 0x5000, 'exact32'),
        ('6', 0x6000, 'exact32'),  # duplicate name has an unmatched sibling
        ('8', 0x7000, 'exact32'),  # duplicate source has an unmatched alias
        ('10', 0x8000, 'exact32'),  # sole valid reciprocal mapping
    ]
    names = {'0': 'Duplicate', '1': 'Duplicate', '2': 'AliasA',
             '3': 'AliasB', '4': 'TargetA', '5': 'TargetB',
             '6': 'AsymmetricName', '7': 'AsymmetricName',
             '8': 'AsymmetricSourceA', '9': 'AsymmetricSourceB',
             '10': 'Unique'}
    sources = {'0': 1, '1': 2, '2': 3, '3': 3,
               '4': 4, '5': 5, '6': 6, '7': 7,
               '8': 8, '9': 8, '10': 10}
    rows = _reconcile_proposals(
        proposals, names, sources,
        {0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000,
         0x7000, 0x8000},
        0x140000000)
    assert rows == [('0x140008000', 'Unique', 'exact32')]
