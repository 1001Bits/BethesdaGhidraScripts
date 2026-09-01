from __future__ import annotations

from pathlib import Path
import importlib.util
import struct

import pytest

from vtable_policy import allow_vtable_emission

_SPEC = importlib.util.spec_from_file_location(
    'commonlibsse_address_library', Path(__file__).with_name('address_library.py'))
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
AddressLibrary = _MODULE.AddressLibrary


def _dotnet_string(value):
    encoded = value.encode('utf-8')
    length = len(encoded)
    prefix = bytearray()
    while length >= 0x80:
        prefix.append((length & 0x7F) | 0x80)
        length >>= 7
    prefix.append(length)
    return bytes(prefix) + encoded


def _relib(versions, fmt=2, pointer_size=8, trailing=b'', high_id=1000):
    blob = bytearray(struct.pack('<iQiB', fmt, high_id, pointer_size, 1))
    blob += _dotnet_string('SkyrimSE.exe')
    blob += struct.pack('<i', len(versions))
    for version, entries in versions:
        blob += struct.pack('<i', len(version))
        blob += struct.pack('<{}I'.format(len(version)), *version)
        blob += b'\x00'
        blob += struct.pack('<qi', 0x140000000, len(entries))
        for relocation_id, offset in entries:
            blob += struct.pack('<QI', relocation_id, offset)
        if fmt == 2:
            blob += struct.pack('<i', 0)
    return bytes(blob) + trailing


def test_legacy_vr_shift_map_cannot_enable_vtable_overlay(tmp_path):
    anchors = tmp_path / 'svr.csv'
    shift = tmp_path / 'shift_svr.json'
    anchors.write_text('class,method,slot\n', encoding='utf-8')
    shift.write_text('{"classes": {}}', encoding='utf-8')
    allowed, reason = allow_vtable_emission('svr', str(anchors), str(shift))
    assert not allowed
    assert 'identity-bound' in reason


def test_canonical_skyrim_overlay_requires_anchors_and_no_shift(tmp_path):
    anchors = tmp_path / 'se.csv'
    shift = tmp_path / 'shift_se.json'
    assert not allow_vtable_emission('se', str(anchors), str(shift))[0]
    anchors.write_text('class,method,slot\n', encoding='utf-8')
    assert allow_vtable_emission('se', str(anchors), str(shift))[0]
    shift.write_text('{}', encoding='utf-8')
    assert not allow_vtable_emission('se', str(anchors), str(shift))[0]


def _address_bin(entries, trailing=b''):
    body = bytearray()
    body += struct.pack('<I4I', 1, 1, 5, 97, 0)
    body += struct.pack('<I', len(b'SkyrimSE.exe')) + b'SkyrimSE.exe'
    body += struct.pack('<II', 8, len(entries))
    for relocation_id, offset in entries:
        body += b'\x00' + struct.pack('<QQ', relocation_id, offset)
    return bytes(body) + trailing


def test_sse_binary_address_library_rejects_duplicates_and_trailing_bytes(tmp_path):
    path = tmp_path / 'version.bin'
    path.write_bytes(_address_bin([(1, 0x1000), (2, 0x2000)]))
    assert AddressLibrary().load_bin(str(path), (1, 5, 97, 0)) == {
        1: 0x1000, 2: 0x2000}

    path.write_bytes(_address_bin([(1, 0x1000), (1, 0x2000)]))
    with pytest.raises(ValueError, match='duplicate relocation ID'):
        AddressLibrary().load_bin(str(path), (1, 5, 97, 0))

    path.write_bytes(_address_bin([(1, 0x1000)], trailing=b'junk'))
    with pytest.raises(ValueError, match='trailing bytes'):
        AddressLibrary().load_bin(str(path), (1, 5, 97, 0))

    malformed = bytearray(_address_bin([(1, 0x1000)]))
    malformed[-17] = 0x08
    path.write_bytes(malformed)
    with pytest.raises(ValueError, match='relocation-ID encoding'):
        AddressLibrary().load_bin(str(path), (1, 5, 97, 0))

    wrong_abi = bytearray(_address_bin([(1, 0x1000)]))
    pointer_size_offset = 4 + 16 + 4 + len(b'SkyrimSE.exe')
    struct.pack_into('<I', wrong_abi, pointer_size_offset, 4)
    path.write_bytes(wrong_abi)
    with pytest.raises(ValueError, match='pointer size'):
        AddressLibrary().load_bin(str(path), (1, 5, 97, 0))


def test_sse_vr_csv_is_metadata_count_and_id_strict(tmp_path):
    path = tmp_path / 'vr.csv'
    path.write_text(
        'id,offset\n2,0.211.0\n1,001000\n2,001000\n',
        encoding='utf-8')
    assert AddressLibrary.load_csv(
        str(path), expected_count=2, expected_marker='0.211.0') == {
            1: 0x1000, 2: 0x1000}

    corruptions = [
        ('wrong,header\n2,0.211.0\n1,001000\n2,002000\n', 'header'),
        ('id,offset\n3,0.211.0\n1,001000\n2,002000\n', 'metadata mismatch'),
        ('id,offset\n2,0.211.0\n1,001000\nbad\n', 'malformed'),
        ('id,offset\n2,0.211.0\n1,001000\n1,002000\n', 'duplicate'),
    ]
    for content, error in corruptions:
        path.write_text(content, encoding='utf-8')
        with pytest.raises(ValueError, match=error):
            AddressLibrary.load_csv(
                str(path), expected_count=2, expected_marker='0.211.0')


def test_tracked_sse_vr_address_library_has_exact_metadata_and_rows():
    path = Path(__file__).parents[2] / 'addresslibrary' / 'sse' / \
        'version-1-4-15-0.csv'
    db = AddressLibrary.load_csv(str(path))
    assert len(db) == 13949


def test_relib_parser_validates_complete_file_and_unique_ids(tmp_path):
    path = tmp_path / 'test.relib'
    first = (1, 6, 1179, 0)
    second = (1, 6, 1170, 0, 1)
    valid = _relib([
        (first, [(1, 0x1000), (2, 0x2000)]),
        (second, [(1, 0x1100)]),
    ])
    path.write_bytes(valid)
    loaded = _MODULE.load_relib_versions(str(path), (first, second))
    assert loaded[first] == {1: 0x1000, 2: 0x2000}
    assert loaded[second] == {1: 0x1100}
    assert _MODULE.list_relib_versions(str(path)) == [first, second]

    path.write_bytes(_relib([
        (first, [(1, 0x1000), (1, 0x2000)]),
    ]))
    with pytest.raises(ValueError, match='duplicate relib relocation ID'):
        _MODULE.load_relib_version(str(path), first)

    # Even when the requested map is first, corruption in a later version
    # invalidates the complete database instead of returning early.
    path.write_bytes(valid[:-1])
    with pytest.raises(ValueError, match='truncated relib'):
        _MODULE.load_relib_version(str(path), first)

    path.write_bytes(valid + b'x')
    with pytest.raises(ValueError, match='trailing bytes'):
        _MODULE.load_relib_version(str(path), first)

    path.write_bytes(_relib([(first, [(1, 0x1000)])], pointer_size=4))
    with pytest.raises(ValueError, match='pointer size'):
        _MODULE.load_relib_version(str(path), first)

    path.write_bytes(_relib([(first, [(1001, 0x1000)])], high_id=1000))
    with pytest.raises(ValueError, match='exceeds declared range'):
        _MODULE.load_relib_version(str(path), first)


def test_reverse_relocation_lookup_rejects_ambiguous_rvas():
    reverse, ambiguous = _MODULE.unique_reverse_ids({
        1: 0x1000, 2: 0x2000, 3: 0x1000})
    assert reverse == {0x2000: 2}
    assert ambiguous == {0x1000}


def test_sse_pdb_merge_uses_multimap_and_unique_decorated_evidence():
    source = Path(__file__).with_name('parse_commonlib_types.py').read_text(
        encoding='utf-8')
    assert 'unique_public_merge_target(' in source
    assert 'name_to_syms.setdefault' in source
    assert "'pdb_decorated_name': public.decorated_name" in source
    assert 'name_to_sym = {' not in source


def test_tracked_skyrim_relib_gog_counts_and_structure():
    path = (Path(__file__).parents[2] / 'extern' /
            'AddressLibraryDatabase' / 'skyrimae.relib')
    if not path.is_file():
        pytest.skip('local Skyrim reverse-engineering RELIB is not bundled')
    first = (1, 6, 1179, 0)
    second = (1, 6, 1170, 0, 1)
    versions, retained = _MODULE._parse_relib(str(path), {first, second})
    assert len(versions) == 12
    assert versions[-2:] == [second, first]
    assert len(retained[first]) == 428510
    assert len(retained[second]) == 428309
