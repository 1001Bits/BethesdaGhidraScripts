from __future__ import annotations

import importlib.util
from pathlib import Path
import struct

import pytest


def _module():
    path = Path(__file__).with_name('address_library.py')
    spec = importlib.util.spec_from_file_location('f4_address_library_under_test', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _evidence_module():
    path = Path(__file__).with_name('bytesig_evidence.py')
    spec = importlib.util.spec_from_file_location('f4_bytesig_evidence_under_test', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _parser_module():
    path = Path(__file__).with_name('parse_commonlib_types.py')
    spec = importlib.util.spec_from_file_location('f4_parser_under_test', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_desktop_resolution_never_uses_coincidental_vr_id():
    lib = _module().F4AddressLibrary()
    lib.og_db = {7: 0x1000}
    lib.ng_db = {7: 0x2000}
    lib.ae_db = {7: 0x3000}
    lib.db_221 = {7: 0x4000}
    lib.vr_db = {7: 0xDEADBEEF}
    assert lib.resolve_desktop(7) == {
        'og': 0x1000, 'ng': 0x2000, 'a': 0x3000, '221': 0x4000,
    }


def test_flat_database_rejects_truncation_and_unsorted_ids(tmp_path):
    lib = _module().F4AddressLibrary()
    truncated = tmp_path / 'truncated.bin'
    truncated.write_bytes(struct.pack('<Q', 2) + struct.pack('<QQ', 1, 0x1000))
    with pytest.raises(ValueError, match='length'):
        lib.load_bin(str(truncated))

    unsorted = tmp_path / 'unsorted.bin'
    unsorted.write_bytes(struct.pack('<Q', 2) +
                         struct.pack('<QQQQ', 2, 0x2000, 1, 0x1000))
    with pytest.raises(ValueError, match='strictly increasing'):
        lib.load_bin(str(unsorted))


def test_f4_vr_csv_is_strict_and_tracked_corpus_is_complete(tmp_path):
    lib = _module().F4AddressLibrary()
    path = tmp_path / 'vr.csv'
    path.write_text(
        'id,offset\n2,1.13.1\n1,001000\n2,001000\n', encoding='utf-8')
    assert lib.load_csv(
        str(path), expected_count=2, expected_marker='1.13.1') == {
            1: 0x1000, 2: 0x1000}
    corruptions = [
        ('bad,header\n2,1.13.1\n1,001000\n2,002000\n', 'header'),
        ('id,offset\n3,1.13.1\n1,001000\n2,002000\n', 'metadata mismatch'),
        ('id,offset\n2,1.13.1\n1,001000\nbad\n', 'malformed'),
        ('id,offset\n2,1.13.1\n1,001000\n1,002000\n', 'duplicate'),
    ]
    for content, error in corruptions:
        path.write_text(content, encoding='utf-8')
        with pytest.raises(ValueError, match=error):
            lib.load_csv(
                str(path), expected_count=2, expected_marker='1.13.1')

    tracked = (Path(__file__).parents[2] / 'addresslibrary' / 'f4' /
               'version-1-2-72-0.csv')
    assert len(lib.load_csv(str(tracked))) == 93858


def test_bytesig_evidence_is_target_bound_and_reciprocal(tmp_path):
    evidence = _evidence_module()
    path = tmp_path / 'ported.csv'
    target = {'sha256': 'a' * 64}
    source_a = {'sha256': 'b' * 64}
    source_b = {'sha256': 'c' * 64}
    evidence.persist(
        path, [('One', 0x1000), ('Two', 0x2000)], 'source-a',
        source_a, target, {'One': 0x3000, 'Two': 0x4000})
    rows, _ = evidence.load_validated(path, target)
    assert {(r['name'], r['target_rva']) for r in rows} == {
        ('One', 0x1000), ('Two', 0x2000)}

    # A second source contradicting target 0x1000 invalidates both claims;
    # first-wins would silently retain a potentially wrong name.
    evidence.persist(
        path, [('Other', 0x1000)], 'source-b', source_b, target,
        {'Other': 0x5000})
    rows, _ = evidence.load_validated(path, target)
    assert [(r['name'], r['target_rva']) for r in rows] == [('Two', 0x2000)]
    with pytest.raises(ValueError, match='another executable'):
        evidence.load_validated(path, {'sha256': 'd' * 64})

    # Rerunning one source replaces its corpus, so withdrawn claims cannot
    # survive forever in an append-only cache.
    evidence.persist(
        path, [('Moved', 0x3000)], 'source-a', source_a, target,
        {'Moved': 0x6000})
    rows, _ = evidence.load_validated(path, target)
    assert {(r['name'], r['target_rva']) for r in rows} == {
        ('Moved', 0x3000)}


def test_legacy_unbound_bytesig_csv_is_rejected(tmp_path):
    evidence = _evidence_module()
    path = tmp_path / 'legacy.csv'
    path.write_text('0x1000,Unsafe,old\n', encoding='utf-8')
    with pytest.raises((OSError, ValueError)):
        evidence.load_validated(path, {'sha256': 'a' * 64})


def test_f4_vtable_overlay_policy_mirrors_skyrim(tmp_path):
    # Canonical OG runtime: allowed only with anchors present and no legacy
    # shift map (same shape as commonlibsse/vtable_policy.py); every other
    # runtime stays disabled until identity-bound layout evidence ships.
    parser = _parser_module()
    anchor = tmp_path / 'og.csv'
    shift = tmp_path / 'shift.json'
    assert not parser._allow_vtable_emission(
        'f4_og', str(anchor), str(shift))[0]  # anchors missing
    anchor.write_text('class,method,slot\n', encoding='utf-8')
    assert parser._allow_vtable_emission(
        'f4_og', str(anchor), str(shift))[0]
    shift.write_text('{}', encoding='utf-8')
    assert not parser._allow_vtable_emission(
        'f4_og', str(anchor), str(shift))[0]  # legacy map present
    assert not parser._allow_vtable_emission(
        'f4_221', str(anchor), str(shift))[0]
    assert not parser._allow_vtable_emission(
        'f4_ae', str(anchor), str(shift))[0]
    assert not parser._allow_vtable_emission(
        'f4_ng', str(anchor), str(shift))[0]
    assert not parser._allow_vtable_emission(
        'f4_vr', str(anchor), str(shift))[0]
