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


def _namespace_lib():
    lib = _module().F4AddressLibrary()
    legacy, ng_era = 7, 2230121
    lib.og_db = {legacy: 0x1000, ng_era: 0xBAD1}      # a real OG db has no id >= 2M
    lib.vr_db = {legacy: 0x5000, ng_era: 0xBAD2}
    lib.ng_db = {legacy: 0x2000, ng_era: 0x2100}
    lib.ae_db = {legacy: 0x3000, ng_era: 0x3100}
    lib.db_221 = {legacy: 0x4000, ng_era: 0x4100}
    return lib, legacy, ng_era


def test_ng_range_ids_never_resolve_in_og_or_vr():
    # Fallout 4 has ONE ID namespace: legacy IDs (< 1.6M) mean the same thing
    # in OG / NG / AE / VR (the VR CSV is keyed on OG IDs); IDs >= 2M exist
    # only in NG and later.  The belief this test used to encode -- "a desktop
    # ID found in vr_db is a coincidental collision" -- was numerically false
    # and cost ~9.9k valid VR vtable labels.
    lib, legacy, ng_era = _namespace_lib()
    parser = _parser_module()

    # the desktop half never reads vr_db on its own ...
    assert lib.resolve_desktop(legacy) == {
        'og': 0x1000, 'ng': 0x2000, 'a': 0x3000, '221': 0x4000}

    # ... VR is opt-in (the generator enables it only with the VR exe staged)
    conservative, staged = {}, {}
    parser._resolve_desktop_offsets(conservative, legacy, lib)
    parser._resolve_desktop_offsets(staged, legacy, lib, allow_vr=True)
    assert 'v' not in conservative
    assert staged == {'og': 0x1000, 'ng': 0x2000, 'a': 0x3000,
                      '221': 0x4000, 'v': 0x5000}

    # the rule that stays true: an NG-range ID yields no OG and no VR offset
    modern = {}
    parser._resolve_desktop_offsets(modern, ng_era, lib, allow_vr=True)
    assert modern == {'ng': 0x2100, 'a': 0x3100, '221': 0x4100}


def test_relocation_id_pair_resolves_each_half_in_its_own_range():
    lib, legacy, ng_era = _namespace_lib()
    parser = _parser_module()
    pair = {'id': ng_era, 'og_id': legacy, 'ng_id': ng_era}

    staged = {}
    parser.resolve_parsed_offsets(staged, pair, lib, allow_vr=True)
    # og id -> OG + VR only; ng id -> NG / AE / 1.11.221 (/240) only
    assert staged == {'og': 0x1000, 'v': 0x5000,
                      'ng': 0x2100, 'a': 0x3100, '221': 0x4100}

    unstaged = {}
    parser.resolve_parsed_offsets(unstaged, pair, lib)
    assert 'v' not in unstaged and unstaged['og'] == 0x1000

    # an og slot that carries an NG-range number is not a legacy ID
    swapped = {}
    parser.resolve_parsed_offsets(
        swapped, {'id': ng_era, 'og_id': ng_era, 'ng_id': 0}, lib, allow_vr=True)
    assert swapped == {}


def test_vr_offsets_are_not_attached_without_the_staged_vr_exe():
    lib, legacy, ng_era = _namespace_lib()
    parser = _parser_module()
    labels = [{'name': 'VTABLE_Actor', 'id': legacy, 'vtable_class': 'Actor',
               'vtable_index': 0}]
    funcs = [{'name': 'AddPerk', 'class_': 'Actor', 'id': ng_era}]

    symbols, classes = parser.build_primary_symbols(funcs, labels, lib, {})
    assert classes == {'VTABLE_Actor': 'Actor'}
    assert all('v' not in s for s in symbols)       # VR exe not staged: as before
    by_name = {s['n']: s for s in symbols}
    assert by_name['Actor::AddPerk'] == {
        'n': 'Actor::AddPerk', 't': 'func', 'sig': '', 'src': 'CommonLibF4',
        'id': ng_era, 'ng': 0x2100, 'a': 0x3100, '221': 0x4100}
    assert by_name['VTABLE_Actor']['og'] == 0x1000


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
