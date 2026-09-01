"""Address Library ID translation, and the slot matching built on it."""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from versionlib_map import (  # noqa: E402
    DEFAULT_IMAGE_BASE,
    VersionlibError,
    build_va_translation,
    read_versionlib,
    verify_image_base,
)
from vtable_layout import ClassVtable, SlotEntry  # noqa: E402
from vtable_matcher import _match_one_class  # noqa: E402


def _v5_bytes(rvas, version=(1, 16, 236, 0), pointer_size=8, fmt=5):
    blob = struct.pack('<I', fmt)
    blob += struct.pack('<4I', *version)
    blob += b'Starfield'.ljust(64, b'\0')
    blob += struct.pack('<Q', pointer_size)
    blob += struct.pack('<I', len(rvas))
    blob += b''.join(struct.pack('<I', rva) for rva in rvas)
    return blob


def _write(tmp_path, name, blob):
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


def test_reads_v5_and_treats_zero_as_absent(tmp_path):
    db = read_versionlib(_write(tmp_path, 'a.bin', _v5_bytes([0, 0x1000, 0, 0x2000])))
    # A zero entry means "this ID has no address in this build", so it must not
    # become a real mapping to the image base.
    assert db == {1: 0x1000, 3: 0x2000}


def test_rejects_non_v5(tmp_path):
    # V1/V2 belong to games whose IDs are not version-stable; translating them
    # would be unsound, so it must fail loudly rather than silently.
    with pytest.raises(VersionlibError, match='only the V5 format'):
        read_versionlib(_write(tmp_path, 'b.bin', _v5_bytes([0x10], fmt=2)))


def test_rejects_truncated_table(tmp_path):
    blob = _v5_bytes([0x1000, 0x2000])[:-4]
    with pytest.raises(VersionlibError, match='truncated'):
        read_versionlib(_write(tmp_path, 'c.bin', blob))


def test_rejects_non_64bit(tmp_path):
    with pytest.raises(VersionlibError, match='pointer size'):
        read_versionlib(_write(tmp_path, 'd.bin', _v5_bytes([0x10], pointer_size=4)))


def test_translation_is_by_id_not_by_address():
    # The whole point: the address changes, the ID does not.
    ref = {7: 0x1000, 9: 0x2000}
    tgt = {7: 0x5000, 9: 0x6000}
    assert build_va_translation(ref, tgt) == {
        DEFAULT_IMAGE_BASE + 0x1000: DEFAULT_IMAGE_BASE + 0x5000,
        DEFAULT_IMAGE_BASE + 0x2000: DEFAULT_IMAGE_BASE + 0x6000,
    }


def test_drops_ids_missing_from_the_target():
    # A function that was removed or inlined must produce no edge at all.
    assert build_va_translation({7: 0x1000, 9: 0x2000}, {7: 0x5000}) == {
        DEFAULT_IMAGE_BASE + 0x1000: DEFAULT_IMAGE_BASE + 0x5000}


def test_drops_addresses_two_ids_share():
    # Folded functions: the address cannot say which ID it is, so neither ID
    # is usable evidence.
    assert build_va_translation({1: 0x1000, 2: 0x1000, 3: 0x3000},
                                {1: 0x5000, 2: 0x5000, 3: 0x7000}) == {
        DEFAULT_IMAGE_BASE + 0x3000: DEFAULT_IMAGE_BASE + 0x7000}


def test_drops_edges_that_collide_on_one_target_address():
    # An ID retired and its address reused would let two reference functions
    # claim one target function.  At most one edge is right; drop both.
    ref = {1: 0x1000, 2: 0x2000}
    tgt = {1: 0x9000, 2: 0x9000}
    assert build_va_translation(ref, tgt) == {}


def test_verify_image_base_rejects_a_wrong_base():
    db = {1: 0x1000, 2: 0x2000, 3: 0x3000}
    good = [DEFAULT_IMAGE_BASE + rva for rva in db.values()]
    rate, ok = verify_image_base(good, db, DEFAULT_IMAGE_BASE)
    assert (rate, ok) == (1.0, True)
    # Same addresses read with the wrong base produce plausible integers that
    # resolve to nothing -- which is exactly what must be caught.
    rate, ok = verify_image_base(good, db, 0x180000000)
    assert ok is False and rate == 0.0


def _table(pairs, name='C', primary=True):
    table = ClassVtable(class_name=name, vtable_addr=0x1000,
                        vtable_id=name + '|primary|0x0', is_primary=primary)
    for slot, (addr, fingerprint) in enumerate(pairs):
        table.add(SlotEntry(slot=slot, func_addr=addr, func_name='',
                            fingerprint=fingerprint))
    return table


def test_id_matching_survives_every_function_moving():
    # The case byte fingerprints cannot handle: identical code, different
    # addresses, and therefore different bytes at every call site.
    ref = _table([(0x1000, 'AA'), (0x2000, 'BB')])
    tgt = _table([(0x5000, 'CC'), (0x6000, 'DD')])
    translation = {0x1000: 0x5000, 0x2000: 0x6000}
    sm = _match_one_class(ref, tgt, translation)
    assert sm.ref_to_target == {0: 0, 1: 1}
    assert all(e['method'] == 'address_library_id'
               for e in sm.match_evidence.values())


def test_repeated_stub_pairs_by_ordinal_when_counts_agree():
    # One folded stub occupying several slots is still resolvable as a group.
    ref = _table([(0x1000, 'AA'), (0x9000, 'ZZ'), (0x9000, 'ZZ')])
    tgt = _table([(0x5000, 'AA'), (0x7000, 'ZZ'), (0x7000, 'ZZ')])
    sm = _match_one_class(ref, tgt, {0x1000: 0x5000, 0x9000: 0x7000})
    assert sm.ref_to_target == {0: 0, 1: 1, 2: 2}


def test_repeated_stub_is_refused_when_the_count_changed():
    # If a build added or dropped one copy, ordinal pairing would shift every
    # later duplicate by one -- silently wrong.  Refuse the whole group.
    ref = _table([(0x9000, 'ZZ'), (0x9000, 'ZZ')])
    tgt = _table([(0x7000, 'ZZ'), (0x7000, 'ZZ'), (0x7000, 'ZZ')])
    sm = _match_one_class(ref, tgt, {0x9000: 0x7000})
    assert sm.ref_to_target == {}
    assert [a['method'] for a in sm.ambiguous_matches] == ['address_id_arity']


def test_two_reference_functions_landing_on_one_target_are_refused():
    ref = _table([(0x1000, 'AA'), (0x2000, 'BB')])
    tgt = _table([(0x5000, 'AA'), (0x6000, 'BB')])
    sm = _match_one_class(ref, tgt, {0x1000: 0x5000, 0x2000: 0x5000})
    assert sm.ref_to_target == {}
    assert {a['method'] for a in sm.ambiguous_matches} == {'address_id_collision'}


def test_fingerprint_disagreement_is_recorded_not_hidden():
    # An ID reused for an unrelated function looks exactly like this, so the
    # edge is kept but flagged rather than silently trusted.
    ref = _table([(0x1000, '48 8B C4')])
    tgt = _table([(0x5000, '33 C0 C3')])
    sm = _match_one_class(ref, tgt, {0x1000: 0x5000})
    assert sm.ref_to_target == {0: 0}
    assert sm.match_evidence[0]['fingerprint_agrees'] is False


def test_agreeing_fingerprints_are_not_flagged():
    ref = _table([(0x1000, '48 8B C4')])
    tgt = _table([(0x5000, '48 8B C4')])
    sm = _match_one_class(ref, tgt, {0x1000: 0x5000})
    assert 'fingerprint_agrees' not in sm.match_evidence[0]


def test_without_translation_behaviour_is_unchanged():
    # Games with version-unstable IDs must keep the old matching exactly.
    ref = _table([(0x1000, '48 8B C4 90')])
    tgt = _table([(0x5000, '48 8B C4 90')])
    sm = _match_one_class(ref, tgt, None)
    assert sm.ref_to_target == {}          # 4 concrete bytes < min_concrete_bytes


def test_name_stage_cannot_reuse_a_slot_id_matching_took():
    ref = ClassVtable(class_name='C', vtable_addr=0x1000, vtable_id='C|primary|0x0')
    ref.add(SlotEntry(slot=0, func_addr=0x1000, func_name='C::a', fingerprint=''))
    ref.add(SlotEntry(slot=1, func_addr=0x2000, func_name='C::b', fingerprint=''))
    tgt = ClassVtable(class_name='C', vtable_addr=0x4000, vtable_id='C|primary|0x0')
    tgt.add(SlotEntry(slot=0, func_addr=0x5000, func_name='C::b', fingerprint=''))
    # ID evidence says ref slot 0 -> target slot 0; the stale name on the target
    # says otherwise and must not be allowed to double-book the slot.
    sm = _match_one_class(ref, tgt, {0x1000: 0x5000})
    assert sm.ref_to_target == {0: 0}
    assert sm.match_evidence[0]['method'] == 'address_library_id'
