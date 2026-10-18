"""Skyrim AE 1.7.x layout rewrite (skyrim17_layouts) for the 1.7.104 importer."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'core'))

import skyrim17_layouts as L  # noqa: E402
from ghidra_import_gen import flatten_structs  # noqa: E402


def _rec(full, size, fields, pdb_bases=(), **extra):
    rec = {'name': full.split('::')[-1], 'full_name': full, 'size': size,
           'record_kind': 'class', 'category': '/CommonLibSSE/RE',
           'fields': [L._f(*f) for f in fields],
           'bases': [b for b, _o in pdb_bases], 'pdb_bases': list(pdb_bases),
           'has_vtable': True, 'vmethods': {}, 'methods': {}}
    rec.update(extra)
    return rec


def _layout(rec):
    return [(f['name'], f['offset'], f['size']) for f in
            sorted(rec['fields'], key=lambda f: f['offset'])]


def _no_overlap(rec):
    fields = sorted(rec['fields'], key=lambda f: f['offset'])
    for a, b in zip(fields, fields[1:]):
        assert a['offset'] + a['size'] <= b['offset'], (a, b)
    assert all(f['offset'] + f['size'] <= rec['size'] for f in fields)


# ---------------------------------------------------------------------------
# Patch tables
# ---------------------------------------------------------------------------

def test_record_patch_tables_are_self_consistent():
    names = [p.name for p in L.RECORD_PATCHES]
    assert len(names) == len(set(names))
    for patch in L.RECORD_PATCHES:
        assert sum(s.delta for s in patch.splices) == patch.new_size - patch.old_size
        for splice in patch.splices:
            assert len(set(splice.expect)) == len(splice.expect)
            spans = []
            for spec in splice.fields:
                if isinstance(spec, tuple):
                    assert spec[1] in splice.expect, (patch.name, spec)
                    offset = spec[2]
                else:
                    offset = spec['offset']
                    spans.append((offset, offset + spec['size']))
                assert splice.at <= offset < splice.at + splice.new_len, (patch.name, spec)
            spans.sort()
            for (a0, a1), (b0, _b1) in zip(spans, spans[1:]):
                assert a1 <= b0, (patch.name, a1, b0)
            assert all(end <= splice.at + splice.new_len for _s, end in spans)
            for _name, offset in splice.bases:
                assert splice.at <= offset < splice.at + splice.new_len


def test_patch_set_covers_every_binary_confirmed_1_7_change():
    # Sizes measured in SkyrimSE.exe 1.6.1170 -> 1.7.104 (deleting dtors,
    # allocations); FirstPersonState keeps 0x90 but moves its tail.
    sizes = {p.name: (p.old_size, p.new_size) for p in L.RECORD_PATCHES}
    assert sizes == {
        'RE::PlayerCharacter': (0xBE8, 0xBF0),
        'RE::SkyrimVM': (0x8978, 0x8988),
        'RE::AttackBlockHandler': (0x48, 0xC0),
        'RE::LookHandler': (0x10, 0xB8),
        'RE::FirstPersonState': (0x90, 0x90),
        'RE::BookMenu': (0x98, 0xA8),
        'RE::LockpickingMenu': (0x110, 0x128),
        'RE::TESTopicInfo': (0x48, 0x50),
        'RE::bhkWorld': (0xC600, 0xC710),
        'RE::BGSDefaultObjectManager': (0xD00, 0xD38),
        'RE::BSGraphics::State': (0x120, 0x130),
        'RE::BSInputEventQueue': (0x390, 0x568),
        'RE::BSInputDeviceManager': (0xF0, 0x100),
        'RE::ControlMap::InputContext': (0x60, 0x90),
    }
    roots = {root: (slot, len(added)) for root, slot, added in L.VTABLE_INSERTS}
    assert roots == {'RE::PlayerInputHandler': (2, 2), 'RE::MenuEventHandler': (2, 2),
                     'RE::BSSystemUtility': (2, 1), 'RE::BSSaveDataSystemUtility': (5, 6)}


# ---------------------------------------------------------------------------
# Splices
# ---------------------------------------------------------------------------

def _player_character():
    return _rec('RE::PlayerCharacter', 0xBE8, [
        ('sinks', 'struct:RE::BSTArray<int>', 0x2D8, 24),
        ('questTargetsLock', 'struct:RE::BSSpinLock', 0x3E0, 8),
        ('playerFlags', 'u64', 0xBE0, 8)], pdb_bases=[
        ('RE::Character', 0),
        ('RE::BSTEventSink<RE::TESTrackedStatsEvent>', 0x2D0),
        ('RE::BSTEventSource<RE::BGSActorCellEvent>', 0x2D8),
        ('RE::BSTEventSource<RE::PositionPlayerEvent>', 0x388)])


def test_insertion_moves_fields_and_bases_and_adds_the_new_base():
    st = _player_character()
    patch = next(p for p in L.RECORD_PATCHES if p.name == 'RE::PlayerCharacter')
    L._check_anchors(st, patch)
    L._splice_record(st, patch.splices[0], validate=True)
    assert st['size'] == 0xBF0
    assert _layout(st) == [('sinks', 0x2E0, 24), ('questTargetsLock', 0x3E8, 8),
                           ('playerFlags', 0xBE8, 8)]
    assert st['pdb_bases'] == [
        ('RE::Character', 0),
        ('RE::BSTEventSink<RE::TESTrackedStatsEvent>', 0x2D0),
        ('RE::BSTEventSink<RE::BSSystemEvent>', 0x2D8),
        ('RE::BSTEventSource<RE::BGSActorCellEvent>', 0x2E0),
        ('RE::BSTEventSource<RE::PositionPlayerEvent>', 0x390)]
    assert 'RE::BSTEventSink<RE::BSSystemEvent>' in st['bases']


def test_replacement_moves_and_renames_the_named_1_6_fields():
    st = _rec('RE::TESTopicInfo', 0x48, [
        ('fileOffset', 'u32', 0x40, 4), ('pad44', 'u32', 0x44, 4)])
    splice = L.Splice(0x40, 8, 0xC, expect=['fileOffset', 'pad44'], fields=[
        L._moved('fileOffset', 0x40), L._moved('pad44', 0x44, 'unk44'),
        L._f('unk48', 'u32', 0x48, 4)])
    L._splice_record(st, splice, validate=True)
    assert _layout(st) == [('fileOffset', 0x40, 4), ('unk44', 0x44, 4),
                           ('unk48', 0x48, 4)]
    assert st['size'] == 0x4C


def test_replacement_refuses_an_unexpected_1_6_shape():
    st = _rec('RE::TESTopicInfo', 0x48, [('somethingElse', 'u32', 0x44, 4)])
    splice = L.Splice(0x44, 4, 0xC, expect=['pad44'], fields=[])
    with pytest.raises(L.LayoutPatchError):
        L._splice_record(st, splice, validate=True)


def test_anchor_check_refuses_already_patched_or_foreign_records():
    patch = next(p for p in L.RECORD_PATCHES if p.name == 'RE::PlayerCharacter')
    st = _player_character()
    L._splice_record(st, patch.splices[0], validate=True)
    with pytest.raises(L.LayoutPatchError):
        L._check_anchors(st, patch)          # 1.7-shaped: size 0xBF0


def test_field_straddling_a_splice_is_refused():
    st = _rec('RE::X', 0x20, [('wide', 'u64', 0x8, 8)])
    with pytest.raises(L.LayoutPatchError):
        L._splice_record(st, L.Splice(0xC, 0, 8))


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------

def _hierarchy():
    base = _rec('RE::Base', 0x20, [('a', 'u32', 0x8, 4), ('b', 'u32', 0x18, 4)])
    mid = _rec('RE::Mid', 0x30, [('a', 'u32', 0x8, 4), ('b', 'u32', 0x18, 4),
                                 ('m', 'u64', 0x20, 8)], pdb_bases=[('RE::Base', 0)])
    # Clang lists every nested base: Leaf names both Mid and Base.
    leaf = _rec('RE::Leaf', 0x48, [('lead', 'u64', 0x8, 8),
                                   ('a', 'u32', 0x18, 4), ('b', 'u32', 0x28, 4),
                                   ('m', 'u64', 0x30, 8), ('l', 'u64', 0x40, 8)],
                pdb_bases=[('RE::Other', 0), ('RE::Mid', 0x10), ('RE::Base', 0x10)])
    holder = _rec('RE::Holder', 0x68, [
        ('one', 'struct:RE::Base', 0x0, 0x20),
        ('two', 'arr:struct:RE::Base:2', 0x20, 0x40),
        ('tail', 'u32', 0x60, 4)], has_vtable=False)
    return {r['full_name']: r for r in (base, mid, leaf, holder)}


def test_change_reaches_derived_records_once_at_their_base_offset():
    structs = _hierarchy()
    splice = L.Splice(0x10, 0, 8, fields=[L._f('new', 'u64', 0x10, 8)])
    L._splice_record(structs['RE::Base'], splice)
    log = []
    L._propagate(structs, 'RE::Base', lambda s, o: L._splice_record(s, splice, o),
                 splice.delta, log)
    assert _layout(structs['RE::Mid']) == [('a', 0x8, 4), ('new', 0x10, 8),
                                           ('b', 0x20, 4), ('m', 0x28, 8)]
    assert structs['RE::Mid']['size'] == 0x38
    assert _layout(structs['RE::Leaf']) == [('lead', 0x8, 8), ('a', 0x18, 4),
                                            ('new', 0x20, 8), ('b', 0x30, 4),
                                            ('m', 0x38, 8), ('l', 0x48, 8)]
    assert structs['RE::Leaf']['size'] == 0x50
    # Embedded by value: one member and a two-element array.
    assert _layout(structs['RE::Holder']) == [('one', 0x0, 0x28),
                                              ('two', 0x28, 0x50),
                                              ('tail', 0x78, 4)]
    assert structs['RE::Holder']['size'] == 0x80
    flatten_structs(structs)
    for rec in structs.values():
        _no_overlap(rec)
    assert len(log) == 4


def test_opaque_pdb_blob_absorbs_the_change_of_its_base():
    blob = _rec('bhkWorldM', 0xC630, [
        ('vftable_bhkWorldM_0', 'ptr', 0, 8), ('_pad_18', 'arr:i8:50712', 0x18, 50712)],
        category='/CommonLibSSE/PDB')
    patch = next(p for p in L.RECORD_PATCHES if p.name == 'RE::bhkWorld')
    L._splice_record(blob, patch.splices[0], 0)
    assert blob['size'] == 0xC740
    assert _layout(blob)[-1] == ('_pad_18', 0x18, 50712 + 0x110)
    assert blob['fields'][-1]['type'] == 'arr:i8:{}'.format(50712 + 0x110)
    assert L.EXTRA_DERIVED['RE::bhkWorld'] == (('bhkWorldM', 0, 0xC630),)


# ---------------------------------------------------------------------------
# Enums and vtables
# ---------------------------------------------------------------------------

def _default_object_1_6():
    names = ['k{:03d}'.format(i) for i in range(366)]
    names[187], names[188] = 'kHelpManualXBox', 'kKeywordTypeAmmo'
    names[262], names[263] = 'kHelpAttackTarget', 'kImagespaceLoadscreen'
    names[365] = 'kModsHelpFormList'
    return [(n, i) for i, n in enumerate(names)] + [('kTotal', 366)]


def test_default_object_matches_the_1_7_104_engine_table():
    values = dict(L._patch_default_object(_default_object_1_6()))
    assert len(values) == 373 and values['kTotal'] == 372
    assert (values['kHelpManualXBox'], values['kHelpManualNX'],
            values['kKeywordTypeAmmo']) == (187, 188, 189)
    assert (values['kHelpAttackTarget'], values['kHelpMotionAttackBlock'],
            values['kHelpAmiibo'], values['kImagespaceLoadscreen']) == (263, 264, 268, 269)
    assert values['kModsHelpFormList'] == 371
    assert sorted(values.values()) == list(range(373))
    with pytest.raises(L.LayoutPatchError):
        L._patch_default_object(L._patch_default_object(_default_object_1_6()))


def test_input_enums():
    devices = L._patch_input_device([('kNone', -1), ('kKeyboard', 0), ('kMouse', 1),
                                     ('kGamepad', 2), ('kVirtualKeyboard', 3),
                                     ('kTotal', 4)])
    assert dict(devices)['kVirtualKeyboard'] == 5 and dict(devices)['kTotal'] == 6
    events = L._patch_input_event_type([('kButton', 0), ('kMouseMove', 1), ('kChar', 2),
                                        ('kThumbstick', 3), ('kDeviceConnect', 4),
                                        ('kKinect', 5)])
    assert events[-3:] == [('kSixaxis', 6), ('kMotionGesture', 7), ('kAmiibo', 8)]
    with pytest.raises(L.LayoutPatchError):
        L._patch_input_device(devices)


def test_vtable_slots_shift_for_the_root_its_subclasses_and_secondaries():
    pih = _rec('RE::PlayerInputHandler', 0x10, [], vfuncs=[
        ('~PlayerInputHandler', 0), ('CanProcess', 8), ('ProcessThumbstick', 16),
        ('ProcessMouseMove', 24), ('ProcessButton', 32)])
    held = _rec('RE::HeldStateHandler', 0x18, [], [('RE::PlayerInputHandler', 0)],
                vfuncs=[('UpdateHeldStateActive', 40), ('SetHeldStateActive', 48)])
    camera = _rec('RE::FirstPersonState', 0x90, [], [
        ('RE::TESCameraState', 0), ('RE::PlayerInputHandler', 0x20)],
        secondary_vtables={0x20: [(0, '~FirstPersonState'), (1, 'CanProcess'),
                                  (2, 'ProcessThumbstick'), (3, 'ProcessMouseMove'),
                                  (4, 'ProcessButton')]})
    structs = {r['full_name']: r for r in (pih, held, camera)}
    root, slot, added = L.VTABLE_INSERTS[0]
    L._insert_vtable_slots(structs, root, slot, added)
    assert pih['vfuncs'] == [('~PlayerInputHandler', 0), ('CanProcess', 8),
                             ('ProcessMotionGesture', 16), ('ProcessSixaxis', 24),
                             ('ProcessThumbstick', 32), ('ProcessMouseMove', 40),
                             ('ProcessButton', 48)]
    assert held['vfuncs'] == [('UpdateHeldStateActive', 56), ('SetHeldStateActive', 64)]
    assert [n for _i, n in camera['secondary_vtables'][0x20]][2:5] == [
        'ProcessMotionGesture', 'ProcessSixaxis', 'ProcessThumbstick']
    assert 'ProcessSixaxis' in pih['vmethods']
    with pytest.raises(L.LayoutPatchError):
        L._insert_vtable_slots(structs, root, slot, added)


def test_new_records_derive_from_their_parsed_base():
    idevent = _rec('RE::IDEvent', 0x28, [('device', 'u32', 8, 4), ('idCode', 'u32', 0x20, 4)],
                   [('RE::InputEvent', 0)])
    structs = {'RE::IDEvent': idevent}
    rec = L._new_record(L.NEW_RECORDS[0], structs)
    assert rec['full_name'] == 'RE::SixaxisEvent' and rec['size'] == 0x90
    assert rec['pdb_bases'] == [('RE::IDEvent', 0), ('RE::InputEvent', 0)]
    assert _layout(rec)[-1] == ('data', 0x28, 0x68)
    _no_overlap(rec)


# ---------------------------------------------------------------------------
# Generator wiring
# ---------------------------------------------------------------------------

def test_only_the_1_7_104_runtime_is_rewritten():
    source = (HERE / 'parse_commonlib_types.py').read_text(encoding='utf-8')
    start = source.index('\nVERSIONS = {')
    versions = source[start:source.index('\n}\n', start)]
    assert versions.count("'layout_patch'") == 1
    block = versions[versions.index("'17104': {"):]
    assert "'layout_patch': _apply_ae17_layouts" in block[:block.index('},')]
    # Applied after the PDB merge, before vtables and flattening.
    run = source[source.index('def run_version('):source.index('def _detect_exe_versions(')]
    assert (run.index('pdb_structs.items()') < run.index('layout_patch(structs, enums)')
            < run.index('_build_vtable_structs(structs)') < run.index('_flatten_structs(structs)'))


def test_apply_refuses_a_missing_target():
    structs = {name: _rec(name, size, []) for name, size in (
        ('RE::IDEvent', 0x28), ('RE::hkpWorldCinfo', 0x100))}
    with pytest.raises(L.LayoutPatchError, match='was not parsed'):
        L.apply_ae17_layouts(structs, {}, record_patches=[L.RECORD_PATCHES[0]],
                             verbose=False)


def test_apply_rewrites_a_record_and_its_dependents_together():
    pc = _player_character()
    structs = {r['full_name']: r for r in (
        pc, _rec('RE::IDEvent', 0x28, []), _rec('RE::hkpWorldCinfo', 0x100, []))}
    before = copy.deepcopy(structs)
    with pytest.raises(L.LayoutPatchError):     # enum targets absent
        L.apply_ae17_layouts(structs, {}, record_patches=[L.RECORD_PATCHES[0]],
                             verbose=False)
    assert pc['size'] == 0xBF0 and before['RE::PlayerCharacter']['size'] == 0xBE8
    assert {'RE::SixaxisEvent', 'RE::bhkWorldCinfo'} <= set(structs)
