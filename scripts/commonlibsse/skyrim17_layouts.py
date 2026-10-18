"""Skyrim AE 1.7.x record layouts for the 1.7.104 importer.

The pinned CommonLibSSE models the 1.6 AE layouts only: ``SKYRIM_SUPPORT_AE``
has no 1.7 switch, so the 17104 importer, parsed with the AE defines, carries
1.6 shapes.  :func:`apply_ae17_layouts` rewrites every parsed record, enum and
vtable whose layout changed in 1.7.x, for that runtime only.

Sources.  The class list is the upstream 1.6.1170 -> 1.7.99 delta:
powerof3/CommonLibSSE ``dev`` (1.7.99 commits 4b919eaa, d3202ec0, ddf05413)
diffed against its ``dev-1.6.1170`` branch, cross-checked with the
``RUNTIME_SSE_1_7_99`` accessors of alandtse/CommonLibSSE-NG.

Evidence.  Each change was measured in SkyrimSE.exe 1.7.104 against 1.6.1170
(``exes/skyrim/{17104,ae}``, pure-Python PE/x64 analysis): object sizes from
the sized ``operator delete`` of the deleting destructor and the immediate
passed to ``MemoryManager::Allocate`` (AE ID 68115); base offsets from the RTTI
class hierarchy descriptors; vtable slot counts from RTTI-located vtables;
field moves from constructor stores and member displacements.  Where a source
and the binary disagree the binary wins (NG's AttackBlockHandler tail,
upstream's FirstPersonState size), and the comment there says so.

Fail closed: a record, enum or vtable is rewritten only when its parsed shape is
exactly the 1.6 one this module was written against.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, Optional, Sequence, Tuple

_ARR_RE = re.compile(r'^arr:(.+):(\d+)$')
_BLOB_ELEMENTS = {'u8', 'i8', 'char', 'bool'}


class LayoutPatchError(RuntimeError):
    """The parsed 1.6 shape is not the one a 1.7 patch was written against."""


def _f(name: str, type_: str, offset: int, size: int) -> dict:
    return {'name': name, 'type': type_, 'offset': offset, 'size': size}


def _moved(name: str, offset: int, rename: Optional[str] = None) -> tuple:
    """A replaced field that survives at ``offset`` (type/size copied from 1.6)."""
    return ('moved', name, offset, rename)


class Splice:
    """Replace ``[at, at + old_len)`` with ``new_len`` bytes of new fields.

    Everything at or after ``at + old_len`` (fields and nested base offsets)
    moves by ``new_len - old_len``.  ``expect`` lists the 1.6 field names in
    the replaced range, in offset order; ``fields`` are absolute 1.7 offsets,
    either :func:`_f` dicts or :func:`_moved` references to replaced fields.
    """

    def __init__(self, at, old_len, new_len, expect=(), fields=(), bases=()):
        self.at, self.old_len, self.new_len = at, old_len, new_len
        self.expect = tuple(expect)
        self.fields = tuple(fields)
        self.bases = tuple(bases)

    @property
    def delta(self) -> int:
        return self.new_len - self.old_len


class RecordPatch:
    """1.6 -> 1.7 rewrite of one record.

    ``anchors`` are ``(field name, 1.6 offset)`` pairs and ``base_anchors``
    ``(base name, 1.6 offset)`` pairs that must exist before patching.
    """

    def __init__(self, name, old_size, new_size, splices, anchors=(),
                 base_anchors=()):
        self.name, self.old_size, self.new_size = name, old_size, new_size
        self.splices = tuple(splices)
        self.anchors = tuple(anchors)
        self.base_anchors = tuple(base_anchors)


_BSFIXEDSTRING = 'struct:RE::detail::BSFixedString<char>'

RECORD_PATCHES: Tuple[RecordPatch, ...] = (
    # BSTEventSink<BSSystemEvent> base at 0x2D8 (upstream 4b919eaa, NG
    # kAE1799ShiftBytes).  RTTI: BSTEventSource<BGSActorCellEvent/
    # ActorDeathEvent/PositionPlayerEvent> mdisp 0x2D8/0x330/0x388 ->
    # 0x2E0/0x338/0x390, new sink vtable at COL offset 0x2D8.  Deleting dtor
    # and allocation 0xBE8 -> 0xBF0; all 191 ctor stores in [0x3E0, 0xBE8)
    # reappear at +8.
    RecordPatch('RE::PlayerCharacter', 0xBE8, 0xBF0, [
        Splice(0x2D8, 0, 8, bases=[('RE::BSTEventSink<RE::BSSystemEvent>', 0x2D8)]),
    ], anchors=[('questTargetsLock', 0x3E0), ('playerFlags', 0xBE0)],
        base_anchors=[('RE::BSTEventSink<RE::TESTrackedStatsEvent>', 0x2D0),
                      ('RE::BSTEventSource<RE::BGSActorCellEvent>', 0x2D8)]),
    # Amiibo sinks inserted before TESPlayerBowShotEvent (upstream 4b919eaa,
    # NG kAE1799AmiiboShift).  RTTI: Amiibo sinks mdisp 0x180/0x188, later
    # sinks, the singleton bases and BSTEventSource<StatsEvent> +0x10.
    # Deleting dtor 0x8978 -> 0x8988; ctor/dtor stores 41/41 and 11/11 at +0x10.
    RecordPatch('RE::SkyrimVM', 0x8978, 0x8988, [
        Splice(0x180, 0, 0x10, bases=[
            ('RE::BSTEventSink<RE::TESAmiiboTouchEvent>', 0x180),
            ('RE::BSTEventSink<RE::TESAmiiboForcedStopDetectionEvent>', 0x188)]),
    ], anchors=[('impl', 0x200), ('InventoryEventFilterMap', 0x8948)],
        base_anchors=[('RE::BSTEventSink<RE::TESPlayerBowShotEvent>', 0x180),
                      ('RE::BSTEventSource<RE::BSScript::StatsEvent>', 0x1A8)]),
    # Eight gesture BSFixedStrings at 0x18 (upstream d3202ec0/ddf05413; the
    # 1.7.104 ctor builds "GestureEngageLL" .. "GestureDropShield" there), the
    # 1.6 block +0x40, then 0x3C new bytes before the flags.  ProcessButton
    # (slot 04 -> 06) reads ignore/heldLeft/heldRight as bytes at 0xB8/0xBA/
    # 0xBB (1.6.1170: 0x40/0x42/0x43); NG's contiguous +0x40 tail is wrong.
    # Allocation and deleting dtor 0x48 -> 0xC0.
    RecordPatch('RE::AttackBlockHandler', 0x48, 0xC0, [
        Splice(0x18, 0x30, 0xA8, expect=[
            'heldTimeMs', 'unk1C', 'controlID', 'attackType', 'pad29', 'pad2A',
            'attackCount', 'initialPowerAttackDelay', 'pad34',
            'subsequentPowerAttackDelay', 'ignore', 'unk41', 'heldLeft',
            'heldRight', 'unk44'], fields=[
            _f('gestureEngageLL', _BSFIXEDSTRING, 0x18, 8),
            _f('gestureEngageLR', _BSFIXEDSTRING, 0x20, 8),
            _f('gestureEngageRL', _BSFIXEDSTRING, 0x28, 8),
            _f('gestureEngageRR', _BSFIXEDSTRING, 0x30, 8),
            _f('gesturePunchLeft', _BSFIXEDSTRING, 0x38, 8),
            _f('gesturePunchRight', _BSFIXEDSTRING, 0x40, 8),
            _f('gestureRaiseShield', _BSFIXEDSTRING, 0x48, 8),
            _f('gestureDropShield', _BSFIXEDSTRING, 0x50, 8),
            _moved('heldTimeMs', 0x58), _moved('unk1C', 0x5C),
            _moved('controlID', 0x60), _moved('attackType', 0x68),
            _moved('pad29', 0x69), _moved('pad2A', 0x6A),
            _moved('attackCount', 0x6C), _moved('initialPowerAttackDelay', 0x70),
            _moved('pad34', 0x74), _moved('subsequentPowerAttackDelay', 0x78),
            _f('unk7C', 'arr:u8:60', 0x7C, 0x3C),
            _moved('ignore', 0xB8), _moved('unk41', 0xB9),
            _moved('heldLeft', 0xBA), _moved('heldRight', 0xBB),
            _moved('unk44', 0xBC)]),
    ]),
    # Members appended (upstream d3202ec0, NG AE1799_RUNTIME_DATA).  The
    # 1.7.104 ctor allocates 0xB8, stores 5 at 0x10, constructs a SixaxisEvent
    # at 0x18 and stores -1/0 at 0xB0/0xB4.
    RecordPatch('RE::LookHandler', 0x10, 0xB8, [
        Splice(0x10, 0, 0xA8, fields=[
            _f('unk10', 'u32', 0x10, 4), _f('pad14', 'u32', 0x14, 4),
            _f('sixaxisEvent', 'struct:RE::SixaxisEvent', 0x18, 0x90),
            _f('unkA8', 'u64', 0xA8, 8), _f('unkB0', 'i32', 0xB0, 4),
            _f('unkB4', 'u32', 0xB4, 4)]),
    ]),
    # A u32 inserted at 0x7C; the old 0x7C..0x88 members move +4 and the u64
    # tail becomes a u32 at 0x8C.  Both ctors allocate 0x90: 1.6.1170 stores
    # 1.0f/0x10000/byte at 0x7C/0x84/0x88, 1.7.104 at 0x80/0x88/0x8C.
    # Upstream d3202ec0 gives the same moves but a 0x98 size, which the
    # binary refutes.
    RecordPatch('RE::FirstPersonState', 0x90, 0x90, [
        Splice(0x7C, 0x14, 0x14, expect=[
            'unk7C', 'unk80', 'cameraOverride', 'cameraPitchOverride', 'unk86',
            'unk88'], fields=[
            _f('unk7C', 'u32', 0x7C, 4), _f('unk80', 'f32', 0x80, 4),
            _f('unk84', 'u32', 0x84, 4), _moved('cameraOverride', 0x88),
            _moved('cameraPitchOverride', 0x89), _f('unk8A', 'u16', 0x8A, 2),
            _f('unk8C', 'u32', 0x8C, 4)]),
    ], anchors=[('targetPitchOffset', 0x78)]),
    # NiRect<float> appended (upstream d3202ec0, NG); the 1.7.104 ctors store
    # 0/1.0/0/1.0 at 0x98..0xA4.  Deleting dtor 0x98 -> 0xA8.
    RecordPatch('RE::BookMenu', 0x98, 0xA8, [
        Splice(0x98, 0, 0x10, fields=[
            _f('unk98', 'struct:RE::NiRect<float>', 0x98, 0x10)]),
    ], anchors=[('pad97', 0x97)]),
    # 0x18 bytes appended (upstream d3202ec0, NG); the 1.7.104 ctor stores at
    # 0x114/0x11C/0x120/0x122.  Deleting dtor 0x110 -> 0x128.
    RecordPatch('RE::LockpickingMenu', 0x110, 0x128, [
        Splice(0x110, 0, 0x18, fields=[
            _f('unk110', 'f32', 0x110, 4), _f('unk114', 'f32', 0x114, 4),
            _f('unk118', 'u32', 0x118, 4)] + [
            _f('unk{:X}'.format(o), 'bool', o, 1) for o in range(0x11C, 0x123)] + [
            _f('pad123', 'arr:u8:5', 0x123, 5)]),
    ], anchors=[('pad10F', 0x10F)]),
    # pad44 becomes data plus a new u32 (upstream d3202ec0, NG); the 1.7.104
    # ctor stores a qword at 0x44.  Deleting dtor 0x48 -> 0x50.
    RecordPatch('RE::TESTopicInfo', 0x48, 0x50, [
        Splice(0x44, 4, 0xC, expect=['pad44'], fields=[
            _f('unk44', 'u32', 0x44, 4), _f('unk48', 'u32', 0x48, 4),
            _f('pad4C', 'u32', 0x4C, 4)]),
    ], anchors=[('fileOffset', 0x40)]),
    # bhkWorldCinfo embedded at 0xC5E0 (upstream d3202ec0, NG): the 1.7.104
    # ctor/dtor construct/destroy a bhkWorldCinfo there; every tail member
    # moves +0x108 (toggleCollision 0xC5F9 -> 0xC701 at 9 sites each, unkC5D8
    # -> 0xC6E0 at 14).  Allocation/deleting dtor 0xC600 -> 0xC710 (bhkWorldM
    # 0xC630 -> 0xC740, see EXTRA_DERIVED).
    RecordPatch('RE::bhkWorld', 0xC600, 0xC710, [
        Splice(0xC5D8, 0x28, 0x138, expect=[
            'unkC5D8', 'unkC5DC', 'unkC5E0', 'unkC5E4', 'unkC5E8', 'unkC5EC',
            'tau', 'damping', 'unkC5F8', 'toggleCollision', 'unkC5FA',
            'unkC5FC', 'unkC5FE'], fields=[
            _f('padC5D8', 'u64', 0xC5D8, 8),
            _f('worldCinfo', 'struct:RE::bhkWorldCinfo', 0xC5E0, 0x100),
            _moved('unkC5D8', 0xC6E0, 'unkC6E0'),
            _moved('unkC5DC', 0xC6E4, 'unkC6E4'),
            _moved('unkC5E0', 0xC6E8, 'unkC6E8'),
            _moved('unkC5E4', 0xC6EC, 'unkC6EC'),
            _moved('unkC5E8', 0xC6F0, 'unkC6F0'),
            _moved('unkC5EC', 0xC6F4, 'unkC6F4'),
            _moved('tau', 0xC6F8), _moved('damping', 0xC6FC),
            _moved('unkC5F8', 0xC700, 'unkC700'),
            _moved('toggleCollision', 0xC701),
            _moved('unkC5FA', 0xC702, 'unkC702'),
            _moved('unkC5FC', 0xC704, 'unkC704'),
            _moved('unkC5FE', 0xC706, 'unkC706'),
            _f('padC708', 'u64', 0xC708, 8)]),
    ], anchors=[('suspendInactiveAgentsUtil', 0xC5D0)]),
    # DEFAULT_OBJECT has 372 entries (see ENUM_PATCHES).  Deleting dtor
    # 0xD00 -> 0xD38.
    RecordPatch('RE::BGSDefaultObjectManager', 0xD00, 0xD38, [
        Splice(0x20, 0xCE0, 0xD18, expect=['objects', 'objectInit'], fields=[
            _f('objects', 'arr:ptr:struct:RE::TESForm:372', 0x20, 0xBA0),
            _f('objectInit', 'arr:bool:372', 0xBC0, 0x174),
            _f('padD34', 'u32', 0xD34, 4)]),
    ]),
    # 0x4C..0x60 regrouped, the rest +0x10 (upstream dev-1.6.1170..dev).  The
    # RIP-relative accesses into the global State match one to one: frameCount
    # 0x4C -> 0x54 (24 sites), the 0x54..0x59 flags -> 0x60..0x65, textures
    # 0x60.. -> 0x70.. (0x98 -> 0xA8: 43), dynamic resolution 0x104.. ->
    # 0x114..; the next global moves from +0x128 to +0x138.  The flag names
    # are upstream's; 0x63 is NG's legacy-AE 0x57 accessor.  The pinned 1.6
    # names at 0x50..0x53 have no accessor in either build.
    RecordPatch('RE::BSGraphics::State', 0x120, 0x130, [
        Splice(0x4C, 0x14, 0x24, expect=[
            'frameCount', 'unk50', 'letterbox', 'unk052',
            'compiledShaderThisFrame', 'insideFrame', 'unk055', 'unk56',
            'doubleDynamicResolutionAdjustmentFrequency', 'unk58', 'unk59'],
            fields=[
            _f('projectionPosScaleXUI', 'f32', 0x4C, 4),
            _f('projectionPosScaleYUI', 'f32', 0x50, 4),
            _moved('frameCount', 0x54), _f('gUpdateCounter', 'u32', 0x58, 4),
            _f('unk05C', 'u32', 0x5C, 4), _f('insideFrame', 'bool', 0x60, 1),
            _f('letterbox', 'bool', 0x61, 1), _f('unk062', 'bool', 0x62, 1),
            _f('doubleDynamicResolutionAdjustmentFrequency', 'bool', 0x63, 1),
            _f('compiledShaderThisFrame', 'bool', 0x64, 1),
            _f('useEarlyZ', 'bool', 0x65, 1), _f('unk066', 'u16', 0x66, 2),
            _f('unk068', 'bool', 0x68, 1)]),
    ], anchors=[('defaultTextureBlack', 0x60), ('dynamicResolutionLock', 0x118)]),
    # Three counters replace pad01C, the arrays move +8 and the 1.7 event
    # arrays follow kinectEvents (upstream ddf05413, NG kQueueHeadAE1799).
    # The queue head is read at 0x380 (1.6.1170) / 0x558 (1.7.104).
    RecordPatch('RE::BSInputEventQueue', 0x390, 0x568, [
        Splice(0x1C, 0x374, 0x54C, expect=[
            'pad01C', 'buttonEvents', 'charEvents', 'mouseEvents',
            'thumbstickEvents', 'connectEvents', 'kinectEvents', 'queueHead',
            'queueTail'], fields=[
            _f('sixaxisEventCount', 'u32', 0x1C, 4),
            _f('gestureEventCount', 'u32', 0x20, 4),
            _f('amiiboEventCount', 'u32', 0x24, 4),
            _moved('buttonEvents', 0x28), _moved('charEvents', 0x208),
            _moved('mouseEvents', 0x2A8), _moved('thumbstickEvents', 0x2D8),
            _moved('connectEvents', 0x338), _moved('kinectEvents', 0x358),
            _f('sixaxisEvents', 'arr:struct:RE::SixaxisEvent:2', 0x388, 0x120),
            _f('gestureEvents', 'arr:struct:RE::MotionGestureEvent:2', 0x4A8, 0x70),
            _f('amiiboEvents', 'arr:struct:RE::AmiiboEvent:1', 0x518, 0x40),
            _moved('queueHead', 0x558), _moved('queueTail', 0x560)]),
    ], anchors=[('kinectEventCount', 0x18)]),
    # devices[INPUT_DEVICES::kTotal] holds 6 entries (upstream f6d08824):
    # queuedGamepadEnableValue/valueQueued 0x80/0x81 -> 0x90/0x91.
    RecordPatch('RE::BSInputDeviceManager', 0xF0, 0x100, [
        Splice(0x60, 0x20, 0x30, expect=['devices'], fields=[
            _f('devices', 'arr:ptr:struct:RE::BSIInputDevice:6', 0x60, 0x30)]),
    ], anchors=[('queuedGamepadEnableValue', 0x80), ('unkE8', 0xE8)]),
    # deviceMappings[INPUT_DEVICES::kTotal] holds 6 BSTArrays (upstream
    # f6d08824): the loader's allocation and the sized delete pass 0x60 in
    # 1.6.1170 and 0x90 in 1.7.104.
    RecordPatch('RE::ControlMap::InputContext', 0x60, 0x90, [
        Splice(0, 0x60, 0x90, expect=['deviceMappings'], fields=[
            _f('deviceMappings',
               'arr:struct:RE::BSTArray<RE::ControlMap::UserEventMapping>:6',
               0, 0x90)]),
    ]),
)

# Records the parsed set holds without a base link to the changed class.  The
# SE PDB merge adds bhkWorldM as an opaque blob of the 1.6 size; RTTI places
# bhkWorld at offset 0 of it in both builds and its deleting dtor/allocation
# is 0xC630 (1.6.1170) / 0xC740 (1.7.104).
EXTRA_DERIVED: Dict[str, Tuple[Tuple[str, int, int], ...]] = {
    'RE::bhkWorld': (('bhkWorldM', 0, 0xC630),),
}


def _event(name: str, extra: Sequence[dict], size: int) -> dict:
    return {'name': name, 'full_name': 'RE::' + name, 'size': size,
            'extra': tuple(extra), 'base': 'RE::IDEvent'}


# Classes the pinned headers do not model.  Sizes: 1.7.104 deleting dtors
# (SixaxisEvent 0x90, MotionGestureEvent 0x38, AmiiboEvent 0x40, bhkWorldCinfo
# 0x100 in both builds); eventType 6/7/8 is stored by their 1.7.104 ctors.
# Member shapes follow upstream d3202ec0.
NEW_RECORDS = (
    _event('SixaxisEvent', [_f('data', 'arr:u8:104', 0x28, 0x68)], 0x90),
    _event('MotionGestureEvent', [
        _f('unk28', 'i32', 0x28, 4), _f('unk2C', 'i32', 0x2C, 4),
        _f('unk30', 'bool', 0x30, 1), _f('pad31', 'u8', 0x31, 1),
        _f('pad32', 'u16', 0x32, 2), _f('unk34', 'i32', 0x34, 4)], 0x38),
    _event('AmiiboEvent', [_f('data', 'arr:u8:24', 0x28, 0x18)], 0x40),
    {'name': 'bhkWorldCinfo', 'full_name': 'RE::bhkWorldCinfo', 'size': 0x100,
     'extra': (), 'base': 'RE::hkpWorldCinfo', 'record_kind': 'struct'},
)

# (root class, first inserted slot, ((name, (ret, params)), ...)).  Upstream
# d3202ec0; RTTI vtable slot counts 1.6.1170 -> 1.7.104 and slot-body
# alignment: PlayerInputHandler 5 -> 7 (+2 at 02; every handler, and the
# camera states' PlayerInputHandler subobject), MenuEventHandler 6 -> 8 (+2 at
# 02), BSWin32SystemUtility 19 -> 20 (+1 at 02), BSWin32SaveDataSystemUtility
# 18 -> 24 (+6 at 05).
VTABLE_INSERTS = (
    ('RE::PlayerInputHandler', 2, (
        ('ProcessMotionGesture', ('void', [
            ('p0', 'ptr:struct:RE::MotionGestureEvent'),
            ('p1', 'ptr:struct:RE::PlayerControlsData')])),
        ('ProcessSixaxis', ('void', [
            ('p0', 'ptr:struct:RE::SixaxisEvent'),
            ('p1', 'ptr:struct:RE::PlayerControlsData')])))),
    ('RE::MenuEventHandler', 2, (
        ('ProcessMotionGesture', ('bool', [('p0', 'ptr:struct:RE::MotionGestureEvent')])),
        ('ProcessSixaxis', ('bool', [('p0', 'ptr:struct:RE::SixaxisEvent')])))),
    ('RE::BSSystemUtility', 2, (
        ('Unk_02', ('void', [('p0', 'ptr:void')])),)),
    ('RE::BSSaveDataSystemUtility', 5, (
        ('Unk_05AE', ('void', [])), ('Unk_06AE', ('void', [])),
        ('Unk_07AE', ('bool', [])), ('Unk_08AE', ('bool', [])),
        ('Unk_09AE', ('bool', [])), ('Unk_0AAE', ('void', [])))),
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

def _patch_default_object(values):
    """DEFAULT_OBJECT: HelpManualNX at 188 and five help entries at 264..268.

    Verified against the engine's DEFAULT_OBJECT_DATA table: 366 entries in
    1.6.1170, 372 in 1.7.104 ("Help Manual NX" 188, "Help - Motion -
    Attack/Block" .. "Help - Amiibo" 264..268, "Imagespace: Load screen" 269,
    "Mods Help FormList" 371).
    """
    old = dict(values)
    expected = {'kHelpManualXBox': 187, 'kKeywordTypeAmmo': 188,
                'kHelpAttackTarget': 262, 'kImagespaceLoadscreen': 263,
                'kModsHelpFormList': 365, 'kTotal': 366}
    numbers = [v for _n, v in values]
    if (any(old.get(k) != v for k, v in expected.items()) or len(old) != len(values)
            or numbers != list(range(367))):
        raise LayoutPatchError('DEFAULT_OBJECT is not the 1.6 AE enum')
    out = []
    for name, value in values:
        if value >= 263:
            value += 6
        elif value >= 188:
            value += 1
        out.append((name, value))
        if name == 'kHelpManualXBox':
            out.append(('kHelpManualNX', 188))
        elif name == 'kHelpAttackTarget':
            out.extend((n, 264 + i) for i, n in enumerate((
                'kHelpMotionAttackBlock', 'kHelpMotionBowAiming',
                'kHelpMotionMagicAiming', 'kHelpMotionLockpicking',
                'kHelpAmiibo')))
    return out


def _patch_input_device(values):
    """kUnk3/kUnk4 precede kVirtualKeyboard (upstream f6d08824).

    The device factory's switch creates the virtual keyboard for type 3 in
    1.6.1170 and type 5 in 1.7.104.
    """
    if list(values) != [('kNone', -1), ('kKeyboard', 0), ('kMouse', 1),
                        ('kGamepad', 2), ('kVirtualKeyboard', 3), ('kTotal', 4)]:
        raise LayoutPatchError('INPUT_DEVICE is not the 1.6 AE enum')
    return [('kNone', -1), ('kKeyboard', 0), ('kMouse', 1), ('kGamepad', 2),
            ('kUnk3', 3), ('kUnk4', 4), ('kVirtualKeyboard', 5), ('kTotal', 6)]


def _patch_input_event_type(values):
    """kSixaxis/kMotionGesture/kAmiibo appended (upstream d3202ec0).

    The 1.7.104 SixaxisEvent/MotionGestureEvent/AmiiboEvent ctors store
    eventType 6/7/8.
    """
    if list(values) != [('kButton', 0), ('kMouseMove', 1), ('kChar', 2),
                        ('kThumbstick', 3), ('kDeviceConnect', 4), ('kKinect', 5)]:
        raise LayoutPatchError('INPUT_EVENT_TYPE is not the 1.6 AE enum')
    return list(values) + [('kSixaxis', 6), ('kMotionGesture', 7), ('kAmiibo', 8)]


ENUM_PATCHES = (
    ('RE::DEFAULT_OBJECTS::DEFAULT_OBJECT', _patch_default_object),
    ('RE::INPUT_DEVICES::INPUT_DEVICE', _patch_input_device),
    ('RE::INPUT_EVENT_TYPE', _patch_input_event_type),
)


# ---------------------------------------------------------------------------
# Record rewriting
# ---------------------------------------------------------------------------

def _is_blob(field: dict) -> bool:
    """An opaque byte run (PDB ``_pad_N[...]``) that may absorb a splice."""
    if field['type'].startswith('bytes:'):
        return True
    m = _ARR_RE.match(field['type'])
    return bool(m and m.group(1) in _BLOB_ELEMENTS)


def _grow_blob(field: dict, delta: int) -> dict:
    size = field['size'] + delta
    if field['type'].startswith('bytes:'):
        return dict(field, type='bytes:{}'.format(size), size=size)
    elem = _ARR_RE.match(field['type']).group(1)
    return dict(field, type='arr:{}:{}'.format(elem, size), size=size)


def _shift_bases(st: dict, start: int, delta: int, new_bases=()) -> None:
    pdb_bases = [(n, o + delta if o >= start else o)
                 for n, o in st.get('pdb_bases', [])]
    names = list(st.get('bases', []))
    for name, offset in new_bases:
        index = next((i for i, (_n, o) in enumerate(pdb_bases) if o > offset),
                     len(pdb_bases))
        pdb_bases.insert(index, (name, offset))
        if name not in names:
            names.insert(min(index, len(names)), name)
    st['pdb_bases'] = pdb_bases
    st['bases'] = names


def _splice_record(st: dict, splice: Splice, base_off: int = 0,
                   validate: bool = False) -> None:
    """Apply ``splice`` to ``st``, where the patched class sits at ``base_off``."""
    lo = base_off + splice.at
    hi = lo + splice.old_len
    delta = splice.delta
    kept, removed, blob = [], [], None
    for f in st['fields']:
        start, end = f['offset'], f['offset'] + f['size']
        if splice.old_len and lo <= start and end <= hi:
            removed.append(f)
        elif start >= hi:
            kept.append(dict(f, offset=start + delta))
        elif end <= lo:
            kept.append(f)
        elif (not validate and blob is None and _is_blob(f)
              and start <= lo and end >= hi):
            # An opaque record (SE PDB blob) absorbs the change in its padding.
            blob = _grow_blob(f, delta)
            kept.append(blob)
        else:
            raise LayoutPatchError('{}: field {} at {:#x} straddles the 1.7 '
                                   'splice at {:#x}'.format(
                                       st['full_name'], f['name'], start, lo))
    if validate and [f['name'] for f in removed] != list(splice.expect):
        raise LayoutPatchError('{}: 1.6 fields {} in [{:#x}, {:#x}) are not {}'.format(
            st['full_name'], [f['name'] for f in removed], lo, hi,
            list(splice.expect)))
    if blob is None:
        by_name = {f['name']: f for f in removed}
        for spec in splice.fields:
            if isinstance(spec, tuple):
                _kind, name, offset, rename = spec
                if name not in by_name:
                    raise LayoutPatchError('{}: no 1.6 field {} to move'.format(
                        st['full_name'], name))
                field = dict(by_name[name], offset=base_off + offset)
                if rename:
                    field['name'] = rename
            else:
                field = dict(spec, offset=base_off + spec['offset'])
            kept.append(field)
    kept.sort(key=lambda f: (f['offset'], f['type']))
    st['fields'] = kept
    _shift_bases(st, hi, delta, () if blob is not None else
                 [(n, base_off + o) for n, o in splice.bases])
    st['size'] = st['size'] + delta


def _grow_member(st: dict, field_name: str, offset: int, delta: int) -> None:
    """Embedded member at ``offset`` grew by ``delta``; move what follows it."""
    member = next((f for f in st['fields']
                   if f['offset'] == offset and f['name'] == field_name), None)
    if member is None:
        raise LayoutPatchError('{}: no member {} at {:#x}'.format(
            st['full_name'], field_name, offset))
    end = offset + member['size']
    fields = []
    for f in st['fields']:
        if f is member:
            fields.append(dict(f, size=f['size'] + delta))
        elif f['offset'] >= end:
            fields.append(dict(f, offset=f['offset'] + delta))
        elif f['offset'] + f['size'] > offset:
            raise LayoutPatchError('{}: field {} overlaps grown member {}'.format(
                st['full_name'], f['name'], field_name))
        else:
            fields.append(f)
    st['fields'] = fields
    _shift_bases(st, end, delta)
    st['size'] += delta


def _embedding_count(type_: str, target: str) -> int:
    """Element count when ``type_`` embeds ``target`` by value, else 0."""
    if target not in type_:
        return 0
    count = 1
    while True:
        if type_ == 'struct:' + target:
            return count
        m = _ARR_RE.match(type_)
        if not m:
            return 0
        type_, count = m.group(1), count * int(m.group(2))


def _dependents(structs: dict, name: str):
    """(record, base offset) deriving from ``name``; (record, field) embedding it."""
    derived, embedders = [], []
    for st in structs.values():
        if st['full_name'] == name:
            continue
        for base, offset in st.get('pdb_bases', []):
            if base == name:
                derived.append((st, offset))
                break
        for f in st.get('fields', []):
            n = _embedding_count(f['type'], name)
            if n:
                embedders.append((st, f, n))
    # Highest member first: growing it leaves the lower members' offsets valid.
    embedders.sort(key=lambda e: -e[1]['offset'])
    return derived, embedders


def _propagate(structs: dict, name: str, op, delta: int, log: list,
               seen: Optional[set] = None, depth: int = 0):
    """Carry a record change to everything deriving from or embedding it.

    ``op(record, base_offset)`` applies the change to a record holding the
    changed class at ``base_offset``.  Clang lists every nested base, so a
    record can be reached twice; ``seen`` applies the change once.
    """
    if depth > 16:
        raise LayoutPatchError('layout propagation does not terminate at ' + name)
    seen = set() if seen is None else seen
    derived, embedders = _dependents(structs, name)
    for st, offset in derived:
        if id(st) in seen:
            continue
        if st.get('record_kind') == 'union':
            raise LayoutPatchError('{} derives from {} as a union'.format(
                st['full_name'], name))
        seen.add(id(st))
        op(st, offset)
        log.append('{} (derives {} at {:#x})'.format(st['full_name'], name, offset))
        _propagate(structs, st['full_name'],
                   lambda s, o, _op=op, _b=offset: _op(s, o + _b),
                   delta, log, seen, depth + 1)
    for st, field, count in embedders:
        if st.get('record_kind') == 'union':
            raise LayoutPatchError('{} embeds {} in a union'.format(
                st['full_name'], name))
        start, grow = field['offset'], delta * count
        _grow_member(st, field['name'], start, grow)
        log.append('{} (embeds {} as {})'.format(st['full_name'], name, field['name']))
        _propagate(structs, st['full_name'],
                   lambda s, o, _n=field['name'], _s=start, _g=grow:
                   _grow_member(s, _n, o + _s, _g),
                   grow, log, seen, depth + 1)


def _check_anchors(st: dict, patch: RecordPatch) -> None:
    if st.get('size') != patch.old_size:
        raise LayoutPatchError('{} is {:#x} bytes, not the 1.6 {:#x}'.format(
            patch.name, st.get('size', 0), patch.old_size))
    fields = {(f['name'], f['offset']) for f in st['fields']}
    missing = [a for a in patch.anchors if a not in fields]
    bases = set(map(tuple, st.get('pdb_bases', [])))
    missing += [a for a in patch.base_anchors if a not in bases]
    if missing:
        raise LayoutPatchError('{} lacks its 1.6 anchors {}'.format(patch.name, missing))


def _new_record(spec: dict, structs: dict) -> dict:
    base = structs.get(spec['base'])
    if base is None:
        raise LayoutPatchError('{} needs its base {}'.format(
            spec['full_name'], spec['base']))
    fields = [dict(f) for f in base['fields']] + [dict(f) for f in spec['extra']]
    return {
        'name': spec['name'], 'full_name': spec['full_name'],
        'record_kind': spec.get('record_kind', 'class'), 'size': spec['size'],
        'category': base.get('category', '/CommonLibSSE/RE'),
        'fields': fields,
        'bases': [spec['base']] + list(base.get('bases', [])),
        'pdb_bases': [(spec['base'], 0)] + [tuple(b) for b in base.get('pdb_bases', [])],
        'has_vtable': True, 'vmethods': {}, 'methods': {},
        '_overload_aliases': {}, 'pointer_size': base.get('pointer_size', 8),
    }


def _insert_vtable_slots(structs: dict, root: str, slot: int, added) -> int:
    """Insert ``added`` virtuals at ``slot`` of ``root`` and every class using its vtable."""
    st = structs.get(root)
    if st is None or not st.get('vfuncs'):
        raise LayoutPatchError('{} has no parsed vtable'.format(root))
    known = {name for name, _off in st['vfuncs']}
    if any(name in known for name, _sig in added):
        raise LayoutPatchError('{} already has the 1.7 slots'.format(root))
    width = 8 * len(added)
    changed = 0
    for rec in structs.values():
        bases = dict((n, o) for n, o in reversed(rec.get('pdb_bases', [])))
        if rec is st or bases.get(root) == 0:
            if rec.get('vfuncs'):
                rec['vfuncs'] = [(n, o + width if o >= 8 * slot else o)
                                 for n, o in rec['vfuncs']]
                changed += 1
        secondaries = rec.get('secondary_vtables') or {}
        offset = bases.get(root)
        if offset and offset in secondaries:
            slots = [(i + len(added) if i >= slot else i, n)
                     for i, n in secondaries[offset]]
            slots += [(slot + i, name) for i, (name, _sig) in enumerate(added)]
            secondaries[offset] = sorted(slots)
            changed += 1
    st['vfuncs'] = sorted(list(st['vfuncs']) + [
        (name, 8 * (slot + i)) for i, (name, _sig) in enumerate(added)],
        key=lambda v: v[1])
    vmethods = st.setdefault('vmethods', {})
    for name, sig in added:
        vmethods[name] = (sig[0], list(sig[1]))
    return changed


def apply_ae17_layouts(structs: dict, enums: dict,
                       record_patches: Iterable[RecordPatch] = RECORD_PATCHES,
                       verbose: bool = True) -> dict:
    """Rewrite the parsed 1.6 records/enums/vtables to their 1.7.104 layouts.

    Must run after every record source is merged (clang AST, SE PDB) and before
    vtable building and flattening.  Raises :class:`LayoutPatchError` when a
    parsed shape is not the 1.6 one the patch tables were measured against.
    """
    summary = {'records': [], 'propagated': [], 'new': [], 'enums': [],
               'vtables': []}
    for spec in NEW_RECORDS:
        existing = structs.get(spec['full_name'])
        if existing is not None and existing.get('size') == spec['size'] and existing.get('fields'):
            continue
        structs[spec['full_name']] = _new_record(spec, structs)
        summary['new'].append(spec['full_name'])
    for patch in record_patches:
        st = structs.get(patch.name)
        if st is None:
            raise LayoutPatchError('1.7 layout target {} was not parsed'.format(patch.name))
        _check_anchors(st, patch)
        for splice in patch.splices:
            _splice_record(st, splice, validate=True)
            _propagate(structs, patch.name,
                       lambda s, o, _sp=splice: _splice_record(s, _sp, o),
                       splice.delta, summary['propagated'])
            for extra, offset, size in EXTRA_DERIVED.get(patch.name, ()):
                rec = structs.get(extra)
                if rec is None:
                    continue
                if rec.get('size') != size:
                    raise LayoutPatchError('{} is {:#x} bytes, not the 1.6 {:#x}'.format(
                        extra, rec.get('size', 0), size))
                _splice_record(rec, splice, offset)
                summary['propagated'].append('{} (derives {} at {:#x})'.format(
                    extra, patch.name, offset))
        if st['size'] != patch.new_size:
            raise LayoutPatchError('{} patched to {:#x}, expected {:#x}'.format(
                patch.name, st['size'], patch.new_size))
        summary['records'].append('{} {:#x}->{:#x}'.format(
            patch.name, patch.old_size, patch.new_size))
    for name, rewrite in ENUM_PATCHES:
        en = enums.get(name)
        if en is None:
            raise LayoutPatchError('1.7 enum target {} was not parsed'.format(name))
        en['values'] = rewrite(en['values'])
        summary['enums'].append(name)
    for root, slot, added in VTABLE_INSERTS:
        _insert_vtable_slots(structs, root, slot, added)
        summary['vtables'].append('{} +{}@{:02X}'.format(root, len(added), slot))
    if verbose:
        print('1.7.x layouts: {} records rewritten, {} dependents, {} new '
              'records, {} enums, {} vtable roots'.format(
                  len(summary['records']), len(summary['propagated']),
                  len(summary['new']), len(summary['enums']),
                  len(summary['vtables'])))
        for line in summary['records'] + summary['propagated']:
            print('  ' + line)
    return summary
