"""Behavioural tests for generated importers (audit items T5 T7 T9 T13 F4 I4 I5 I9).

Each test generates a REAL importer with ``generate_script`` and executes it
against ``fake_ghidra`` -- the embedded script templates are exercised
end-to-end, not grepped.
"""

import base64
import json
import os
import struct
import sys

import pytest

_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _CORE_DIR)

import fake_ghidra as fg  # noqa: E402
import ghidra_import_gen as gen  # noqa: E402

BASE = 0x140000000
PREFIX = '/CommonLibTest'


def _manifest(function_starts=()):
    return {
        'schema': 1, 'sha256': 'a' * 64, 'file_size': 0x4000,
        'pointer_size': 8, 'image_base': BASE, 'image_size': 0x10000,
        'sections': [
            {'name': '.text', 'rva': 0x1000, 'virtual_size': 0x4000,
             'raw_size': 0x4000, 'executable': True},
            {'name': '.rdata', 'rva': 0x8000, 'virtual_size': 0x1000,
             'raw_size': 0x1000, 'executable': False},
        ],
        'anchors': [{'rva': 0x1000, 'bytes': '90' * 16}],
        'function_starts': list(function_starts),
    }


def _enum(full_name, category, values, size=4):
    return {'name': full_name.split('::')[-1], 'full_name': full_name,
            'size': size, 'category': category, 'values': values}


def _struct(full_name, category, fields=(), size=8, kind='struct', **extra):
    record = {'name': full_name.split('::')[-1], 'full_name': full_name,
              'record_kind': kind, 'size': size, 'category': category,
              'fields': [dict(zip(('name', 'type', 'offset', 'size'), f))
                         for f in fields],
              'bases': [], 'has_vtable': False}
    record.update(extra)
    return record


def _generate(tmp_path, enums=(), structs=(), vtables=None, symbols=(),
              fallback=(), version='ae', manifest=None, **kwargs):
    output = tmp_path / 'Import.py'
    gen.generate_script(
        {e['full_name']: e for e in enums},
        {s['full_name']: s for s in structs},
        vtables or {}, str(output), version,
        json.dumps(list(symbols)), json.dumps(list(fallback)),
        project_name='CommonLibTest',
        target_manifest=manifest or _manifest(), **kwargs)
    source = output.read_text(encoding='utf-8')
    compile(source, str(output), 'exec')
    return source


def _run(tmp_path, program=None, manifest=None, **kwargs):
    manifest = manifest or _manifest()
    program = program or fg.Program(manifest)
    source = _generate(tmp_path, manifest=manifest, **kwargs)
    return program, fg.run_importer(source, program)


# --------------------------------------------------------------------- T5
def test_same_leaf_and_size_in_other_category_is_not_aliased(tmp_path):
    enums = [
        _enum('RE::ByteCode::Type', PREFIX + '/RE/ByteCode', [('kInt', 1)]),
        _enum('RE::FunctionMessage::Type', PREFIX + '/RE/FunctionMessage',
              [('kCall', 7)]),
    ]
    structs = [
        _struct('RE::ListA::Node', PREFIX + '/RE/ListA',
                [('item', 'ptr:struct:RE::A', 0, 8)]),
        _struct('RE::ListB::Node', PREFIX + '/RE/ListB',
                [('item', 'ptr:struct:RE::B', 0, 8)]),
    ]
    program, ns = _run(tmp_path, enums=enums, structs=structs)
    created = ns['created']
    first, second = (created['RE::ByteCode::Type'],
                     created['RE::FunctionMessage::Type'])
    assert first is not second
    assert first.values == {'kInt': 1} and second.values == {'kCall': 7}
    assert str(second.getCategoryPath()) == PREFIX + '/RE/FunctionMessage'
    assert created['RE::ListA::Node'] is not created['RE::ListB::Node']
    # both Node layouts were filled, each in its own category
    assert program.dtm.getDataType(PREFIX + '/RE/ListB', 'Node').field('item')


def test_prior_run_type_with_other_full_name_is_not_aliased(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    stale = fg.EnumDataType(PREFIX + '/RE/ByteCode', 'Type', 4)
    stale.add('kInt', 1)
    program.dtm.seed(stale)             # left behind by an earlier run
    enums = [_enum('RE::FunctionMessage::Type', PREFIX + '/RE/FunctionMessage',
                   [('kCall', 7)])]
    _program, ns = _run(tmp_path, program=program, manifest=manifest, enums=enums)
    assert ns['created']['RE::FunctionMessage::Type'] is not stale
    assert ns['created']['RE::FunctionMessage::Type'].values == {'kCall': 7}


def test_same_cpp_full_name_elsewhere_is_reused(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    demangled = program.dtm.seed(
        fg.StructureDataType('/Demangler/RE/BSScript', 'Stack', 8))
    nested_elsewhere = program.dtm.seed(
        fg.StructureDataType('/game.pdb/Other/RE/BSScript', 'Stack', 8))
    structs = [_struct('RE::BSScript::Stack', PREFIX + '/RE/BSScript')]
    _program, ns = _run(tmp_path, program=program, manifest=manifest,
                        structs=structs)
    assert ns['created']['RE::BSScript::Stack'] is demangled
    assert ns['created']['RE::BSScript::Stack'] is not nested_elsewhere
    assert program.dtm.getDataType(PREFIX + '/RE/BSScript', 'Stack') is None


def test_equivalent_definition_is_reused_but_a_different_one_is_not(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    same = fg.EnumDataType('/game.pdb', 'ACTOR_AGGRESSION', 4)
    same.add('kCalmed', -1)
    same.add('kFrenzied', 3)
    program.dtm.seed(same)
    different = fg.EnumDataType('/game.pdb', 'DIFFICULTY', 4)
    different.add('kEasy', 0)
    program.dtm.seed(different)
    wrong_size = program.dtm.seed(fg.StructureDataType('/game.pdb', 'Opaque', 16))
    enums = [
        _enum('RE::ACTOR_AGGRESSION', PREFIX + '/RE',
              [('kCalmed', -1), ('kFrenzied', 3)]),
        _enum('RE::DIFFICULTY', PREFIX + '/RE', [('kEasy', 0), ('kHard', 1)]),
    ]
    structs = [_struct('RE::Opaque', PREFIX + '/RE', size=8)]
    _program, ns = _run(tmp_path, program=program, manifest=manifest,
                        enums=enums, structs=structs)
    assert ns['created']['RE::ACTOR_AGGRESSION'] is same
    assert ns['created']['RE::DIFFICULTY'] is not different
    assert ns['created']['RE::Opaque'] is not wrong_size


# ----------------------------------------------------------------- EnumSet
def test_enumset_fields_get_their_enum_at_the_storage_width(tmp_path):
    enums = [
        _enum('RE::Kind', PREFIX + '/RE', [('kA', 0), ('kB', 1)]),
        _enum('RE::A::Type', PREFIX + '/RE/A', [('kOne', 1)]),
        _enum('RE::B::Type', PREFIX + '/RE/B', [('kTwo', 2)]),
    ]
    structs = [
        _struct('RE::NotEnum', PREFIX + '/RE', size=4),
        _struct('RE::Holder', PREFIX + '/RE', size=16, fields=[
            ('kind', 'enum:RE::Kind:1', 0, 1),
            ('wide', 'enum:RE::Kind:4', 4, 4),          # storage == enum size
            ('a', 'enum:RE::A::Type:1', 8, 1),
            ('b', 'enum:RE::B::Type:1', 9, 1),
            ('odd', 'enum:RE::NotEnum:2', 10, 2),       # name is not an enum
            ('pair', 'arr:enum:RE::Kind:2:2', 12, 4)]),
    ]
    program, ns = _run(tmp_path, enums=enums, structs=structs)
    holder = program.dtm.getDataType(PREFIX + '/RE', 'Holder')
    kind = holder.field('kind').getDataType()
    assert isinstance(kind, fg.EnumDataType) and kind.getName() == 'Kind'
    assert kind.getLength() == 1 and kind.values == {'kA': 0, 'kB': 1}
    assert str(kind.getCategoryPath()) == '/_sized_enums/1' + PREFIX + '/RE'
    assert holder.field('wide').getDataType() is ns['created']['RE::Kind']
    a, b = holder.field('a').getDataType(), holder.field('b').getDataType()
    assert a is not b                     # two 'Type' enums never share a copy
    assert (a.values, b.values) == ({'kOne': 1}, {'kTwo': 2})
    assert holder.field('odd').getDataType().getLength() == 2
    pair = holder.field('pair').getDataType().element
    assert (pair.getName(), pair.getLength()) == ('Kind', 2) and pair is not kind


# --------------------------------------------------------------------- T7
def _class_with_update(full_name, extra_vfuncs=()):
    return _struct(
        full_name, PREFIX + '/RE', has_vtable=True,
        vfuncs=[('Update', 0)] + list(extra_vfuncs),
        vmethods={'Update': ('void', [['delta', 'f32']]),
                  'Load': ('bool', [['id', 'u32']])})


def test_vtable_slot_function_definitions_are_per_class(tmp_path):
    structs = [_class_with_update('RE::Actor'),
               _class_with_update('RE::Projectile')]
    by_name = {s['full_name']: s for s in structs}
    vtables = gen.build_vtable_structs(by_name)
    program, ns = _run(tmp_path, structs=structs, vtables=vtables)
    actor = program.dtm.getDataType(PREFIX + '/RE', 'Actor_Update_t')
    projectile = program.dtm.getDataType(PREFIX + '/RE', 'Projectile_Update_t')
    assert actor is not None and projectile is not None
    assert program.dtm.getDataType(PREFIX + '/RE', 'Update_t') is None
    assert actor.getArguments()[0].getDataType().target is ns['created']['RE::Actor']
    assert (projectile.getArguments()[0].getDataType().target
            is ns['created']['RE::Projectile'])
    slot = program.dtm.getDataType(PREFIX + '/RE', 'Actor_vtbl').field('Update')
    assert slot.getDataType().target is actor


def test_overloaded_virtuals_get_distinct_untyped_slots(tmp_path):
    structs = [_class_with_update('RE::Actor', [('Load', 8), ('Load', 16)])]
    vtables = gen.build_vtable_structs({s['full_name']: s for s in structs})
    slots = {off: (name, ret, params)
             for off, name, ret, params in vtables['RE::Actor']['slots']}
    # T9: ONE stored signature must not be stamped on every overload.
    assert slots[0] == ('Update', 'void', [['delta', 'f32']])
    assert slots[8] == ('Load', None, None)
    assert slots[16] == ('Load', None, None)
    # T7: if overload slots ever carry signatures their names stay distinct.
    typed = dict(vtables)
    typed['RE::Actor'] = dict(vtables['RE::Actor'], slots=[
        (0, 'Update', 'void', []), (8, 'Load', 'bool', [['id', 'u32']]),
        (16, 'Load', 'bool', [['name', 'ptr']])])
    program, _ns = _run(tmp_path, structs=structs, vtables=typed)
    names = sorted(name for (_cat, name) in program.dtm.types if name.endswith('_t'))
    assert names == ['Actor_Load_008_t', 'Actor_Load_010_t', 'Actor_Update_t']


# -------------------------------------------------------------------- T13
def test_namespace_free_function_gets_no_this(tmp_path):
    structs = [
        _struct('RE::MagicSystem', PREFIX + '/RE/MagicSystem', size=0,
                kind='namespace'),
        _struct('RE::Actor', PREFIX + '/RE'),
    ]
    symbols = [
        {'n': 'MagicSystem::GetCannotCastString', 't': 'func', 'a': 0x1000,
         'sd': ['ptr', [['reason', 'u32']], 0]},
        {'n': 'Actor::AddSpell', 't': 'func', 'a': 0x1100,
         'sd': ['bool', [['spell', 'ptr']], 0]},
        {'n': 'MagicSystem::FromHeader', 't': 'func', 'a': 0x1200,
         'sig': 'int FromHeader(int a_value)'},
    ]
    manifest = _manifest([0x1000, 0x1100, 0x1200])
    program = fg.Program(manifest)
    for rva in (0x1000, 0x1100, 0x1200):
        program.add_function(rva)
    source = _generate(tmp_path, structs=structs, symbols=symbols,
                       manifest=manifest)
    ns = fg.run_importer(source, program)
    assert program.function_at(0x1000).fdef.param_names() == ['reason']
    assert program.function_at(0x1100).fdef.param_names() == ['this', 'spell']
    assert 'this' not in program.function_at(0x1200).fdef.param_names()
    # the emitted data itself is corrected (seed_this.py reads sd[2])
    emitted = {s['n']: s for s in ns['SYMBOLS']}
    assert emitted['MagicSystem::GetCannotCastString']['sd'][2] == 1
    assert emitted['Actor::AddSpell']['sd'][2] == 0
    assert ns['NAMESPACE_OWNERS'] == frozenset(['MagicSystem', 'RE::MagicSystem'])


def test_record_with_a_namespace_twin_keeps_this(tmp_path):
    structs = [_struct('RE::Util', PREFIX + '/RE/Util', size=0, kind='namespace'),
               _struct('Other::Util', PREFIX + '/Other')]
    assert gen._namespace_owner_names(
        {s['full_name']: s for s in structs}) == {'RE::Util'}


# --------------------------------------------------------------------- F4
def test_version_keys_are_shared_and_unknown_version_raises(tmp_path):
    assert gen.version_keys('svr') == ('v', 'si')
    assert gen.version_keys('se') == ('s', 'si')
    assert gen.version_keys('sf') == ('sf', 'ai')
    assert gen.version_keys('fnv')[0] == 'fnv'
    with pytest.raises(ValueError, match='unknown importer VERSION'):
        _generate(tmp_path, version='skyrim_next')
    source = _generate(tmp_path, version='ae')
    assert ".get(VERSION, 'a')" not in source
    program = fg.Program(_manifest())
    broken = source.replace("VERSION = 'ae'", "VERSION = 'skyrim_next'")
    with pytest.raises(RuntimeError, match='Unknown importer VERSION'):
        fg.run_importer(broken, program)
    assert program.committed('Atomic CommonLib import') == [False]


def test_skyrim_vr_never_receives_an_ae_id_comment(tmp_path):
    symbols = [
        {'n': 'AEOnly', 't': 'func', 'a': 0x1000, 'ai': 111},      # AE RVA == VR RVA
        {'n': 'VRFunc', 't': 'func', 'v': 0x1100, 'si': 222, 'ai': 333},
    ]
    _program, ns = _run(tmp_path, version='svr', symbols=symbols)
    assert ns['_build_rva_to_id']() == {0x1100: 222}
    _program, ns = _run(tmp_path, version='ae', symbols=symbols)
    assert ns['_build_rva_to_id']() == {0x1000: 111}


def test_address_library_map_round_trips_ids_above_32_bits(tmp_path):
    wanted = {0x1000: 5375528368, 0x2000: 7}
    source = _generate(tmp_path, version='svr', address_lib_map=wanted)
    ns = fg.run_importer(source, fg.Program(_manifest()))
    assert ns['_build_rva_to_id']() == wanted
    blob = base64.b64decode(ns['_ADDRLIB_B64'])
    assert len(blob) == 2 * struct.calcsize(gen.ADDRLIB_RECORD)


# --------------------------------------------------------------------- I4
def _sig_fixture(tmp_path):
    manifest = _manifest([0x1000, 0x1100])
    program = fg.Program(manifest)
    program.add_function(0x1000, 'Actor::AddSpell')
    program.add_function(0x1100, 'Actor::RemoveSpell')
    symbols = [
        {'n': 'Actor::AddSpell', 't': 'func', 'a': 0x1000,
         'sd': ['bool', [['spell', 'ptr']], 0]},
        {'n': 'Actor::RemoveSpell', 't': 'func', 'a': 0x1100,
         'sd': ['bool', [['spell', 'ptr']], 0]},
    ]
    return manifest, program, symbols


def test_primary_pass_keeps_user_defined_prototype(tmp_path, capsys):
    manifest, program, symbols = _sig_fixture(tmp_path)
    analyst = fg.FunctionDefinitionDataType('/', 'AddSpell')
    analyst.setReturnType(fg.IntegerDataType())
    program.function_at(0x1000).fdef = analyst
    program.function_at(0x1000).signature_source = fg.SourceType.USER_DEFINED
    imported = fg.FunctionDefinitionDataType('/', 'RemoveSpell')
    imported.setReturnType(fg.IntegerDataType())
    program.function_at(0x1100).fdef = imported
    program.function_at(0x1100).signature_source = fg.SourceType.IMPORTED
    _run(tmp_path, program=program, manifest=manifest, symbols=symbols)
    assert program.function_at(0x1000).fdef is analyst
    assert program.function_at(0x1000).signature_source == fg.SourceType.USER_DEFINED
    # a non-analyst prototype is still refreshed by the authoritative source
    assert program.function_at(0x1100).fdef is not imported
    assert 'USER_DEFINED prototypes kept: 1' in capsys.readouterr().out


def test_rejected_signature_command_is_counted_as_failure(tmp_path, capsys):
    manifest, program, symbols = _sig_fixture(tmp_path)
    program.fail_signature_at.add(BASE + 0x1000)
    _run(tmp_path, program=program, manifest=manifest, symbols=symbols)
    out = capsys.readouterr().out
    assert 'Signatures applied: 1, failed: 1' in out
    assert program.function_at(0x1000).fdef is None


def _run_with_flat_create(source, program):
    """``fake_ghidra.run_importer`` with createFunction as Ghidra 12's
    FlatProgramAPI implements it: a passed name is recorded as USER_DEFINED."""
    names_passed = []

    def create_function(address, name):
        names_passed.append(name)
        function = fg.Function(program, address,
                               name or 'FUN_{:08x}'.format(address.getOffset()))
        if name is not None:
            function.name_source = fg.SourceType.USER_DEFINED
        program.functions[address.getOffset()] = function
        return function

    namespace = {'__name__': '__bgs_generated_importer__',
                 'currentProgram': program, 'monitor': fg._Monitor(),
                 'createFunction': create_function}
    previous = fg.install()
    try:
        exec(compile(source, '<generated-importer>', 'exec'), namespace)
    finally:
        fg.uninstall(previous)
    return names_passed


def test_created_functions_carry_the_import_source_not_user_defined(tmp_path):
    manifest = _manifest([0x1000, 0x1100])
    program = fg.Program(manifest)
    source = _generate(
        tmp_path, manifest=manifest,
        symbols=[{'n': 'Actor::Update', 't': 'func', 'a': 0x1000}],
        fallback=[{'n': 'Actor::Load', 't': 'func', 'a': 0x1100}])
    assert _run_with_flat_create(source, program) == [None, None]
    update, load = program.function_at(0x1000), program.function_at(0x1100)
    assert (update.getName(), update.name_source) == (
        'Actor::Update', fg.SourceType.IMPORTED)
    assert (load.getName(), load.name_source) == ('Actor::Load', fg.SourceType.ANALYSIS)


def test_vtable_prototype_replaces_only_an_analyser_guess(tmp_path):
    vtable_rva = 0x8010
    manifest = _manifest([0x1000, 0x1100, 0x1200])
    program = fg.Program(manifest)
    previous = {}
    for slot, (rva, source) in enumerate([(0x1000, fg.SourceType.ANALYSIS),
                                          (0x1100, fg.SourceType.USER_DEFINED),
                                          (0x1200, fg.SourceType.IMPORTED)]):
        function = program.add_function(rva)
        function.fdef = fg.FunctionDefinitionDataType('/', 'guess')
        function.fdef.setReturnType(fg.IntegerDataType())
        function.signature_source = source
        previous[rva] = function.fdef
        program.memory.qwords[BASE + vtable_rva + 8 * slot] = BASE + rva
    actor = _struct('RE::Actor', PREFIX + '/RE', has_vtable=True,
                    vfuncs=[('Update', 0), ('Load', 8), ('Save', 16)],
                    vmethods={'Update': ('void', [['delta', 'f32']]),
                              'Load': ('bool', [['id', 'u32']]),
                              'Save': ('bool', [])})
    _run(tmp_path, program=program, manifest=manifest, structs=[actor],
         vtables=gen.build_vtable_structs({'RE::Actor': actor}),
         symbols=[{'n': 'VTABLE_Actor', 't': 'label', 'a': vtable_rva}])
    guessed = program.function_at(0x1000)
    assert guessed.fdef is not previous[0x1000]
    assert guessed.signature_source == fg.SourceType.IMPORTED
    assert [a.getName() for a in guessed.fdef.getArguments()] == ['this', 'delta']
    assert program.function_at(0x1100).fdef is previous[0x1100]   # analyst
    assert program.function_at(0x1200).fdef is previous[0x1200]   # an import


# --------------------------------------------------------------------- I5
def test_decorated_fallback_names_are_sanitised_not_dropped(tmp_path, capsys):
    decorated = 'public: virtual void __cdecl CXAPOBase::UnlockForProcess(void)'
    fallback = [
        {'n': decorated, 't': 'func', 'a': 0x1000, 'src': 'pdb'},
        {'n': 'WinMain(HINSTANCE hInstance, int nShowCmd)', 't': 'func',
         'a': 0x1100, 'src': 'ida'},
        {'n': 'TESFile::GetChunkData(char*)', 't': 'func', 'a': 0x1200, 'src': 'pdb'},
        {'n': 'TESFile::GetChunkData(uint)', 't': 'func', 'a': 0x1300, 'src': 'pdb'},
    ]
    manifest = _manifest([0x1000, 0x1100, 0x1200, 0x1300])
    program = fg.Program(manifest)
    for rva in manifest['function_starts']:
        program.add_function(rva)
    _run(tmp_path, program=program, manifest=manifest, fallback=fallback)
    assert program.function_at(0x1000).getName() == 'CXAPOBase::UnlockForProcess'
    assert 'Symbol: ' + decorated in program.comment_at(0x1000)
    assert program.function_at(0x1100).getName() == 'WinMain'
    assert program.function_at(0x1200).getName() == 'TESFile::GetChunkData'
    assert program.function_at(0x1300).getName() == 'TESFile::GetChunkData'
    assert 'Symbol: TESFile::GetChunkData(uint)' in program.comment_at(0x1300)
    out = capsys.readouterr().out
    assert 'Fallback: applied 4' in out
    assert 'Fallback symbols failures: 0 of 4' in out


def test_decorated_fallback_name_is_deduplicated_against_primary(tmp_path, capsys):
    symbols = [{'n': 'TESFile::OpenTES', 't': 'func', 'a': 0x1000},
               {'n': 'TESFile::CloseTES(bool)', 't': 'func', 'a': 0x1400},
               {'n': 'RE::Actor::AddSpell', 't': 'func', 'a': 0x1500}]
    fallback = [
        # an overload of an undecorated primary: another function, kept
        # (exactly like two fallback overloads of one name are)
        {'n': 'TESFile::OpenTES(NiFile::OpenMode,bool)', 't': 'func', 'a': 0x1100},
        {'n': 'TESFile::OpenTES(NiFile::OpenMode,bool)', 't': 'func', 'a': 0x1000},
        # the primary's own name AND arguments elsewhere: one function claimed
        # at two addresses, dropped; its const overload is another function
        {'n': 'public: void __cdecl TESFile::CloseTES(bool) __ptr64', 't': 'func',
         'a': 0x1200},
        {'n': 'TESFile::CloseTES(bool) const', 't': 'func', 'a': 0x1600},
        {'n': 'TESFile::OpenTES', 't': 'func', 'a': 0x1300},   # driver's call
        {'n': 'public: bool __cdecl RE::Actor::AddSpell(class RE::SpellItem *,int)',
         't': 'func', 'a': 0x1700},
    ]
    _program, ns = _run(tmp_path, symbols=symbols, fallback=fallback)
    assert [(s['n'], s['a']) for s in ns['FALLBACK_SYMBOLS']] == [
        ('TESFile::OpenTES(NiFile::OpenMode,bool)', 0x1100),
        ('TESFile::OpenTES(NiFile::OpenMode,bool)', 0x1000),
        ('TESFile::CloseTES(bool) const', 0x1600),
        ('TESFile::OpenTES', 0x1300),
        ('public: bool __cdecl RE::Actor::AddSpell(class RE::SpellItem *,int)', 0x1700)]
    assert 'Dropped 1 fallback symbols' in capsys.readouterr().out


def test_vtable_signature_skips_a_fallback_overload_of_a_primary_name(tmp_path):
    actor = _class_with_update('RE::Actor', [('Load', 8)])
    vtables = gen.build_vtable_structs({'RE::Actor': actor})
    symbols = [{'n': 'Actor::Update', 't': 'func', 'a': 0x1000}]
    fallback = [{'n': 'Actor::Update(float,int)', 't': 'func', 'a': 0x1100},
                {'n': 'Actor::Load(unsigned int)', 't': 'func', 'a': 0x1200}]
    _program, ns = _run(tmp_path, structs=[actor], vtables=vtables,
                        symbols=symbols, fallback=fallback)
    update, load = ns['FALLBACK_SYMBOLS']
    assert 'sd' not in update          # the vtable's Update may be the primary's
    assert load['sd'] == ['bool', [['id', 'u32']], 0]


def _failing_symbols(count):
    return [{'n': 'BAD_{}'.format(i), 't': 'label', 'a': 0x8000 + i * 8}
            for i in range(count)]


def test_swallowed_failures_are_counted_and_reported(tmp_path, capsys):
    manifest = _manifest()
    program = fg.Program(manifest)
    program.fail_name_prefix = 'BAD_'
    symbols = _failing_symbols(3) + [{'n': 'Good', 't': 'label', 'a': 0x8800}]
    _run(tmp_path, program=program, manifest=manifest, symbols=symbols)
    out = capsys.readouterr().out
    assert 'Primary symbols failures: 3 of 4 (budget 25)' in out
    assert 'FAILED label BAD_0: JavaError' in out
    assert 'All passes complete (Primary symbols=3)' in out
    assert program.committed('Atomic CommonLib import') == [True]


def test_failures_over_budget_roll_the_import_back(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    program.fail_name_prefix = 'BAD_'
    with pytest.raises(RuntimeError, match='26 of 26 symbols failed'):
        _run(tmp_path, program=program, manifest=manifest,
             symbols=_failing_symbols(26))
    assert program.committed('Symbol import') == [False]
    assert program.committed('Atomic CommonLib import') == [False]
    assert 'BGS_PROVENANCE' not in program.options.strings


def test_fallback_failures_over_budget_roll_back_too(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    program.fail_name_prefix = 'BAD_'
    with pytest.raises(RuntimeError, match='Fallback symbols: 26 of 26'):
        _run(tmp_path, program=program, manifest=manifest,
             fallback=_failing_symbols(26))
    assert program.committed('Atomic CommonLib import') == [False]


# --------------------------------------------------------------------- I9
def test_provenance_is_written_inside_the_import_transaction(tmp_path):
    program, _ns = _run(tmp_path)
    events = program.transactions
    assert events.index(('start', 'BGS provenance')) < events.index(
        ('end', 'Atomic CommonLib import', True))
    assert events[-1] == ('end', 'Atomic CommonLib import', True)
    assert 'BGS_PROVENANCE' in program.options.strings


def test_provenance_failure_rolls_the_import_back(tmp_path):
    manifest = _manifest()
    program = fg.Program(manifest)
    program.fail_provenance = True
    with pytest.raises(fg.JavaError, match='provenance storage failed'):
        _run(tmp_path, program=program, manifest=manifest,
             symbols=[{'n': 'Good', 't': 'label', 'a': 0x8800}])
    assert program.committed('Symbol import') == [True]
    assert program.committed('Atomic CommonLib import') == [False]


def test_generated_importer_still_ends_with_run_call(tmp_path):
    # apply_enrich.py / stamp_provenance.py cut the script at the final run().
    source = _generate(tmp_path)
    assert source.rstrip().endswith('\nrun()')
    assert source.count('_apply_bgs_provenance()') == 1      # only the def


# ---------------------------------------------------------------- sanitiser
@pytest.mark.parametrize('raw, expected', [
    ('Actor::Update', 'Actor::Update'),
    ('Foo::operator()', 'Foo::operator()'),
    ('public: virtual void __cdecl CXAPOBase::UnlockForProcess(void)',
     'CXAPOBase::UnlockForProcess'),
    ('BGSUtil::FreeBlock(void*, uint32_t)', 'BGSUtil::FreeBlock'),
    ('WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance', 'WinMain'),
    ('??0_Fac_node@std@@QEAA@Z_340public: __cdecl std::_Fac_node::_Fac_node('
     'struct std::_Fac_node *)', 'std::_Fac_node::_Fac_node'),
    ('PathManagerMessage::operator=(class PathManagerMessage const &)',
     'PathManagerMessage::operator='),
    ('std::less<int>::operator()(int, int) const', 'std::less<int>::operator()'),
    ('Foo::operator<<(int)', 'Foo::operator<<'),
    ('public: static void * __cdecl Foo::operator new(unsigned __int64)',
     'Foo::operator_new'),
    ("public: virtual void * __cdecl Foo::`scalar deleting destructor'(unsigned int)",
     "Foo::`scalar_deleting_destructor'"),
    ('`anonymous_namespace::NearestCellSort(TESObjectCELL*,TESObjectCELL*)',
     '`anonymous_namespace::NearestCellSort'),
    ('Foo<void (int)>::Bar(float)', 'Foo<void_(int)>::Bar'),
    ('protected: static class Foo * Foo::instance', 'Foo::instance'),
    ('int (__cdecl* Foo::ptr)(void)', 'Foo::ptr'),
    ("RTTI_Queue<struct `anonymous namespace'::Policy,class A::B * __ptr64>",
     "RTTI_Queue<`anonymous_namespace'::Policy,A::B*>"),
    # a trailing qualifier without an argument list is not the name
    ('TESForm::GetFormType const', 'TESForm::GetFormType'),
    ('A::B const volatile __ptr64', 'A::B'),
    # '> >' is the primary symbols' '>>' spelling
    ('Foo<std::pair<int,int> >', 'Foo<std::pair<int,int>>'),
    ('public: void __cdecl Foo<Bar<Baz<int> > >::f(void)', 'Foo<Bar<Baz<int>>>::f'),
    ('(void)', ''), ('', ''), (None, ''),
])
def test_sanitize_symbol_name(raw, expected):
    result = gen.sanitize_symbol_name(raw)
    assert result == expected
    assert not any(ch.isspace() for ch in result)
    assert gen.sanitize_symbol_name(result) == result        # idempotent


def test_generated_importer_embeds_the_same_sanitiser(tmp_path):
    ns = fg.run_importer(_generate(tmp_path), fg.Program(_manifest()))
    raw = 'public: virtual void __cdecl A::B(int, float) const'
    assert ns['sanitize_symbol_name'](raw) == gen.sanitize_symbol_name(raw) == 'A::B'


def test_enum_values_get_one_consistent_sign_representation():
    """Ghidra enums are signed OR unsigned as a whole; mixing aborts the import."""
    from ghidra_import_gen import normalize_enum_values as norm

    # -1 and 0xFFFFFFFF in one 4-byte enum (XAUDIO2_WINDOWS_PROCESSOR_SPECIFIER)
    assert norm([('Any', 0xFFFFFFFF), ('Default', -1), ('P1', 1)], 4) == [
        ('Any', 0xFFFFFFFF), ('Default', 0xFFFFFFFF), ('P1', 1)]
    # purely signed and purely unsigned enums are left exactly as they are
    assert norm([('kNone', -1), ('kA', 0)], 4) == [('kNone', -1), ('kA', 0)]
    assert norm([('kAll', 0xFFFFFFFF), ('kA', 0)], 4) == [('kAll', 0xFFFFFFFF), ('kA', 0)]
    assert norm([('kNeg', -1), ('kHigh', 0x80)], 1) == [('kNeg', 0xFF), ('kHigh', 0x80)]
    # a value wider than the enum is reduced to the enum's width
    assert norm([('kWide', 0x1FF)], 1) == [('kWide', 0xFF)]
    # 8-byte enums stay inside a Java long
    assert norm([('kTop', 0xFFFFFFFFFFFFFFFF), ('kA', 1)], 8) == [('kTop', -1), ('kA', 1)]


def test_function_absorbs_a_same_named_label_left_at_its_entry(tmp_path):
    # A FUN_ function whose real name already sits at its entry as a label
    # (left by an earlier pass) used to fail with DuplicateNameException.
    manifest = _manifest([0x1000, 0x1100])
    program = fg.Program(manifest)
    for rva in (0x1000, 0x1100):
        program.add_function(rva)
    table = program.getSymbolTable()
    table.createLabel(fg.Address(BASE + 0x1000), 'Actor::Update', fg.SourceType.IMPORTED)
    table.createLabel(fg.Address(BASE + 0x1100), 'Actor::Load', fg.SourceType.USER_DEFINED)
    source = _generate(tmp_path, manifest=manifest, symbols=[
        {'n': 'Actor::Update', 't': 'func', 'a': 0x1000},
        {'n': 'Actor::Load', 't': 'func', 'a': 0x1100}])
    fg.run_importer(source, program)
    assert program.function_at(0x1000).getName() == 'Actor::Update'
    assert not table.getSymbols(fg.Address(BASE + 0x1000))
    # an analyst's label is never deleted to make room
    assert program.function_at(0x1100).getName().startswith('FUN_')
    assert [s.getName() for s in table.getSymbols(fg.Address(BASE + 0x1100))] == ['Actor::Load']
