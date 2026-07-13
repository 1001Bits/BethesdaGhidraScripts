"""Regression tests for core safety/identity/type/matching invariants."""

import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import sys

import pytest

_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _CORE_DIR)


def _load_core(name):
    """Import a core module by explicit path under a core-qualified name.

    ``scripts/commonlibvr/`` ships same-named modules (ctor_plan, globals_plan,
    ...).  A bare ``import ctor_plan`` resolves through ``sys.modules``, so
    whichever sibling package pytest collected first would win and this suite
    would silently test the wrong module.  Loading by path under a unique name
    binds the core copy without touching the shared bare namespace.
    """
    path = os.path.join(_CORE_DIR, name + '.py')
    spec = importlib.util.spec_from_file_location('bgs_core_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


import binary_identity
import bytesig_port
import clang_types
import ghidra_import_gen
import run_vtable_pipeline

ctor_plan = _load_core('ctor_plan')
globals_plan = _load_core('globals_plan')
import steamless
import template_types
import vtable_dumper
import vtable_patcher
from vtable_layout import BinaryLayout, SlotEntry
from vtable_layout import load_csv as load_vtable_csv, save_csv as save_vtable_csv
import vtable_matcher


def test_rtti_manifest_clipping_rejects_overlay_and_out_of_image_blocks():
    manifest = {
        'machine': 0x8664, 'pointer_size': 8,
        'image_base': 0x140000000, 'image_size': 0x4000,
        'sections': [{
            'name': '.rdata', 'rva': 0x1000, 'raw_size': 0x200,
            'virtual_size': 0x300, 'readable': True,
            'writable': False, 'executable': False,
        }],
    }
    assert run_vtable_pipeline._block_manifest_intersections(
        0x140000F00, 0x1400012FF, True, manifest) == [
            (0x140001000, 0x1400011FF, manifest['sections'][0])]
    assert run_vtable_pipeline._block_manifest_intersections(
        0x140001000, 0x1400011FF, False, manifest) == []
    assert run_vtable_pipeline._block_manifest_intersections(
        0x150000000, 0x150000FFF, True, manifest) == []
    with pytest.raises(ValueError, match='i386/AMD64'):
        run_vtable_pipeline._validate_rtti_machine(
            dict(manifest, machine=0xAA64), 8)


def test_rtti_reads_writable_type_descriptors_without_scanning_them_as_cols():
    class Block:
        def __init__(self, writable=False, executable=False):
            self.writable = writable
            self.executable = executable

        def isInitialized(self):
            return True

        def isRead(self):
            return True

        def isWrite(self):
            return self.writable

        def isExecute(self):
            return self.executable

    ro_section = {'readable': True, 'writable': False,
                  'executable': False}
    data_section = {'readable': True, 'writable': True,
                    'executable': False}
    text_section = {'readable': True, 'writable': False,
                    'executable': True}

    assert run_vtable_pipeline._rtti_section_roles(
        Block(), ro_section) == (True, True)
    assert run_vtable_pipeline._rtti_section_roles(
        Block(writable=True), data_section) == (True, False)
    assert run_vtable_pipeline._rtti_section_roles(
        Block(executable=True), text_section) == (False, False)


def test_rtti_metadata_reads_are_clipped_to_section_boundaries():
    sections = [
        {'vaddr': 0x1000, 'vsize': 0x100},
        {'vaddr': 0x2000, 'vsize': 0x400},
    ]
    assert run_vtable_pipeline._bounded_metadata_read_size(
        sections, 0x1010, 0x20) == 0x20
    assert run_vtable_pipeline._bounded_metadata_read_size(
        sections, 0x10f0, 0x100) == 0x10
    assert run_vtable_pipeline._bounded_metadata_read_size(
        sections, 0x2400, 0x20) == 0
    assert run_vtable_pipeline._bounded_metadata_read_size(
        sections, 0x999, 0x20) == 0


def test_vtable_expansion_rejects_unsigned_garbage_before_java_address(
        monkeypatch):
    image_base = 0x140000000
    vtable_va = image_base + 0x2000
    manifest = {
        'image_base': image_base, 'image_size': 0x4000,
        'sections': [
            {'name': '.text', 'rva': 0x1000, 'raw_size': 0x100,
             'virtual_size': 0x100, 'readable': True, 'writable': False,
             'executable': True},
            {'name': '.rdata', 'rva': 0x2000, 'raw_size': 0x100,
             'virtual_size': 0x100, 'readable': True, 'writable': False,
             'executable': False},
        ],
    }

    class Address:
        def __init__(self, offset):
            self.offset = offset

        def getOffset(self):
            return self.offset

    class Space:
        def getAddress(self, value):
            if value > 0x7fffffffffffffff:
                raise OverflowError('would overflow Java long')
            return Address(value)

    class Block:
        def getEnd(self):
            return Address(vtable_va + 7)

        def isInitialized(self):
            return True

        def isExecute(self):
            return False

    class Memory:
        def __init__(self):
            self.block_queries = []

        def getLong(self, _address):
            return -1  # unsigned pointer becomes 0xffffffffffffffff

        def getBlock(self, address):
            self.block_queries.append(address.getOffset())
            return Block()

    class AddressFactory:
        def __init__(self, space):
            self.space = space

        def getDefaultAddressSpace(self):
            return self.space

    class Program:
        def __init__(self):
            self.space = Space()
            self.memory = Memory()

        def getMemory(self):
            return self.memory

        def getAddressFactory(self):
            return AddressFactory(self.space)

        def getDefaultPointerSize(self):
            return 8

    program = Program()
    monkeypatch.setattr(
        run_vtable_pipeline, 'resolve_backing_manifest',
        lambda *_args, **_kwargs: manifest)
    assert list(run_vtable_pipeline.expand_vtables(
        program, {vtable_va: 'Example'})) == []
    assert program.memory.block_queries == [vtable_va]


def _write_minimal_pe(path, pointer_size=8, marker=0):
    pe_offset = 0x80
    opt_size = 0xF0 if pointer_size == 8 else 0xE0
    section_offset = pe_offset + 24 + opt_size
    raw_offset = 0x200
    data = bytearray(raw_offset + 0x200)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b'PE\0\0'
    machine = 0x8664 if pointer_size == 8 else 0x14C
    struct.pack_into('<HHIIIHH', data, pe_offset + 4,
                     machine, 1, 0x12345678 + marker, 0, 0, opt_size, 0x22)
    optional = pe_offset + 24
    struct.pack_into('<H', data, optional, 0x20B if pointer_size == 8 else 0x10B)
    if pointer_size == 8:
        struct.pack_into('<Q', data, optional + 24, 0x140000000)
    else:
        struct.pack_into('<I', data, optional + 28, 0x400000)
    struct.pack_into('<I', data, optional + 56, 0x3000)
    data[section_offset:section_offset + 8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, section_offset + 8,
                     0x180, 0x1000, 0x200, raw_offset)
    struct.pack_into('<I', data, section_offset + 36, 0x60000020)
    data[raw_offset] = marker & 0xFF
    path.write_bytes(data)


def test_binary_identity_exact_manifest(tmp_path):
    pe = tmp_path / 'sample.exe'
    _write_minimal_pe(pe, 4)
    manifest = binary_identity.inspect_pe(str(pe))
    assert manifest['pointer_size'] == 4
    assert manifest['machine_name'] == 'i386'
    assert manifest['sections'][0]['executable'] is True
    assert binary_identity.manifest_matches(manifest, dict(manifest))[0]
    changed = dict(manifest, sha256='0' * 64)
    ok, reasons = binary_identity.manifest_matches(changed, manifest)
    assert not ok and any('sha256' in reason for reason in reasons)


def test_gzip_vtable_layout_output_is_deterministic(tmp_path):
    layout = BinaryLayout('fixture')
    table = layout.upsert('Actor', 0x140001000, 'Actor|primary|0x0')
    table.add(SlotEntry(0, 0x140002000, 'Actor::Run', 'AA BB'))
    first = tmp_path / 'first.csv.gz'
    second = tmp_path / 'second.csv.gz'
    save_vtable_csv(layout, str(first))
    save_vtable_csv(layout, str(second))
    assert first.read_bytes() == second.read_bytes()
    loaded = load_vtable_csv(str(first), 'loaded')
    assert loaded.get('Actor').slot(0).func_name == 'Actor::Run'


def test_vtable_layout_loader_rejects_partial_or_duplicate_evidence(tmp_path):
    malformed = tmp_path / 'malformed.csv'
    malformed.write_text(
        'class,vtable_addr,slot,func_addr\n'
        'Actor,0x1000,0,0x2000\n'
        'Actor,0x1000,0,0x2000\n', encoding='utf-8')
    try:
        load_vtable_csv(str(malformed), 'fixture')
    except ValueError as exc:
        assert 'duplicate slot' in str(exc)
    else:
        raise AssertionError('duplicate vtable evidence was silently accepted')

    malformed.write_text(
        'class,vtable_addr,slot\nActor,0x1000,0\n', encoding='utf-8')
    try:
        load_vtable_csv(str(malformed), 'fixture')
    except ValueError as exc:
        assert 'missing vtable columns' in str(exc)
    else:
        raise AssertionError('partial vtable schema was silently accepted')


def test_artifact_sidecar_binds_both_files(tmp_path):
    source = tmp_path / 'packed.exe'
    artifact = tmp_path / 'unpacked.exe'
    _write_minimal_pe(source, 8, 1)
    _write_minimal_pe(artifact, 8, 2)
    sidecar = binary_identity.make_artifact_sidecar(
        str(source), str(artifact), cache_policy=1,
        producer={'name': 'fixture', 'sha256': 'f' * 64}, arguments=[])
    assert sidecar['source']['sha256'] != sidecar['artifact']['sha256']
    sidecar_path = str(artifact) + '.identity.json'
    binary_identity.write_manifest(sidecar_path, sidecar)
    assert binary_identity.artifact_is_fresh(str(source), str(artifact), sidecar_path)


def test_steamless_preparation_never_silently_skips_missing_windows_cli(
        tmp_path, monkeypatch):
    source = tmp_path / 'game.exe'
    source.write_bytes(b'fixture')
    monkeypatch.setattr(steamless.sys, 'platform', 'win32')
    monkeypatch.setattr(
        steamless, 'inspect_pe',
        lambda _path: {'sections': [], 'sha256': 'a' * 64})
    try:
        steamless.ensure_unpacked(source, tmp_path / 'missing.exe')
    except FileNotFoundError as exc:
        assert 'Steamless CLI is required' in str(exc)
    else:
        raise AssertionError('missing Steamless CLI was silently ignored')


def test_non_windows_rejects_marked_steamstub(tmp_path, monkeypatch):
    source = tmp_path / 'game.exe'
    source.write_bytes(b'fixture')
    monkeypatch.setattr(steamless.sys, 'platform', 'linux')
    monkeypatch.setattr(
        steamless, 'inspect_pe',
        lambda _path: {'sections': [{'name': '.bind'}], 'sha256': 'a' * 64})
    try:
        steamless.ensure_unpacked(source, tmp_path / 'unused.exe')
    except RuntimeError as exc:
        assert 'SteamStub .bind section' in str(exc)
    else:
        raise AssertionError('marked SteamStub was analyzed without unpacking')


def test_loaded_program_import_hash_must_match_backing_file(tmp_path):
    pe = tmp_path / 'program.exe'
    _write_minimal_pe(pe, 8)
    manifest = binary_identity.inspect_pe(str(pe))

    class Address:
        def __init__(self, value): self.value = value
        def getOffset(self): return self.value
        def add(self, value): return Address(self.value + value)

    class Memory:
        def getBlock(self, _address): return object()

    class Program:
        def getExecutablePath(self): return str(pe)
        def getDefaultPointerSize(self): return 8
        def getImageBase(self): return Address(manifest['image_base'])
        def getExecutableSHA256(self): return '0' * 64
        def getMemory(self): return Memory()

    try:
        binary_identity.verify_ghidra_program(Program(), [manifest])
    except binary_identity.PEIdentityError as exc:
        assert 'import-time SHA-256' in str(exc)
    else:
        raise AssertionError('stale loaded Program was accepted')


def _program_fixture(path, manifest, stored_hash, anchor_bytes=None,
                     mapped_sections=True, pointer_size=None, image_base=None):
    anchor_bytes = anchor_bytes or {
        int(anchor['rva']) + index: byte
        for anchor in manifest.get('anchors', [])
        for index, byte in enumerate(bytes.fromhex(anchor['bytes']))
    }

    class Address:
        def __init__(self, value): self.value = value
        def getOffset(self): return self.value
        def add(self, value): return Address(self.value + value)

    class Memory:
        def getByte(self, address):
            return anchor_bytes[address.getOffset() - manifest['image_base']]
        def getBlock(self, _address):
            return object() if mapped_sections else None

    class Program:
        def getExecutablePath(self): return str(path)
        def getDefaultPointerSize(self):
            return pointer_size or manifest['pointer_size']
        def getImageBase(self):
            return Address(image_base or manifest['image_base'])
        def getExecutableSHA256(self): return stored_hash
        def getMemory(self): return Memory()

    return Program()


def test_missing_backing_path_requires_hash_anchors_and_sections(tmp_path):
    removed = tmp_path / 'removed.exe'
    _write_minimal_pe(removed, 8, marker=1)
    manifest = binary_identity.inspect_pe(str(removed))
    removed.unlink()

    program = _program_fixture(removed, manifest, manifest['sha256'])
    assert binary_identity.verify_ghidra_program(program, [manifest]) is manifest

    with pytest.raises(binary_identity.PEIdentityError, match='memory anchor mismatch'):
        bad_bytes = {
            int(anchor['rva']) + index: 0
            for anchor in manifest['anchors']
            for index, _byte in enumerate(bytes.fromhex(anchor['bytes']))
        }
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, manifest['sha256'], bad_bytes),
            [manifest])
    with pytest.raises(binary_identity.PEIdentityError, match='section missing'):
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, manifest['sha256'],
                             mapped_sections=False),
            [manifest])
    with pytest.raises(binary_identity.PEIdentityError, match='exact import-time'):
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, None), [manifest])
    with pytest.raises(binary_identity.PEIdentityError, match='not allowed'):
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, 'f' * 64), [manifest])
    with pytest.raises(binary_identity.PEIdentityError, match='pointer width'):
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, manifest['sha256'],
                             pointer_size=4),
            [manifest])
    with pytest.raises(binary_identity.PEIdentityError, match='image base'):
        binary_identity.verify_ghidra_program(
            _program_fixture(removed, manifest, manifest['sha256'],
                             image_base=manifest['image_base'] + 0x1000),
            [manifest])


def test_existing_replaced_backing_file_never_uses_missing_path_fallback(tmp_path):
    backing = tmp_path / 'program.exe'
    _write_minimal_pe(backing, 8, marker=1)
    allowed = binary_identity.inspect_pe(str(backing))
    program_path = backing
    if os.name == 'nt':
        program_path = '/' + str(backing).replace('\\', '/')
        assert binary_identity._program_executable_path(
            _program_fixture(program_path, allowed, allowed['sha256'])) == \
            str(backing)
    program = _program_fixture(program_path, allowed, allowed['sha256'])
    _write_minimal_pe(backing, 8, marker=2)

    with pytest.raises(binary_identity.PEIdentityError,
                       match='backing executable mismatch'):
        binary_identity.verify_ghidra_program(program, [allowed])

    backing.unlink()
    backing.mkdir()
    with pytest.raises(binary_identity.PEIdentityError,
                       match='not a regular file'):
        binary_identity.verify_ghidra_program(program, [allowed])


def test_rtti_runner_attests_missing_import_path_with_exact_local_pe(tmp_path):
    exact = tmp_path / 'exact.exe'
    _write_minimal_pe(exact, 8, marker=7)
    manifest = binary_identity.inspect_pe(str(exact))
    removed_import = tmp_path / 'deleted-steamless-temp.exe'
    program = _program_fixture(
        removed_import, manifest, manifest['sha256'])

    resolved = run_vtable_pipeline.resolve_backing_manifest(
        program, target_pe_paths=[exact])

    assert resolved['sha256'] == manifest['sha256']
    assert resolved['anchors'] == manifest['anchors']
    assert resolved['sections'] == manifest['sections']


def test_rtti_runner_accepts_complete_manifest_for_missing_import_path(tmp_path):
    exact = tmp_path / 'exact.exe'
    _write_minimal_pe(exact, 8, marker=8)
    manifest = binary_identity.inspect_pe(str(exact))
    manifest_path = tmp_path / 'exact.identity.json'
    binary_identity.write_manifest(str(manifest_path), manifest)
    program = _program_fixture(
        tmp_path / 'removed.exe', manifest, manifest['sha256'])

    resolved = run_vtable_pipeline.resolve_backing_manifest(
        program, target_manifest_paths=[manifest_path])

    assert resolved['sha256'] == manifest['sha256']


def test_rtti_runner_missing_path_without_evidence_fails_closed(tmp_path):
    exact = tmp_path / 'exact.exe'
    _write_minimal_pe(exact, 8, marker=9)
    manifest = binary_identity.inspect_pe(str(exact))
    program = _program_fixture(
        tmp_path / 'removed.exe', manifest, manifest['sha256'])

    with pytest.raises(binary_identity.PEIdentityError,
                       match='pass --target-pe or --target-manifest'):
        run_vtable_pipeline.resolve_backing_manifest(program)


def test_rtti_runner_rejects_replaced_existing_path_even_with_old_target(tmp_path):
    backing = tmp_path / 'recorded.exe'
    exact_old = tmp_path / 'exact-old.exe'
    _write_minimal_pe(backing, 8, marker=10)
    exact_old.write_bytes(backing.read_bytes())
    imported = binary_identity.inspect_pe(str(backing))
    program = _program_fixture(backing, imported, imported['sha256'])
    _write_minimal_pe(backing, 8, marker=11)

    with pytest.raises(binary_identity.PEIdentityError,
                       match='import-time SHA-256 mismatch'):
        run_vtable_pipeline.resolve_backing_manifest(
            program, target_pe_paths=[exact_old])


def test_abi_normalization_removes_contradictions():
    args, abi = clang_types._normalize_abi_args(
        ['--target=x86_64-pc-windows-msvc', '-D_WIN64', '-D_M_IX86', '-Ifoo'])
    assert abi['pointer_size'] == 4
    assert '--target=i686-pc-windows-msvc' in args
    assert '-D_WIN64' not in args
    assert '-D_M_IX86' in args


def test_abi_normalization_does_not_treat_ix86_undefine_as_x86():
    args, abi = clang_types._normalize_abi_args([
        '--target=x86_64-pc-windows-msvc',
        '-U_M_IX86', '-D_WIN64', '-D_M_X64', '-Ifoo',
    ])
    assert abi['pointer_size'] == 8
    assert abi['arch'] == 'x64'
    assert '--target=x86_64-pc-windows-msvc' in args
    assert '-U_M_IX86' in args
    assert '-D_M_IX86' not in args


def test_find_clang_prefers_explicit_override_then_path(tmp_path, monkeypatch):
    explicit = tmp_path / 'explicit-clang.exe'
    on_path = tmp_path / 'path-clang.exe'
    explicit.write_bytes(b'explicit')
    on_path.write_bytes(b'path')
    monkeypatch.setenv('BGS_CLANG_BINARY', str(explicit))
    monkeypatch.setattr(clang_types.shutil, 'which',
                        lambda executable: str(on_path))

    assert clang_types.find_clang_binary() == str(explicit)

    monkeypatch.delenv('BGS_CLANG_BINARY')
    assert clang_types.find_clang_binary() == str(on_path)


def test_find_clang_rejects_missing_explicit_override(tmp_path, monkeypatch):
    missing = tmp_path / 'missing-clang.exe'
    monkeypatch.setenv('BGS_CLANG_BINARY', str(missing))

    try:
        clang_types.find_clang_binary()
    except FileNotFoundError as exc:
        assert 'BGS_CLANG_BINARY' in str(exc)
    else:
        raise AssertionError('missing explicit Clang override was ignored')


def test_include_setup_keeps_game_specific_overlays_out_of_tracked_stubs(
        tmp_path, monkeypatch):
    commonlib = tmp_path / 'commonlib'
    rex_w32 = commonlib / 'REX' / 'W32'
    rex_w32.mkdir(parents=True)
    (rex_w32 / 'API.h').write_text(
        'inline constexpr auto TARGET_ONLY = 1;\n', encoding='utf-8')

    stubs = tmp_path / 'tracked-stubs'
    details = stubs / 'spdlog' / 'details'
    sinks = stubs / 'spdlog' / 'sinks'
    details.mkdir(parents=True)
    sinks.mkdir(parents=True)
    tracked_windows = details / 'windows_include.h'
    tracked_sink = sinks / 'wincolor_sink-inl.h'
    tracked_spdlog = stubs / 'spdlog' / 'spdlog.h'
    tracked_windows.write_text('tracked windows sentinel\n', encoding='utf-8')
    tracked_sink.write_text('tracked sink sentinel\n', encoding='utf-8')
    tracked_spdlog.write_text('tracked spdlog sentinel\n', encoding='utf-8')
    monkeypatch.delenv('VCPKG_ROOT', raising=False)

    first_runtime = len(clang_types._RUNTIME_STUB_DIRS)
    try:
        args = clang_types._setup_include_paths(str(commonlib), str(stubs))
        overlay = Path(next(arg[2:] for arg in args if arg.startswith('-I')))

        assert tracked_windows.read_text(encoding='utf-8') == \
            'tracked windows sentinel\n'
        assert tracked_sink.read_text(encoding='utf-8') == \
            'tracked sink sentinel\n'
        assert overlay.resolve() != stubs.resolve()
        assert (overlay / 'spdlog' / 'spdlog.h').read_text(
            encoding='utf-8') == 'tracked spdlog sentinel\n'
        generated = (overlay / 'spdlog' / 'details' /
                     'windows_include.h').read_text(encoding='utf-8')
        assert '#undef TARGET_ONLY' in generated
        assert (overlay / 'spdlog' / 'sinks' /
                'wincolor_sink-inl.h').read_text(
                    encoding='utf-8') == '#pragma once\n'
    finally:
        for runtime in clang_types._RUNTIME_STUB_DIRS[first_runtime:]:
            runtime.cleanup()
        del clang_types._RUNTIME_STUB_DIRS[first_runtime:]


def test_union_layout_preserves_overlapping_members():
    dump = '''
*** Dumping AST Record Layout
         0 | union RE::Value
         0 | int asInt
         0 | float asFloat
           | [sizeof=4, dsize=4, align=4]
'''
    layout = clang_types._parse_layouts_with_bases(dump)['RE::Value']
    assert layout['record_kind'] == 'union'
    assert [field['size'] for field in layout['fields']] == [4, 4]
    structs = {'RE::Value': {
        'name': 'Value', 'full_name': 'RE::Value', 'record_kind': 'union',
        'size': 4, 'fields': layout['fields'], 'bases': [], 'has_vtable': False,
        'category': '/Test/RE',
    }}
    ghidra_import_gen.flatten_structs(structs)
    assert len(structs['RE::Value']['fields']) == 2
    assert all(field['offset'] == 0 and field['size'] == 4
               for field in structs['RE::Value']['fields'])


def test_short_type_index_rejects_ambiguous_leaf():
    structs = {
        'A::Node': {'name': 'Node', 'full_name': 'A::Node'},
        'B::Node': {'name': 'Node', 'full_name': 'B::Node'},
    }
    index = ghidra_import_gen._build_type_index(structs)
    assert index['A::Node'] is structs['A::Node']
    assert 'Node' not in index


def _layout(label, entries):
    result = BinaryLayout(label)
    table = result.upsert('Actor', 0x1000)
    for slot, name, fp in entries:
        table.add(SlotEntry(slot, 0x2000 + slot, name, fp))
    return result


def test_vtable_matcher_rejects_duplicate_name_and_fingerprint():
    fp = '48 89 5C 24 08 57 48 83 EC 20'
    ref = _layout('ref', [(0, 'Actor::Tick', fp)])
    target = _layout('target', [(0, 'Actor::Tick', fp), (1, 'Actor::Tick', fp)])
    match = vtable_matcher.build_shift_map(ref, target).classes['Actor']
    assert match.ref_to_target == {}
    assert match.ambiguous_matches


def test_vtable_matcher_records_unique_evidence():
    ref = _layout('ref', [(3, 'Actor::Tick', '')])
    target = _layout('target', [(5, 'Actor::Tick', '')])
    match = vtable_matcher.build_shift_map(ref, target).classes['Actor']
    assert match.ref_to_target == {3: 5}
    assert match.match_evidence[3]['method'] == 'exact_unique_name'


def test_vtable_fingerprint_rejects_near_identical_common_prologue():
    common = '48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA'
    assert not vtable_matcher._fingerprints_match(
        common + ' E8 11 22 33 44 84 C0 75 05',
        common + ' E9 11 22 33 44 84 C0 75 05')
    assert not vtable_matcher._fingerprints_match(
        common, common + ' 90 90 90 90')


def test_vtable_fingerprint_requires_global_reciprocal_uniqueness():
    fp = ('48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA '
          'E8 11 22 33 44 84 C0 75 05')
    ref = _layout('ref', [(0, '', fp)])
    target = _layout('target', [(1, '', fp), (40, '', fp)])
    match = vtable_matcher.build_shift_map(ref, target).classes['Actor']
    assert match.ref_to_target == {}
    assert match.ambiguous_matches[0]['candidates'] == [1, 40]


def test_vtable_csv_preserves_secondary_identity(tmp_path):
    layout = BinaryLayout('test')
    primary = layout.upsert('Derived', 0x1000)
    secondary = layout.upsert(
        'Derived', 0x1100, vtable_id='Derived|Base|0x20',
        subobject_offset=0x20, is_primary=False)
    primary.add(SlotEntry(0, 0x2000, 'Derived::A', ''))
    secondary.add(SlotEntry(0, 0x2100, 'Base::B', ''))
    path = tmp_path / 'vtables.csv'
    assert save_vtable_csv(layout, str(path)) == 2
    loaded = load_vtable_csv(str(path), 'loaded')
    assert len(loaded.vtables) == 2
    assert loaded.classes['Derived'].vtable_addr == 0x1000
    assert loaded.vtables['Derived|Base|0x20'].subobject_offset == 0x20


def test_shift_map_and_patcher_preserve_secondary_table_identity():
    ref = BinaryLayout('ref')
    tgt = BinaryLayout('target')
    ref_primary = ref.upsert('Derived', 0x1000)
    tgt_primary = tgt.upsert('Derived', 0x2000)
    ref_secondary = ref.upsert(
        'Derived', 0x1100, vtable_id='Derived|secondary|32',
        subobject_offset=32, is_primary=False)
    tgt_secondary = tgt.upsert(
        'Derived', 0x2100, vtable_id='Derived|secondary|32',
        subobject_offset=32, is_primary=False)
    ref_primary.add(SlotEntry(0, 1, 'Derived::A', ''))
    tgt_primary.add(SlotEntry(1, 2, 'Derived::A', ''))
    ref_secondary.add(SlotEntry(0, 3, 'Base::B', ''))
    tgt_secondary.add(SlotEntry(2, 4, 'Base::B', ''))

    shift = vtable_matcher.build_shift_map(ref, tgt).to_json()
    assert len(shift['vtables']) == 2
    assert shift['vtables']['Derived|secondary|32']['ref_to_target'] == {
        '0x0': '0x2'}

    structs = {
        'Derived': {
            'class_full_name': 'Derived', 'vtable_kind': 'primary',
            'subobject_offset': 0, 'slots': [(0, 'A', None, None)], 'size': 8},
        'Derived|secondary|32': {
            'class_full_name': 'Derived', 'vtable_kind': 'secondary',
            'subobject_offset': 32, 'slots': [(0, 'B', None, None)], 'size': 8},
    }
    vtable_patcher.patch_vtable_structs(structs, shift, 'target', verbose=False)
    assert structs['Derived']['slots'][0][0] == 8
    assert structs['Derived|secondary|32']['slots'][0][0] == 16


def test_sparse_shift_map_cannot_erase_vtable_struct():
    original = [(index * 8, 'Fn%d' % index, None, None)
                for index in range(10)]
    structs = {'Actor': {
        'class_full_name': 'Actor', 'vtable_kind': 'primary',
        'subobject_offset': 0, 'slots': list(original), 'size': 80}}
    sparse = {'classes': {'Actor': {
        'ref_to_target': {'0x0': '0x1'},
        'unmatched_ref_slots': ['0x{:X}'.format(i) for i in range(1, 10)],
        'target_only_slots': []}}}
    vtable_patcher.patch_vtable_structs(structs, sparse, 'target', verbose=False)
    assert structs['Actor']['slots'] == original
    assert structs['Actor']['size'] == 80


def test_prefix_index_includes_last_position():
    index = bytesig_port.build_prefix_index(b'abcd', 2)
    assert index[b'cd'] == [2]


def test_bytesig_reciprocal_target_conflict_is_rejected():
    sig = b'ABCDEFGH'
    source = sig + b'12345678' + sig
    target = sig + b'XXXXXXXX'
    index = bytesig_port.build_prefix_index(target, 3)
    ported, stats = bytesig_port.port_symbols(
        [('One', 0x1000), ('Two', 0x1010)], 0x1000, source,
        0x2000, target, index, window=8, prefix_k=3)
    assert ported == []
    assert stats['target_conflict'] == 2


def test_bytesig_respects_function_boundaries():
    source = b'ABCDEFGH'
    target = b'ABCDEFGH'
    ported, stats = bytesig_port.port_symbols(
        [('One', 0x1000)], 0x1000, source, 0x2000, target,
        bytesig_port.build_prefix_index(target, 3), window=8, prefix_k=3,
        src_function_sizes={0x1000: 4}, target_function_starts={0x2000})
    assert not ported and stats['crosses_function_boundary'] == 1


def test_global_duplicate_caller_is_not_independent_evidence():
    info = globals_plan.aggregate_global_types([
        (0x1000, 'Actor', 'same'), (0x1000, 'Actor', 'same')])[0x1000]
    assert info['total'] == 1
    assert globals_plan.global_confidence(info) == 'medium'


def test_ctor_consensus_and_destructor_rejection():
    assert not ctor_plan.is_ctor('Actor::~Actor', 'Actor')
    resolved, ambiguous = ctor_plan.field_consensus([
        (0x10, 'int', 'count', 'ctor_a'),
        (0x10, 'int', 'count', 'ctor_b'),
        (0x18, 'float', 'value', 'ctor_a'),
    ])
    assert resolved[0x10]['votes'] == 2
    assert 0x18 in ambiguous


def test_template_collection_includes_method_only_types():
    structs = {'RE::Actor': {
        'full_name': 'RE::Actor', 'fields': [],
        'methods': {'Get': ('ptr:struct:RE::NiPointer<RE::Node>',
                            [('items', 'struct:RE::BSTArray<RE::Node>')], False)},
    }}
    names = template_types.collect_template_names(structs)
    assert 'RE::NiPointer<RE::Node>' in names
    assert 'RE::BSTArray<RE::Node>' in names


def test_vtable_dumper_keeps_destructor_and_function_address():
    text = ('private static vtable vtable VTABLE_Actor @ 140010000 -> '
            'vtable[0]->Actor::~Actor, vtable[1]->Actor::Update\n')
    groups = vtable_dumper._parse_vtable_response(text, 'Actor')
    assert groups[0][2] == [(0, 'Actor::~Actor'), (1, 'Actor::Update')]

    class FakeClient:
        def call_tool(self, _name, _args):
            return '{"name":"Actor::~Actor","address":"0x140001234",' \
                   '"signature":"48 89 5C 24 08"}'

    name, address, fingerprint = vtable_dumper._get_function_signature(
        FakeClient(), 'Actor::~Actor', 'Game.exe')
    assert name == 'Actor::~Actor'
    assert address == 0x140001234
    assert fingerprint.startswith('48 89')


def test_generated_importer_is_bound_and_syntactically_valid(tmp_path):
    output = tmp_path / 'Import.py'
    manifest = {
        'schema': 1, 'sha256': 'a' * 64, 'file_size': 123,
        'pointer_size': 8, 'image_base': 0x140000000, 'image_size': 0x4000,
        'sections': [{'name': '.text', 'rva': 0x1000, 'virtual_size': 0x100,
                      'raw_size': 0x100, 'executable': True}],
        'anchors': [{'rva': 0x1000, 'bytes': '90' * 16}],
        'function_starts': [],
    }
    structs = {'RE::Value': {
        'name': 'Value', 'full_name': 'RE::Value', 'record_kind': 'union',
        'size': 4, 'category': '/Test/RE', 'fields': [
            {'name': 'asInt', 'type': 'i32', 'offset': 0, 'size': 4},
            {'name': 'asFloat', 'type': 'f32', 'offset': 0, 'size': 4},
        ], 'bases': [], 'has_vtable': False,
    }}
    ghidra_import_gen.generate_script(
        {}, structs, {}, str(output), 'ae', '[]', target_manifest=manifest)
    source = output.read_text(encoding='utf-8')
    compile(source, str(output), 'exec')
    assert 'TARGET_MANIFESTS' in source
    assert 'UnionDataType' in source
    assert 'had_parent_transaction' in source
    assert 'datatype import transaction did not commit' not in source
    assert 'symbol import transaction did not commit' not in source
    assert 'CommonLib import transaction did not commit' in source
    assert 'Executable SHA-256 mismatch' in source
    assert '_symbol_evidence_matches_target(s, version_key, off)' in source
    assert 'Shared unnamed-vtable claims:' in source
    assert 'if len(claims) == 1:' in source
    assert 'max_table_slots' in source


def _run_embedded_import_transaction(program, dtm):
    parsed = ast.parse(ghidra_import_gen.GHIDRA_SCRIPT_FOOTER)
    run_node = next(node for node in parsed.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'run')
    module = ast.fix_missing_locations(ast.Module(
        body=[run_node], type_ignores=[]))
    calls = []
    namespace = {
        'currentProgram': program,
        'dtm': dtm,
        '_preflight_target': lambda: calls.append('preflight'),
        '_import_types': lambda: calls.append('types'),
        '_import_symbols': lambda: calls.append('symbols'),
        '_import_fallback_symbols': lambda: calls.append('fallback'),
        '_import_vtable_names': lambda: calls.append('vtables'),
    }
    exec(compile(module, '<embedded-import-run>', 'exec'), namespace)
    namespace['run']()
    return calls


def test_generated_importer_accepts_expected_nested_transaction_result():
    class Transactions:
        def __init__(self, has_parent):
            self.has_parent = has_parent
            self.started = []
            self.ended = []

        def getCurrentTransactionInfo(self):
            return object() if self.has_parent else None

        def startTransaction(self, label):
            self.started.append(label)
            return len(self.started)

        def endTransaction(self, transaction_id, commit):
            self.ended.append((transaction_id, commit))
            # Ghidra returns False until the caller-owned parent is closed.
            return not self.has_parent

    program = Transactions(has_parent=True)
    dtm = Transactions(has_parent=True)
    calls = _run_embedded_import_transaction(program, dtm)
    assert calls == ['preflight', 'types', 'symbols', 'fallback', 'vtables']
    assert dtm.ended == [(1, True)]
    assert program.ended == [(2, True), (1, True)]


def test_generated_importer_rejects_failed_outermost_commit():
    class Transactions:
        def getCurrentTransactionInfo(self):
            return None

        def startTransaction(self, _label):
            return 1

        def endTransaction(self, _transaction_id, _commit):
            return False

    with pytest.raises(RuntimeError, match='CommonLib import transaction'):
        _run_embedded_import_transaction(Transactions(), Transactions())


def _run_embedded_preflight(program, manifest):
    function_names = {
        '_sha256_file', '_valid_sha256', '_is_windows_host',
        '_program_executable_path', '_preflight_target',
    }
    parsed = ast.parse(ghidra_import_gen.GHIDRA_SCRIPT_HEADER)
    functions = [node for node in parsed.body
                 if isinstance(node, ast.FunctionDef)
                 and node.name in function_names]
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    namespace = {
        'os': os, 'hashlib': hashlib,
        'currentProgram': program, 'TARGET_MANIFESTS': [manifest],
        '_PSIZE': manifest['pointer_size'], '_ACTIVE_TARGET': None,
        '_LINKER_FUNCTION_STARTS': set(),
    }
    exec(compile(module, '<embedded-preflight>', 'exec'), namespace)
    namespace['_preflight_target']()
    return namespace


def test_embedded_preflight_strictly_attests_missing_backing_path(tmp_path):
    manifest = {
        'sha256': 'a' * 64, 'file_size': 123, 'pointer_size': 8,
        'image_base': 0x140000000, 'image_size': 0x3000,
        'sections': [{'name': '.text', 'rva': 0x1000,
                      'virtual_size': 0x100, 'raw_size': 0x100}],
        'anchors': [{'rva': 0x1000, 'bytes': '90' * 16}],
        'function_starts': [0x1000],
    }
    missing = tmp_path / 'removed.exe'
    program = _program_fixture(missing, manifest, manifest['sha256'])
    namespace = _run_embedded_preflight(program, manifest)
    assert namespace['_ACTIVE_TARGET'] is manifest
    assert namespace['_LINKER_FUNCTION_STARTS'] == {0x1000}

    bad_bytes = {0x1000 + index: 0 for index in range(16)}
    with pytest.raises(RuntimeError, match='anchor mismatch'):
        _run_embedded_preflight(
            _program_fixture(missing, manifest, manifest['sha256'], bad_bytes),
            manifest)
    with pytest.raises(RuntimeError, match='not allowed'):
        _run_embedded_preflight(
            _program_fixture(missing, manifest, 'b' * 64), manifest)
    with pytest.raises(RuntimeError, match='mapped PE sections'):
        no_sections = dict(manifest, sections=[])
        _run_embedded_preflight(
            _program_fixture(missing, no_sections, manifest['sha256']),
            no_sections)
    with pytest.raises(RuntimeError, match='memory anchors'):
        no_anchors = dict(manifest, anchors=[])
        _run_embedded_preflight(
            _program_fixture(missing, no_anchors, manifest['sha256']),
            no_anchors)


def test_embedded_preflight_existing_replacement_is_authoritative(tmp_path):
    backing = tmp_path / 'program.exe'
    original = b'A' * 123
    backing.write_bytes(original)
    manifest = {
        'sha256': hashlib.sha256(original).hexdigest(),
        'file_size': len(original), 'pointer_size': 8,
        'image_base': 0x140000000, 'image_size': 0x3000,
        'sections': [{'name': '.text', 'rva': 0x1000,
                      'virtual_size': 0x100, 'raw_size': 0x100}],
        'anchors': [{'rva': 0x1000, 'bytes': '90' * 16}],
        'function_starts': [],
    }
    program_path = backing
    if os.name == 'nt':
        program_path = '/' + str(backing).replace('\\', '/')
    program = _program_fixture(program_path, manifest, manifest['sha256'])
    backing.write_bytes(b'B' * len(original))

    with pytest.raises(RuntimeError, match='Executable SHA-256 mismatch'):
        _run_embedded_preflight(program, manifest)
