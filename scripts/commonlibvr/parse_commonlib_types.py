#!/usr/bin/env python3
"""Additive CommonLibVR (alandtse) type/vtable extractor for Skyrim SE/AE/VR.

Reuses scripts/commonlibsse/parse_commonlib_types.py (import-safe: main-guarded, no
top-level side effects) but repoints it at extern/CommonLibVR and parses each runtime
with exactly one ENABLE_SKYRIM_* define, so REL/Common.h resolves to that runtime's
EXCLUSIVE_* (concrete) layout. This produces TRUE VR layouts (e.g. NiAVObject == 0x138),
unlike the powerof3 path which approximates VR as SE.

Nothing in scripts/commonlibsse/ is modified. This only overrides module globals on the
imported base parser at runtime.

Type/vtable layer only for now: emitted with empty symbols ('[]'). The address layer
(VariantID(se,ae,vr) 3-arg + VR addresslib from vr_address_tools) is a separate module.

Usage:  python parse_commonlib_types.py [svr|se|ae ...]   (default: svr)
Env:    BGS_VCPKG_INCLUDE  -> include dir with real DirectXMath.h + directxtk/SimpleMath.h
                              (State.h uses SimpleMath Vector4/Matrix as members, so the
                              real sizes are required for correct layout).
"""
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))   # scripts/commonlibvr
SCRIPTS_DIR = os.path.dirname(SCRIPT_DIR)                 # scripts
PROJECT_DIR = os.path.dirname(SCRIPTS_DIR)               # repo root
SSE_DIR = os.path.join(SCRIPTS_DIR, 'commonlibsse')

# Import the shared core + the powerof3 parser as modules (import-safe).
sys.path.insert(0, os.path.join(SCRIPTS_DIR, 'core'))
sys.path.insert(0, SSE_DIR)
import parse_commonlib_types as base  # noqa: E402

CLVR_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibVR', 'include')
OPENVR_INC = os.path.join(PROJECT_DIR, 'extern', 'CommonLibVR', 'extern', 'openvr', 'headers')
# DirectXTK's SimpleMath.h (and the DirectXMath it is built on) are vendored as
# pinned submodules rather than taken from a machine-local vcpkg: RE/State.h
# holds SimpleMath Vector4/Matrix *by value*, so their real sizes decide real
# struct offsets.  A missing or hand-stubbed header does not degrade gracefully
# -- it silently shifts every field after it.  BGS_VCPKG_INCLUDE still overrides.
DXTK_INC = os.path.join(PROJECT_DIR, 'extern', 'DirectXTK', 'Inc')
DXMATH_INC = os.path.join(PROJECT_DIR, 'extern', 'DirectXMath', 'Inc')
VCPKG_INC = os.environ.get('BGS_VCPKG_INCLUDE', '')

# Extra include dirs the powerof3 path never needed:
#   - openvr: BSVRInterface.h pulls <openvr.h> under ENABLE_SKYRIM_VR
#   - DirectXMath + DirectXTK/SimpleMath.h: RE/State.h members (Vector4/Matrix)
# Appended AFTER the base include args so the stub dir (spdlog/binary_io shadows) keeps
# priority over vcpkg's real spdlog/fmt (a raw vcpkg include otherwise breaks the PCH).
_EXTRA_INCLUDES = []
if VCPKG_INC:
    _INCLUDE_CANDIDATES = [OPENVR_INC,
                           os.path.join(VCPKG_INC, 'directxtk'), VCPKG_INC]
else:
    _INCLUDE_CANDIDATES = [OPENVR_INC, DXTK_INC, DXMATH_INC]
for _p in _INCLUDE_CANDIDATES:
    if os.path.isdir(_p):
        _EXTRA_INCLUDES += ['-I', _p]
    else:
        raise SystemExit(
            'missing include dir: {}\n'
            'RE/State.h needs the openvr and DirectXTK/DirectXMath headers to lay '
            'out its members correctly; parsing without them would emit wrong '
            'struct offsets.  Run: git submodule update --init --recursive'.format(_p))

# --- additive overrides on the imported base parser (powerof3 files untouched on disk) ---
# Vtable policy: the powerof3 parse must refuse VR (it compiles VR with the SE
# define set, so its header vtables are SE's).  This parse compiles VR with
# ENABLE_SKYRIM_VR, so the AST *is* the VR layout -- emission is allowed, but
# still gated on the hand-verified anchors CSV, which anchor_verifier checks
# fail-closed.  See vtable_policy.py in this directory.
# Loaded by explicit path, not by name: importing `base` above already put
# commonlibsse's vtable_policy in sys.modules, so `import vtable_policy` here
# would silently hand back the SE/AE-only policy and this override would be a
# no-op that looks like it worked.
import importlib.util  # noqa: E402

_policy_spec = importlib.util.spec_from_file_location(
    'clvr_vtable_policy', os.path.join(SCRIPT_DIR, 'vtable_policy.py'))
_clvr_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_clvr_policy)

base._allow_vtable_emission = _clvr_policy.allow_vtable_emission

base.COMMONLIB_INCLUDE = CLVR_INCLUDE
base.SKYRIM_H = os.path.join(CLVR_INCLUDE, 'RE', 'Skyrim.h')
base.RE_INCLUDE = os.path.join(CLVR_INCLUDE, 'RE')
base.SCRIPT_DIR = SCRIPT_DIR  # -> refs/anchors resolve under commonlibvr/ (none yet => no shift, soft-skip anchors)

# Inheritance representation: route flattening through embed_structs, which embeds
# each base as a struct member when it receives DIRECT bases + OWN-only fields.
# clang_types has no such mode: its record-layout parser always yields the full
# nested base chain (pdb_bases) and no own/inherited field split, so today every
# struct takes embed_structs' per-struct flat fallback and the result equals the
# powerof3 flatten layout (byte-accurate, not compositional).  An earlier
# ``clang_types.SKIP_NESTED_BASE_FIELDS = True`` here was a dead assignment (nothing
# ever read it) and has been removed.  CLVR_EMBED=0 selects flatten_structs directly.
if os.environ.get('CLVR_EMBED', '1') != '0':
    import ghidra_import_gen as _gig  # noqa: E402  (core dir already on sys.path)
    base._flatten_structs = _gig.embed_structs
    print('Inheritance: embed_structs (falls back to a flat layout per struct: '
          'clang_types provides no direct-base/own-field split). '
          'Set CLVR_EMBED=0 to call flatten_structs directly.')

base.VERSIONS = {
    'se': {
        'defines': ['-DENABLE_SKYRIM_SE=1'] + _EXTRA_INCLUDES,   # -> EXCLUSIVE_SKYRIM_SE / FLAT
        'output': os.path.join(base.OUTPUT_DIR, 'CommonLibImport_CLVR_SE.py'),
    },
    'ae': {
        'defines': ['-DENABLE_SKYRIM_AE=1'] + _EXTRA_INCLUDES,   # -> EXCLUSIVE_SKYRIM_AE / FLAT
        'output': os.path.join(base.OUTPUT_DIR, 'CommonLibImport_CLVR_AE.py'),
    },
    'svr': {
        'defines': ['-DENABLE_SKYRIM_VR=1'] + _EXTRA_INCLUDES,   # -> EXCLUSIVE_SKYRIM_VR (true VR layout)
        'output': os.path.join(base.OUTPUT_DIR, 'CommonLibImport_CLVR_VR.py'),
    },
}


# --- address layer: CommonLibVR reloc parser + multi-runtime address DBs ---
# VR offsets come from the canonical vr_address_tools output (generated from
# database.csv), not meh321.  This repository ships a copy of that CSV, so it is
# the default; override with BGS_VR_CSV to point at your own vr_address_tools out.
_VR_CSV_FALLBACK = os.path.join(PROJECT_DIR, 'addresslibrary', 'sse', 'version-1-4-15-0.csv')
_VR_CSV = os.environ.get('BGS_VR_CSV', _VR_CSV_FALLBACK)
_ADDRLIB_SSE = os.path.join(PROJECT_DIR, 'addresslibrary', 'sse')
CLVR_SRC = os.path.join(PROJECT_DIR, 'extern', 'CommonLibVR', 'src')


def _load_commonlibvr_reloc_parser():
    """Import this dir's reloc_parser by explicit path (shares basename with the
    powerof3 one, so a plain import could alias the wrong module)."""
    import importlib.util
    p = os.path.join(SCRIPT_DIR, 'reloc_parser.py')
    spec = importlib.util.spec_from_file_location('commonlibvr_reloc_parser', p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build_address_library():
    from address_library import AddressLibrary
    lib = AddressLibrary()
    # expected_version: a renamed / swapped .bin must fail here, not shift every
    # SE or AE symbol (the powerof3 loader has always checked this).
    lib.se_db = lib.load_bin(os.path.join(_ADDRLIB_SSE, 'version-1-5-97-0.bin'),
                             expected_version=(1, 5, 97, 0))
    lib.ae_db = lib.load_bin(os.path.join(_ADDRLIB_SSE, 'versionlib-1-6-1170-0.bin'),
                             expected_version=(1, 6, 1170, 0))
    vr_csv = _VR_CSV if os.path.isfile(_VR_CSV) else _VR_CSV_FALLBACK
    lib.vr_db = AddressLibrary.load_csv(vr_csv)
    print('Address DBs: SE {}, AE {}, VR {} (from {})'.format(
        len(lib.se_db), len(lib.ae_db), len(lib.vr_db), vr_csv))
    return lib


# The method tracker reads ``if (...) {`` inside an inline body as a method
# definition; a relocation there belongs to the enclosing method, not to
# ``Class::if``.
_NOT_FUNCTION_NAMES = frozenset((
    'if', 'for', 'while', 'switch', 'return', 'else', 'do', 'case', 'catch',
    'sizeof', 'alignof', 'decltype', 'static_assert', 'noexcept', 'typeid',
    'new', 'delete', 'throw', 'co_return', 'co_await', 'co_yield', 'requires'))


def _build_symbols(addr_lib, target_layouts=None):
    """Collect RELOCATION_ID functions + VariantID RTTI/VTABLE labels into the
    symbol-dict list run_version/generate_script consume. Mirrors the powerof3
    main()'s symbol build, minus the powerof3-only Offset:: path.

    Every offset is checked against the staged executable of its runtime
    (``base._validate_symbol_offsets``): a RELOCATION_ID is not proof of a
    function, and VR offsets in .data/.rdata were shipped as functions."""
    import json as _json
    rp = _load_commonlibvr_reloc_parser()
    if target_layouts is None:
        target_layouts = base._load_target_layouts()

    func_syms, label_syms, off_map, statics, se_off_map, ae_off_map = rp.collect_relocations(
        base.RE_INCLUDE, addr_lib, verbose=True)

    if os.path.isdir(CLVR_SRC):
        src_funcs = rp.collect_src_relocations(CLVR_SRC, addr_lib, off_map,
                                               se_offset_map=se_off_map,
                                               ae_offset_map=ae_off_map, verbose=True)
    else:
        src_funcs = []
        print('  CommonLibVR src/ not found at {}, skipping'.format(CLVR_SRC))

    # Merge header + src functions, dedup on (se,ae,vr).
    merged = list(func_syms)
    seen = set((f.get('se_off'), f.get('ae_off'), f.get('vr_off')) for f in merged)
    for fs in src_funcs:
        key = (fs.get('se_off'), fs.get('ae_off'), fs.get('vr_off'))
        if key in seen:
            continue
        seen.add(key)
        merged.append(fs)

    symbols = []
    skipped_keywords = 0
    for fs in merged:
        if fs['name'] in _NOT_FUNCTION_NAMES:
            skipped_keywords += 1
            continue
        full = '{}::{}'.format(fs['class_'], fs['name']) if fs.get('class_') else fs['name']
        sig = ''
        if fs.get('ret'):
            sig = '{}({})'.format(fs['ret'], fs.get('params', ''))
            if fs.get('is_static'):
                sig = 'static ' + sig
        sym = {'n': full, 't': 'func', 'sig': sig, 'src': 'CommonLibVR'}
        if fs.get('se_off'): sym['s'] = fs['se_off']
        if fs.get('ae_off'): sym['a'] = fs['ae_off']
        if fs.get('vr_off'): sym['v'] = fs['vr_off']
        base._validate_symbol_offsets(sym, 'func', target_layouts)
        symbols.append(sym)

    for lbl in label_syms:
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibVR'}
        if lbl.get('se_off'): sym['s'] = lbl['se_off']
        if lbl.get('ae_off'): sym['a'] = lbl['ae_off']
        if lbl.get('vr_off'): sym['v'] = lbl['vr_off']
        base._validate_symbol_offsets(sym, 'label', target_layouts)
        symbols.append(sym)
    rejected = sum(len(s.get('rejected_offsets', {})) for s in symbols)
    print('Rejected {} offsets the staged executables contradict ({} staged); '
          'skipped {} keyword "functions"'.format(
              rejected, ', '.join(sorted(target_layouts)) or 'none',
              skipped_keywords))

    # Normalize __ -> :: and attach address-library IDs (si/ai) by reverse lookup.
    import re as _re
    for s in symbols:
        if '__' in s['n']:
            s['n'] = _re.sub(r':{3,}', '::', s['n'].replace('__', '::'))
    # Never a last-wins {rva: id} dict: an RVA shared by two IDs gets no ID.
    from address_library import unique_reverse_ids
    se_rva_to_id, _se_ambiguous = unique_reverse_ids(addr_lib.se_db)
    ae_rva_to_id, _ae_ambiguous = unique_reverse_ids(addr_lib.ae_db)
    for s in symbols:
        si = se_rva_to_id.get(s.get('s'))
        ai = ae_rva_to_id.get(s.get('a'))
        if si is not None: s['si'] = si
        if ai is not None: s['ai'] = ai

    funcs = [s for s in symbols if s['t'] == 'func']
    n_v = sum(1 for s in symbols if s.get('v'))
    print('Built {} symbols: {} funcs ({} with sig), {} labels; VR coverage {}'.format(
        len(symbols), len(funcs), sum(1 for s in funcs if s.get('sig')),
        len(symbols) - len(funcs), n_v))
    return _json.dumps(symbols, separators=(',', ':'))


def main():
    versions = [v for v in sys.argv[1:] if v in base.VERSIONS] or ['svr']
    types_only = '--types-only' in sys.argv
    print('CommonLibVR source: {}'.format(CLVR_INCLUDE))
    print('Versions: {}{}'.format(', '.join(versions),
                                   ' (types only)' if types_only else ''))

    if types_only:
        symbols_json = '[]'
    else:
        addr_lib = _build_address_library()
        symbols_json = _build_symbols(addr_lib)

    # Identity binding: alandtse's fork emits importers that name no target, but
    # this repo refuses to apply one (a CommonLib import stamps build-specific
    # addresses).  Reuse the powerof3 path's staging logic so a CLVR importer is
    # bound to the same exact executable under exes/skyrim/<runtime>/.
    emitted = 0
    for v in versions:
        binding, _artifact = base._target_binding(v)
        if binding is None:
            print('SKIP {}: no single exact executable staged under exes/skyrim/{}/; '
                  'refusing to emit an unbound importer'.format(
                      v, base._TARGET_DIRS.get(v, v)))
            continue
        base.run_version(v, symbols_json, target_manifest=binding)
        emitted += 1
    if not emitted:
        raise SystemExit(
            'No CLVR importer was generated: stage the exact executable for each '
            'runtime under exes/skyrim/ and re-run.')


if __name__ == '__main__':
    main()
