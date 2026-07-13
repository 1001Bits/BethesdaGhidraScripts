#!/usr/bin/env python3
"""
Parse libxse/commonlibf4 headers and generate Ghidra import scripts for
Fallout 4 OG / NG / AE / VR.

Pipeline:
  Types:        core/clang_types.py  (clang AST dump + record layouts)
  Relocations:  reloc_parser.py      (IDs.h map + ID::Class::Method references)
  Address lib:  address_library.py   (OG / NG / AE / VR)
  Fallback:     ida_names.py         (extras/IDAImportNames_1.11.191.0.py)
  Script gen:   core/ghidra_import_gen.py

Generates:
  ghidrascripts/CommonLibImport_F4_OG.py   (types/labels only)
  ghidrascripts/CommonLibImport_F4_NG.py   (types + NG-resolved symbols)
  ghidrascripts/CommonLibImport_F4_AE.py   (types + AE-resolved symbols)
  ghidrascripts/CommonLibImport_F4_VR.py   (types/labels only)

Symbol resolution
-----------------
CommonLibF4's desktop IDs are managed by meh321 with one ID space across
OG / NG / AE / 1.11.221.  The community VR database uses a different ID
space.  Desktop IDs must therefore never be looked up in ``vr_db``: a
numeric hit there is only a coincidental collision, not the same symbol.
Each desktop symbol carries the offsets that resolve in its shared ID
namespace; VR addresses come only from explicitly VR-authored evidence.

Function-name coverage for IDs that exist only in AE (the remaining 17%)
is recovered post-generation via masked byte-signature porting — see
`run_bytesig_port.py`.
"""

import os
import sys
import re
import hashlib

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
CORE_DIR    = os.path.join(os.path.dirname(SCRIPT_DIR), 'core')

sys.path.insert(0, CORE_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.append(os.path.join(os.path.dirname(SCRIPT_DIR), 'commonlibsf'))

from pe_layout import PELayout, attach_section, x64_runtime_function_starts
from bytesig_evidence import load_validated as _load_bytesig_evidence

COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'include')
FALLOUT_H         = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Fallout.h')
RE_INCLUDE        = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR        = os.path.join(PROJECT_DIR, 'ghidrascripts')
ADDRLIB_DIR       = os.path.join(PROJECT_DIR, 'addresslibrary', 'f4')
IDA_CORPUS_SHA256 = 'b0c327619f1a4e71fb3061c571d44a9d4de9154ab641dcc1932414dcbca639c0'
IDA_SOURCE_SHA256 = {
    # AE 1.11.191 packed Steam exe ...
    '81694b37816c8045855905a52c5fb13583c5803121fabb5024760892014e9bc6',
    # ... and its Steamless-unpacked artifact, which is what target_layouts
    # actually binds to (the corpus is keyed by RVA, identical in both).
    'e555c6c0e7aba3e9e4801c2e5e11e3a76b42ce080683b4b9c1cf074c2030b737',
    'a5c5df53bf9f99201d35261851adf28f7bce309328c2b5ffd2a66326a7f4752a',
}


_TARGET_EXE_DIRS = {
    'og': os.path.join(PROJECT_DIR, 'exes', 'f4', 'og'),
    'ng': os.path.join(PROJECT_DIR, 'exes', 'f4', 'ng'),
    'a': os.path.join(PROJECT_DIR, 'exes', 'f4', 'ae'),
    'v': os.path.join(PROJECT_DIR, 'exes', 'f4', 'vr'),
    '221': os.path.join(PROJECT_DIR, 'exes', 'f4', '221'),
}
_EXPECTED_TARGET_VERSIONS = {
    'og': (1, 10, 163, 0), 'ng': (1, 10, 984, 0),
    'a': (1, 11, 191, 0), 'v': (1, 2, 72, 0),
    '221': (1, 11, 221, 0),
}


def _source_executable(key):
    directory = _TARGET_EXE_DIRS[key]
    if not os.path.isdir(directory):
        return None
    candidates = [os.path.join(directory, n) for n in sorted(os.listdir(directory))
                  if n.lower().endswith('.exe') and 'unpacked' not in n.lower()]
    return candidates[0] if len(candidates) == 1 else None


def _target_binding(key):
    """Return ``(manifest_or_lineage, analyzed_path)`` for one exact target."""
    from binary_identity import artifact_is_fresh, inspect_pe, read_manifest
    source = _source_executable(key)
    if source is None:
        return None, None
    directory = os.path.dirname(source)
    stem = os.path.splitext(os.path.basename(source))[0]
    artifacts = [os.path.join(directory, n) for n in sorted(os.listdir(directory))
                 if 'unpacked' in n.lower() and n.lower().startswith(stem.lower())
                 and not n.lower().endswith('.identity.json')]
    fresh = [p for p in artifacts if artifact_is_fresh(source, p)]
    if len(fresh) > 1:
        raise RuntimeError('multiple fresh Steamless artifacts for {}'.format(source))
    if fresh:
        binding = read_manifest(fresh[0] + '.identity.json')
        analyzed = fresh[0]
    else:
        binding = inspect_pe(source)
        analyzed = source
    source_manifest = binding.get('source', binding)
    actual = tuple(source_manifest.get('file_version') or ())
    actual = (actual + (0, 0, 0, 0))[:4]
    if actual != _EXPECTED_TARGET_VERSIONS[key]:
        raise RuntimeError('F4 {} executable version {} != expected {}'.format(
            key, actual, _EXPECTED_TARGET_VERSIONS[key]))
    return binding, analyzed


def _load_target_layouts():
    """Load one unambiguous PE layout for each locally present target."""
    out = {}
    for key, directory in _TARGET_EXE_DIRS.items():
        if not os.path.isdir(directory):
            continue
        _, analyzed_path = _target_binding(key)
        if analyzed_path is None:
            continue
        layout = PELayout.read(analyzed_path)
        if layout.pointer_size != 8 or layout.machine != 0x8664:
            raise RuntimeError('F4 {} target is not AMD64: {}'.format(key, analyzed_path))
        out[key] = layout
    return out


def _validate_symbol_offsets(symbol, declared_kind, layouts):
    """Remove target offsets that contradict the PE's mapped section kind."""
    for key in ('og', 'ng', 'a', 'v', '221'):
        layout = layouts.get(key)
        if key not in symbol or layout is None:
            continue
        probe = {'t': declared_kind, key: symbol[key]}
        if not attach_section(probe, key, layout, declared_kind=declared_kind):
            del symbol[key]
            continue
        actual = layout.classify_rva(symbol[key])[0]
        if actual != declared_kind:
            # A function relocation in data (or a vtable/RTTI label in code)
            # is a wrong ID/address for this build, not permission to change
            # the semantic kind of the shared symbol.
            del symbol[key]
            symbol.setdefault('rejected_offsets', {})[key] = actual
            continue
        symbol.setdefault('sections', {})[key] = probe['sections'][key]
        symbol.setdefault('target_sha256', {})[key] = layout.sha256


def _resolve_desktop_offsets(symbol, id_val, addr_lib):
    """Resolve only the shared desktop ID namespace (never community VR)."""
    symbol.update(addr_lib.resolve_desktop(id_val))


# A descriptor that ends in a single-letter uppercase qualified path is an
# uninstantiated template parameter (``T``, ``K``, ``V``...).  Signatures
# containing such tokens can't point at the exact correct type and are
# dropped instead of being applied with a stale ``RE::T`` placeholder.
_UNRESOLVED_TPARAM_RE = re.compile(r'(?:^|[:>])([A-Z])(?=$|\W)')


def _has_unresolved_tparam(desc):
    if not desc:
        return False
    if 'struct:' not in desc and 'enum:' not in desc:
        return False
    return bool(_UNRESOLVED_TPARAM_RE.search(desc))


def _enrich_symbols(symbols_list, structs):
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    enriched = 0
    skipped = 0
    for sym in symbols_list:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name  = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        info = st.get('methods', {}).get(method_name)
        if info:
            ret, params, is_static = info
            # Reject signatures containing uninstantiated template parameters
            # (e.g. ``T*`` from a class template's method) — they would resolve
            # to ``void*`` in Ghidra and mask the real types in the binary.
            if _has_unresolved_tparam(ret) or any(_has_unresolved_tparam(p[1]) for p in params):
                skipped += 1
                continue
            sym['sd'] = [ret, params, 1 if is_static else 0]
            enriched += 1
    if enriched:
        print(f'Enriched {enriched} symbols with AST method signatures')
    if skipped:
        print(f'Skipped {skipped} symbols with uninstantiated template params in signature')


# Per-version output config.  OG/VR have no fallback symbol pool — their
# IDs are in disjoint namespaces, so an AE-namespace fallback would
# poison the import with mislabeled functions.
#
# Each entry is (version_key, output_filename, fallback_symbols_json_or_None,
# anchors_basename, parse_defines).
#
# `parse_defines` lets each runtime parse the CommonLib headers with its own
# preprocessor flags.  All four are currently empty because the powerof3
# CommonLibF4 fork has no per-version vfunc-insertion #ifdefs — but the seam
# exists so a VR-aware overlay can add (e.g.) `-DBGS_FALLOUT4_VR=1` and emit
# a correctly-shifted vtable layout for F4VR without affecting OG/NG/AE.
F4_TARGETS = (
    # OG/NG inherit the IDA fallback pool: meh321's ID namespace is shared
    # across OG/NG/AE/221, so IDA entries cross-resolve via their 'ai' ID
    # (see the n_ng_resolved/n_og_resolved loop in main).  VR keeps '[]'
    # -- its community ID namespace is disjoint, nothing would resolve.
    ('f4_og', 'CommonLibImport_F4_OG.py', None,  'og.csv', []),
    ('f4_ng', 'CommonLibImport_F4_NG.py', None,  'ng.csv', []),
    ('f4_ae', 'CommonLibImport_F4_AE.py', None,  'ae.csv', []),
    ('f4_vr', 'CommonLibImport_F4_VR.py', '[]',  'vr.csv', []),
    # 1.11.221 uses meh321's version-1-11-221-0.bin (same ID namespace as
    # AE/NG).  Direct address-library resolution covers every CommonLibF4
    # symbol; AE->221 byte-sig porting (run_bytesig_port.py) still fills
    # in IDA-name extras whose source pool is AE-only.
    ('f4_221', 'CommonLibImport_F4_221.py', '[]',  '221.csv', []),
)


def _allow_vtable_emission(version, anchor_path, shift_map_path):
    """Return whether this runtime has sufficient binary-layout proof.

    Mirrors the Skyrim policy (commonlibsse/vtable_policy.py): CommonLibF4's
    headers are the canonical layout for the OG (1.10.163) runtime, so OG
    vtables come straight from the clang AST and are smoke-tested against the
    hand anchors before emission.  The NG/VR shift JSON files predate
    executable/layout identity sidecars, and AE/1.11.221 have neither a
    validated map nor anchors -- emitting header-shaped overlays there is
    worse than omitting them (method slots can be confidently wrong), so
    those runtimes stay types+symbols-only until identity-bound full-layout
    evidence is added.
    """
    if version != 'f4_og':
        return False, ('no exact identity-bound, coverage-valid full vtable '
                       'layout/map is shipped for {}'.format(version))
    if os.path.isfile(shift_map_path):
        return False, 'legacy/unbound shift map present for canonical runtime'
    if not os.path.isfile(anchor_path):
        return False, 'required canonical vtable anchors are missing'
    return True, ''


def main():
    import argparse as _argparse
    import json as _json

    ap = _argparse.ArgumentParser(description='Generate CommonLibF4 importers.')
    ap.add_argument('--only', action='append', metavar='VERSION',
                    help='generate just this runtime (og, ng, ae, vr, 221; '
                         'repeatable).  Default: every F4 runtime.')
    cli = ap.parse_args()
    selected = None
    if cli.only:
        selected = {('f4_' + v.lower().removeprefix('f4_')) for v in cli.only}
        known = {t[0] for t in F4_TARGETS}
        unknown = selected - known
        if unknown:
            ap.error('unknown runtime(s): {} (known: {})'.format(
                ', '.join(sorted(unknown)),
                ', '.join(sorted(k.removeprefix('f4_') for k in known))))

    from address_library import F4AddressLibrary, get_pe_version
    from ghidra_import_gen import (
        build_vtable_structs as _build_vtable_structs,
        inject_vtable_fields as _inject_vtable_fields,
        flatten_structs       as _flatten_structs,
        apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
        generate_script,
    )

    # --- Address library (OG / NG / AE / VR) ---
    addr_lib = F4AddressLibrary()
    addr_lib.load_all(ADDRLIB_DIR)
    print(f'Address libraries — OG: {len(addr_lib.og_db):,}, '
          f'NG: {len(addr_lib.ng_db):,}, AE: {len(addr_lib.ae_db):,}, '
          f'VR: {len(addr_lib.vr_db):,}, 221: {len(addr_lib.db_221):,}')
    target_layouts = _load_target_layouts()
    if target_layouts:
        print('PE section validation: {}'.format(', '.join(
            '{}={}'.format(k, v.sha256[:12]) for k, v in target_layouts.items())))

    # --- Relocation scan ---
    print('\n=== Collecting symbols via relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, static_methods = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    # Mark statics
    for fs in func_syms:
        if fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    # OG / NG / AE / 221 share a relocation-ID namespace.  VR explicitly
    # does not.  Never probe vr_db with one of these IDs: low integer IDs
    # collide frequently and used to place confidently wrong VR names.
    # The 'a' key stays as AE for backward compatibility with the generator.
    symbols = []
    for fs in func_syms:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sym = {'n': full_name, 't': 'func', 'sig': '', 'src': 'CommonLibF4'}
        if fs.get('id'):
            sym['id'] = fs['id']
        _resolve_desktop_offsets(sym, fs.get('id'), addr_lib)
        _validate_symbol_offsets(sym, 'func', target_layouts)
        symbols.append(sym)

    for lbl in label_syms:
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibF4'}
        if lbl.get('id'):
            sym['id'] = lbl['id']
        _resolve_desktop_offsets(sym, lbl.get('id'), addr_lib)
        _validate_symbol_offsets(sym, 'label', target_layouts)
        symbols.append(sym)

    # Do not reinterpret ``__`` as a namespace separator.  Bethesda rename
    # corpora also use it to encode template arguments, inheritance paths,
    # and literal identifiers; global replacement manufactured namespaces
    # that do not exist.  Relocation/AST sources already emit real ``::``.

    n_og = sum(1 for s in symbols if 'og' in s)
    n_ng = sum(1 for s in symbols if 'ng' in s)
    n_ae = sum(1 for s in symbols if 'a'  in s)
    n_vr = sum(1 for s in symbols if 'v'  in s)
    n_221 = sum(1 for s in symbols if '221' in s)
    print(f'\nTotal symbols: {len(symbols)} '
          f'(OG: {n_og}, NG: {n_ng}, AE: {n_ae}, VR: {n_vr}, 221: {n_221})')

    # --- Type parsing setup (per-version below) ---
    print('\n=== Parsing types (clang AST) — per version ===')
    from clang_types import collect_types, _setup_include_paths
    from anchor_verifier import verify_or_exit as _verify_anchors_or_exit
    from vtable_matcher import load_json as _load_shift_map_json
    from vtable_patcher import patch_vtable_structs as _patch_vtable_structs

    if not os.path.isfile(FALLOUT_H):
        print('ERROR: Could not find Fallout.h at', FALLOUT_H)
        sys.exit(1)

    stub_dir = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    base_parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
    # commonlib-shared provides REL/ and REX/ headers
    shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'lib', 'commonlib-shared', 'include')
    if os.path.isdir(shared_include):
        base_parse_args = ['-I' + shared_include] + base_parse_args

    # Capture types from REL/, REX/, F4SE/ as well as RE/ — they're sibling
    # namespaces under CommonLibF4 whose AST methods would otherwise be skipped.
    extra_scopes = [
        COMMONLIB_INCLUDE,                                   # F4SE/ + RE/
        os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4',
                     'lib', 'commonlib-shared', 'include'),  # REL/ + REX/
    ]

    # --- IDAImportNames_1.11.191.0.py fallback symbols (AE only) ---
    print('\n=== Loading IDAImportNames_1.11.191.0.py fallback symbols ===')
    from ida_names import load_ida_import_names as _load_ida
    f4_ida_path = os.path.join(PROJECT_DIR, 'extras', 'IDAImportNames_1.11.191.0.py')
    ae_layout_for_ida = target_layouts.get('a')
    ida_hash = None
    if os.path.isfile(f4_ida_path):
        with open(f4_ida_path, 'rb') as ida_stream:
            ida_hash = hashlib.sha256(ida_stream.read()).hexdigest()
    if (ida_hash == IDA_CORPUS_SHA256 and ae_layout_for_ida is not None and
            ae_layout_for_ida.sha256 in IDA_SOURCE_SHA256):
        ida_names = _load_ida(f4_ida_path)
    else:
        ida_names = {}
        if os.path.isfile(f4_ida_path):
            print('WARNING: IDA name corpus is unbound to the exact AE source; skipped.')
    print(f'IDA names: {len(ida_names):,} entries')

    primary_rvas = {s['a'] for s in symbols if s.get('a')}
    # Inverse AE address-library map (RVA -> ID) for back-referencing IDA-named
    # functions to a stable CommonLibF4 ID where one exists.  Built from
    # addr_lib.ae_db ({id: rva}) so a CommonLib upgrade that renumbers IDs
    # invalidates the cache automatically.
    ae_rva_to_id = {rva: id_val for id_val, rva in addr_lib.ae_db.items()}
    ida_fallback = []
    n_ng_resolved = n_og_resolved = n_221_resolved = 0
    for rva, name in ida_names.items():
        entry = {'n': name, 't': 'func', 'sig': '', 'a': rva, 'src': 'IDAImportNames'}
        ae_layout = target_layouts.get('a')
        if ae_layout is not None:
            if not attach_section(entry, 'a', ae_layout, declared_kind='func'):
                continue
            entry.setdefault('target_sha256', {})['a'] = ae_layout.sha256
        ae_id = ae_rva_to_id.get(rva)
        if ae_id is not None:
            entry['ai'] = ae_id
            # The meh321 ID namespace is shared across OG/NG/AE/221, so an
            # AE-derived ID resolves directly in the sibling DBs.  This is
            # what lets NG and OG (previously fallback='[]') inherit the
            # IDA name pool.  VR stays out: its community IDs are disjoint.
            ng = addr_lib.ng_db.get(ae_id)
            og = addr_lib.og_db.get(ae_id)
            v221 = addr_lib.db_221.get(ae_id)
            if ng:
                entry['ng'] = ng
                n_ng_resolved += 1
            if og:
                entry['og'] = og
                n_og_resolved += 1
            if v221 and '221' not in entry:
                entry['221'] = v221
                n_221_resolved += 1
        _validate_symbol_offsets(entry, entry['t'], target_layouts)
        if 'a' not in entry:
            continue
        ida_fallback.append(entry)
    not_in_primary = sum(1 for s in ida_fallback if s['a'] not in primary_rvas)
    print(f'IDA fallback symbols: {len(ida_fallback):,} loaded '
          f'({not_in_primary:,} not in primary; cross-resolved: '
          f'NG {n_ng_resolved:,}, OG {n_og_resolved:,}, 221 {n_221_resolved:,})')

    fallback_json_ae = _json.dumps(ida_fallback, separators=(',', ':'))

    # --- F4 1.11.221 community-generated public-symbol corpus ---
    print('\n=== Loading Fallout4 1.11.221 community PDB publics ===')
    from pdb_publics_f4_221 import load_publics as _load_f4_221_publics
    layout_221 = target_layouts.get('221')
    f4_221_publics = (_load_f4_221_publics(layout_221.path, layout_221.sha256)
                      if layout_221 is not None else [])
    if layout_221 is not None:
        classified_publics = []
        for entry in f4_221_publics:
            if not attach_section(entry, '221', layout_221,
                                  declared_kind=entry['t']):
                continue
            entry.setdefault('target_sha256', {})['221'] = layout_221.sha256
            classified_publics.append(entry)
        f4_221_publics = classified_publics
    primary_221_rvas = {s['221'] for s in symbols if s.get('221')}
    f4_221_fallback = [s for s in f4_221_publics
                       if s['221'] not in primary_221_rvas]
    n_221_func  = sum(1 for s in f4_221_fallback if s['t'] == 'func')
    n_221_label = sum(1 for s in f4_221_fallback if s['t'] == 'label')
    print(f'F4 1.11.221 PDB publics: {len(f4_221_publics):,} loaded, '
          f'{len(f4_221_fallback):,} new ({n_221_func:,} funcs, '
          f'{n_221_label:,} labels)')
    # Merge IDA names that cross-resolved to a 221 RVA (PDB publics win on
    # collision -- they're authoritative for this build).
    used_221 = {s['221'] for s in f4_221_fallback}
    ida_into_221 = [e for e in ida_fallback
                    if e.get('221') and e['221'] not in used_221]
    print(f'  + IDA names cross-resolved into 221 pool: {len(ida_into_221):,}')
    fallback_json_221 = _json.dumps(f4_221_fallback + ida_into_221,
                                    separators=(',', ':'))
    fallback_json_by_ver = {'f4_221': fallback_json_221}

    # --- Per-version: parse → build vtable structs → verify anchors → generate ---
    # One AST parse per target so a VR-aware overlay can change the layout for
    # F4VR without affecting OG/NG/AE.  Today all four use empty defines so
    # the parses produce identical results; the seam is here to make adding
    # version-specific layout fixes a one-line change in F4_TARGETS.
    anchors_dir = os.path.join(SCRIPT_DIR, 'anchors')
    print('\nGenerating Ghidra scripts...')
    # Per-version RVA key used both by the generated script's version_key
    # map and by the persisted-bytesig merge below.
    _ver_rva_key = {'f4_og': 'og', 'f4_ng': 'ng', 'f4_ae': 'a',
                    'f4_vr': 'v', 'f4_221': '221'}

    def _merge_bytesig_csv(fb_json, ver):
        """Merge refs/bytesig_ported_<short>.csv into a fallback pool.

        Written by bytesig_port_combined.py / run_bytesig_port.py; makes
        ported names survive regeneration instead of living only inside
        the previously-generated script.
        """
        short = ver.replace('f4_', '')
        csv_path = os.path.join(SCRIPT_DIR, 'refs',
                                'bytesig_ported_{}.csv'.format(short))
        if not os.path.isfile(csv_path):
            return fb_json
        rva_key = _ver_rva_key[ver]
        layout = target_layouts.get(rva_key)
        if layout is None:
            print('  rejecting persisted bytesig evidence without exact target PE: {}'.format(
                os.path.basename(csv_path)))
            return fb_json
        target_manifest = {
            'sha256': layout.sha256,
            'path': layout.path,
            'machine': layout.machine,
            'pointer_size': layout.pointer_size,
            'image_base': layout.image_base,
            'image_size': layout.image_size,
        }
        try:
            evidence_rows, _identity = _load_bytesig_evidence(
                csv_path, target_manifest)
            target_starts = x64_runtime_function_starts(layout.path)
        except FileNotFoundError:
            print('  skipping legacy pre-identity bytesig evidence {} '
                  '(no sidecar; the byte-sig port step rebuilds it in the '
                  'bound format)'.format(os.path.basename(csv_path)))
            return fb_json
        except (OSError, ValueError) as exc:
            print('  rejecting stale/unbound persisted bytesig evidence {}: {}'.format(
                os.path.basename(csv_path), exc))
            return fb_json
        existing = _json.loads(fb_json)
        used = {s.get(rva_key) for s in existing if s.get(rva_key)}
        n_added = 0
        seen_pairs = set()
        for row in evidence_rows:
            rva = row['target_rva']
            pair = (row['name'], rva)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if rva not in target_starts:
                continue
            probe = {'t': 'func', rva_key: rva}
            if (not attach_section(probe, rva_key, layout,
                                   declared_kind='func') or
                    probe['t'] != 'func'):
                continue
            if rva in used:
                continue
            used.add(rva)
            entry = {'n': row['name'], 't': 'func', 'sig': '',
                     rva_key: rva,
                     'src': row.get('source_tag') or 'bytesig-port',
                     'sections': probe.get('sections', {}),
                     'target_sha256': {rva_key: layout.sha256}}
            existing.append(entry)
            n_added += 1
        if n_added:
            print('  merged {} persisted bytesig names from {}'.format(
                n_added, os.path.basename(csv_path)))
        return _json.dumps(existing, separators=(',', ':'))

    for ver, fname, fb_json, anchors_name, parse_defines in F4_TARGETS:
        if selected is not None and ver not in selected:
            continue
        print(f'\n--- {ver} ---')
        rva_key = _ver_rva_key[ver]
        target_binding, _target_artifact = _target_binding(rva_key)
        if target_binding is None:
            print('  SKIP: no single exact {} executable; refusing to emit an unbound importer'.format(ver))
            continue
        if ver in fallback_json_by_ver:
            fb_json = fallback_json_by_ver[ver]
        elif fb_json is None:
            fb_json = fallback_json_ae
        fb_json = _merge_bytesig_csv(fb_json, ver)
        parse_args = list(base_parse_args) + list(parse_defines)
        enums, structs, template_source = collect_types(
            FALLOUT_H, RE_INCLUDE, parse_args,
            verbose=True, category_prefix='/CommonLibF4',
            extra_scope_paths=extra_scopes,
            # Every accepted F4 target is verified as AMD64 above.  Keep the
            # Clang ABI explicit rather than re-inferring it from macro flags.
            target_arch='x64')
        print(f'  found {len(enums)} enums, {len(structs)} structs/classes')

        _enrich_symbols(symbols, structs)
        # Serialize AFTER enrichment: _enrich_symbols mutates 'sd'
        # (structured signature) fields onto the symbol dicts.  A
        # pre-loop dump silently dropped every signature from the
        # generated scripts ("Signatures applied: 0" at apply time).
        symbols_json = _json.dumps(symbols, separators=(',', ':'))

        anchor_path = os.path.join(anchors_dir, anchors_name)
        shift_map_path = os.path.join(
            SCRIPT_DIR, 'refs', 'shift_{}.json'.format(ver))
        emit_vtables, vtable_reason = _allow_vtable_emission(
            ver, anchor_path, shift_map_path)
        vtable_structs = _build_vtable_structs(structs) if emit_vtables else {}
        if emit_vtables:
            _inject_vtable_fields(structs, vtable_structs)
        else:
            print('  VTABLES DISABLED: {}'.format(vtable_reason))
        _flatten_structs(structs)
        _apply_secondary_vtable_typing(structs)

        if emit_vtables:
            # No legacy map is accepted on the correctness path (mirrors the
            # Skyrim emitter); a validated identity-bound map schema would go
            # through its own loader, not this branch.
            shift_map = _load_shift_map_json(shift_map_path)
            if shift_map:
                raise RuntimeError('unvalidated shift map reached vtable emitter')

            # Missing anchors must never be the anchor verifier's historical
            # soft-success path in a correctness build.
            if not os.path.isfile(anchor_path):
                raise RuntimeError(
                    'required vtable anchors are missing: {}'.format(anchor_path))
            _verify_anchors_or_exit(ver, vtable_structs, anchor_path)

        output_path = os.path.join(OUTPUT_DIR, fname)
        n_enums, n_structs = generate_script(
            enums, structs, vtable_structs, output_path,
            version=ver,
            symbols_json=symbols_json,
            fallback_symbols_json=fb_json,
            template_source=template_source,
            project_name='CommonLibF4',
            target_manifest=target_binding,
        )
        print(f'  {fname}: {n_enums} enums, {n_structs} structs')


if __name__ == '__main__':
    main()
