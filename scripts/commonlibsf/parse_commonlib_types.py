#!/usr/bin/env python3
"""
Parse CommonLibSF headers and generate a Ghidra import script for Starfield.

Single-version pipeline (no SE/AE-style branching).  Symbol sources, in
priority order:

  1. ``RE/IDs.h``         function IDs grouped by ``namespace RE::ID::<Class>``
  2. ``RE/IDs_RTTI.h``    flat ``RTTI_*`` labels
  3. ``RE/IDs_NiRTTI.h``  flat ``NiRTTI_*`` labels
  4. ``RE/IDs_VTABLE.h``  ``std::array<REL::ID, N> VTABLE_*`` slots
  5. clang AST + record-layouts on ``RE/Starfield.h`` for type definitions
     (best-effort -- if the libclang parse fails, fall through to a
     label/symbol-only script)

Output: ``ghidrascripts/CommonLibImport_SF.py``.
"""

import json as _json
import hashlib
import os
import re
import sys

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSF', 'include')
STARFIELD_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Starfield.h')
RE_INCLUDE  = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR  = os.path.join(PROJECT_DIR, 'ghidrascripts')
EXES_DIR    = os.path.join(PROJECT_DIR, 'exes', 'starfield', 'sf')

sys.path.insert(0, os.path.join(SCRIPT_DIR))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))

from address_library import AddressLibrary
from ids_parser import collect_all as collect_id_symbols
from pe_layout import PELayout, attach_section
from pe_version import get_pe_version


def _detect_sf_version():
    """Return the PE version tuple of the first Starfield.exe in EXES_DIR.

    Returns None when no exe is present or when the version can't be parsed.
    Steam-DRM-packed binaries are handled by pe_version's FileVersion-string
    fallback (VS_FIXEDFILEINFO is scrambled by SteamStub).
    """
    if not os.path.isdir(EXES_DIR):
        return None
    for fname in sorted(os.listdir(EXES_DIR)):
        if not fname.lower().endswith('.exe'):
            continue
        if 'unpacked' in fname.lower():
            continue
        v = get_pe_version(os.path.join(EXES_DIR, fname))
        if v:
            return v
    return None


def _detect_sf_target():
    """Return ``(path, version, PELayout)`` for the one supported target.

    Multiple regular executables are ambiguous and therefore fatal.  The old
    first-file-wins behavior could pair one PE version with another binary's
    address library merely because directory ordering changed.
    """
    candidates = []
    if os.path.isdir(EXES_DIR):
        for fname in sorted(os.listdir(EXES_DIR)):
            if not fname.lower().endswith('.exe') or 'unpacked' in fname.lower():
                continue
            path = os.path.join(EXES_DIR, fname)
            version = get_pe_version(path)
            if version:
                candidates.append((path, version))
    if not candidates:
        return None
    if len(candidates) != 1:
        raise RuntimeError(
            'Expected exactly one packed Starfield target in {}, found: {}'.format(
                EXES_DIR, ', '.join(os.path.basename(p) for p, _ in candidates)))
    path, version = candidates[0]
    _binding, analyzed_path = _target_binding(path)
    layout = PELayout.read(analyzed_path)
    if layout.pointer_size != 8 or layout.machine != 0x8664:
        raise RuntimeError('Starfield target is not an AMD64 PE: {}'.format(path))
    return path, version, layout


def _target_binding(source_path):
    """Return ``(lineage/manifest, analyzed path)`` prepared by run.py."""
    from binary_identity import artifact_is_fresh, inspect_pe, read_manifest
    directory = os.path.dirname(source_path)
    stem = os.path.splitext(os.path.basename(source_path))[0]
    for name in sorted(os.listdir(directory)):
        artifact = os.path.join(directory, name)
        if (artifact == source_path or 'unpacked' not in name.lower() or
                not name.lower().startswith(stem.lower()) or
                name.lower().endswith('.identity.json')):
            continue
        if artifact_is_fresh(source_path, artifact):
            return read_manifest(artifact + '.identity.json'), artifact
    return inspect_pe(source_path), source_path


def _make_symbols(funcs, labels, layout):
    """Convert ids_parser output into the SYMBOLS array used by the import script.

    ``sf_off`` carries the offset; the script-side ``version_key`` map
    looks symbols up by the ``'sf'`` key (see scripts/core/ghidra_import_gen.py).
    """
    symbols = []
    seen = set()

    for f in funcs:
        full_name = '{}::{}'.format(f['class_'], f['name']) if f.get('class_') else f['name']
        key = (full_name, 'func', f['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbol = {
            'n':   full_name,
            't':   'func',
            'sig': '',
            'sf':  f['sf_off'],
            'src': 'CommonLibSF',
        }
        if not attach_section(symbol, 'sf', layout, declared_kind='func'):
            continue
        symbols.append(symbol)

    # CommonLib's std::array order is not primary-first.  Assign the
    # unsuffixed VTABLE_<Class> label only to the entry whose MSVC Complete
    # Object Locator says subobject offset zero; use stable offset identities
    # for secondary tables.  Failed COL validation drops the assertion.
    classified_labels = []
    identity_counts = {}
    for original in labels:
        l = dict(original)
        class_name = l.get('vtable_class')
        if class_name:
            try:
                subobject = layout.msvc_vtable_subobject_offset(l['sf_off'])
            except (OSError, ValueError):
                continue
            identity = (class_name, subobject)
            identity_counts[identity] = identity_counts.get(identity, 0) + 1
            l['_physical_vtable_identity'] = identity
            l['vtable_subobject_offset'] = subobject
        classified_labels.append(l)

    unambiguous_labels = []
    for l in classified_labels:
        identity = l.pop('_physical_vtable_identity', None)
        if identity is not None:
            # A second COL for the same semantic class/subobject is not a new
            # C++ class.  Ordinal suffixing used to launder that ambiguity as
            # VTABLE_Class__primary_2 / __sub_20_2.  Omit both assertions
            # unless the physical identity is unique.
            if identity_counts.get(identity) != 1:
                continue
            class_name, subobject = identity
            suffix = '' if subobject == 0 else '__sub_{:X}'.format(subobject)
            l['n'] = 'VTABLE_{}{}'.format(class_name, suffix)
            l['name'] = l['n']
        unambiguous_labels.append(l)
    classified_labels = unambiguous_labels

    for l in classified_labels:
        key = (l['name'], 'label', l['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbol = {
            'n':   l['name'],
            't':   'label',
            'sig': '',
            'sf':  l['sf_off'],
            'src': 'CommonLibSF',
        }
        if not attach_section(symbol, 'sf', layout, declared_kind='label'):
            continue
        symbols.append(symbol)

    return symbols


SF_IMAGE_BASE = 0x140000000
# The offline naming corpus in refs/ was produced against this binary.
CORPUS_SOURCE_VERSION = (1, 16, 236, 0)
CORPUS_SOURCE_SHA256 = '1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351'
CORPUS_ARTIFACT_SHA256 = 'fb4c781ffcd5ecf58b5750c04289c1a125326d429693516df58a31e50db8774f'


def _build_fallback_symbols(addr_lib, sf_version, layout, verbose=True):
    """Assemble FALLBACK_SYMBOLS from the two on-disk name pools:

      1. ``extern/AddressLibraryDatabase/starfield.rename`` -- meh321's
         curated ID->name database (~974 entries).  ID-keyed, so it
         resolves against ANY versionlib: fully version-portable.
      2. ``refs/sf116_named_from_combined_final.csv`` -- the offline
         enrichment corpus (~64k ``0xVA,name`` rows: byte-sig + BSim +
         RTTI-walk names harvested from the user's Combined project).
         VA-keyed against 1.16.236; when the detected exe is a different
         patch the RVAs are remapped 236-RVA -> ID -> detected-RVA via
         the two versionlibs.

    Fallback symbols only ever rename FUN_/sub_ placeholders at apply
    time, so lower-confidence corpus names are safe to ship.
    """
    out = []
    by_rva = set()

    # --- 1. starfield.rename (curated, ID-keyed -- takes priority) ---
    rename_path = os.path.join(PROJECT_DIR, 'extern',
                               'AddressLibraryDatabase', 'starfield.rename')
    n_rename = 0
    if os.path.isfile(rename_path):
        with open(rename_path, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                parts = ln.split(None, 1)
                if len(parts) != 2 or not parts[0].isdigit():
                    continue  # version header / malformed
                rva = addr_lib.sf_db.get(int(parts[0]))
                if not rva or rva in by_rva:
                    continue
                name = parts[1].strip()
                # meh321 wildcard convention: trailing _* means "append
                # address" -- drop it; Ghidra names must be unique anyway
                # and the apply path suffixes on collision.
                if name.endswith('_*'):
                    name = name[:-2]
                if not name:
                    continue
                entry = {'n': name, 't': 'func', 'sig': '',
                         'sf': rva, 'src': 'starfield.rename',
                         'target_sha256': layout.sha256}
                if not attach_section(entry, 'sf', layout, declared_kind='func'):
                    continue
                out.append(entry)
                by_rva.add(rva)
                n_rename += 1
    if verbose:
        print('Fallback pool 1 (starfield.rename): {} resolved'.format(n_rename))

    # --- 2. offline corpus (VA-keyed at 1.16.236) ---
    corpus_path = os.path.join(SCRIPT_DIR, 'refs',
                               'sf116_named_from_combined_final.csv')
    n_corpus = n_remap_miss = 0
    corpus_hash = None
    if os.path.isfile(corpus_path):
        digest = hashlib.sha256()
        with open(corpus_path, 'rb') as corpus_stream:
            for chunk in iter(lambda: corpus_stream.read(1024 * 1024), b''):
                digest.update(chunk)
        corpus_hash = digest.hexdigest()
    if corpus_hash == CORPUS_ARTIFACT_SHA256:
        det = tuple(sf_version) + (0,) * (4 - len(sf_version))
        same_build = (det[:4] == CORPUS_SOURCE_VERSION and
                      layout.sha256.lower() == CORPUS_SOURCE_SHA256)
        rev_236 = None
        det_db = None
        if not same_build:
            # Remap chain: corpus 236-RVA -> versionlib ID -> detected RVA.
            try:
                src_lib = AddressLibrary()
                src_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'),
                                 pe_version=CORPUS_SOURCE_VERSION)
                rev_236 = {}
                for id_value, source_rva in src_lib.sf_db.items():
                    rev_236.setdefault(source_rva, set()).add(id_value)
                det_db = addr_lib.sf_db
                if verbose:
                    print('Corpus remap active: 1.16.236 -> {} via versionlib IDs'
                          .format('.'.join(str(x) for x in det[:4])))
            except FileNotFoundError:
                print('WARNING: no versionlib for 1.16.236 -- corpus names '
                      'skipped (cannot remap to detected build).')
                rev_236 = {}
        with open(corpus_path, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('target_va'):
                    continue
                parts = ln.split(',', 1)
                if len(parts) != 2:
                    continue
                try:
                    va = int(parts[0], 16)
                except ValueError:
                    continue
                rva236 = va - SF_IMAGE_BASE
                if rva236 <= 0:
                    continue
                if same_build:
                    rva = rva236
                else:
                    ids = rev_236.get(rva236, set()) if rev_236 else set()
                    candidates = {det_db[id_value] for id_value in ids
                                  if det_db and id_value in det_db}
                    rva = next(iter(candidates)) if len(candidates) == 1 else None
                    if rva is None:
                        n_remap_miss += 1
                        continue
                if rva in by_rva:
                    continue
                name = parts[1].strip()
                if not name:
                    continue
                entry = {
                    'n': name, 't': 'func', 'sig': '', 'sf': rva,
                    'src': 'sf116_corpus',
                    'source_version': '.'.join(str(x) for x in CORPUS_SOURCE_VERSION),
                    'source_sha256': CORPUS_SOURCE_SHA256,
                    'target_sha256': layout.sha256,
                }
                # This corpus claims to contain functions harvested from a
                # Ghidra project.  Rows landing outside executable memory are
                # contaminated evidence, not data labels; discard them.
                if not attach_section(entry, 'sf', layout, declared_kind='func'):
                    continue
                if entry['t'] != 'func':
                    continue
                out.append(entry)
                by_rva.add(rva)
                n_corpus += 1
    elif corpus_hash is not None:
        print('WARNING: SF116 naming corpus hash mismatch; refusing unbound evidence.')
    if verbose:
        print('Fallback pool 2 (sf116 corpus): {} loaded{}'.format(
            n_corpus,
            ', {} dropped (no ID remap)'.format(n_remap_miss) if n_remap_miss else ''))
        print('Total fallback symbols: {}'.format(len(out)))
    return out


def _try_clang_types(verbose=True):
    """Best-effort clang AST parse of CommonLibSF headers.

    Wrapped in a broad try/except: CommonLibSF uses C++23 features and may
    need additional system include stubs.  When the parse fails we return
    empty type containers so the rest of the pipeline still produces a
    usable labels-only script.
    """
    try:
        from clang_types import collect_types, _setup_include_paths
        from ghidra_import_gen import (
            build_vtable_structs,
            inject_vtable_fields,
            flatten_structs,
            apply_secondary_vtable_typing,
        )

        stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
        parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
        # libxse/commonlibsf split out the REL/ and REX/ headers into a
        # nested commonlib-shared submodule (same shape as F4 already uses).
        # The old SR-E/Starfield-Reverse-Engineering tree had them inline
        # under include/, so adding -I unconditionally is harmless if the
        # nested submodule isn't present (clang ignores missing dirs).
        shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSF',
                                      'lib', 'commonlib-shared', 'include')
        if os.path.isdir(shared_include):
            parse_args = ['-I' + shared_include] + parse_args
        # CommonLibSF uses C++23 features.  -std=c++23 is widely supported by
        # recent clang; older clang falls back to c++latest.
        parse_args = ['-std=c++23'] + parse_args

        if verbose:
            print('Parsing CommonLibSF headers via clang AST...')
        enums, structs, template_source = collect_types(
            STARFIELD_H, RE_INCLUDE, parse_args,
            verbose=verbose,
            root_namespace='RE',
            category_prefix='/CommonLibSF',
        )

        if verbose:
            print('Building vtable structs...')
        vtable_structs = build_vtable_structs(structs)
        inject_vtable_fields(structs, vtable_structs)
        flatten_structs(structs)
        apply_secondary_vtable_typing(structs)

        if verbose:
            print('  enums:    {}'.format(len(enums)))
            print('  structs:  {}'.format(len(structs)))
            print('  vtables:  {}'.format(len(vtable_structs)))
        return enums, structs, vtable_structs, template_source
    except (Exception, SystemExit) as e:
        # clang_types.collect_types() calls sys.exit() when clang.exe isn't
        # on PATH, so catch SystemExit too.
        print('WARNING: CommonLibSF AST parse failed ({}: {})'.format(type(e).__name__, e))
        print('         Falling back to labels-only output (no struct/enum types).')
        return {}, {}, {}, ''


def main():
    print('=== CommonLibSF -> Ghidra import script ===')
    print('PROJECT_DIR        =', PROJECT_DIR)
    print('COMMONLIB_INCLUDE  =', COMMONLIB_INCLUDE)
    print('STARFIELD_H        =', STARFIELD_H)
    print('OUTPUT_DIR         =', OUTPUT_DIR)
    print()

    if not os.path.isfile(STARFIELD_H):
        print('ERROR: {} not found.  Run `git submodule update --init` first.'.format(
            STARFIELD_H))
        sys.exit(1)

    # 1. Address library -- match the bin to the installed Starfield.exe.
    target = _detect_sf_target()
    if target is None:
        print('ERROR: Could not detect Starfield.exe version in {}.  '
              'Drop a Starfield.exe in that directory.'.format(EXES_DIR))
        sys.exit(1)
    sf_exe, sf_version, pe_layout = target
    print('Detected Starfield.exe version: {}'.format(
        '.'.join(str(x) for x in sf_version)))
    print('Target SHA-256: {}'.format(pe_layout.sha256))

    addr_lib = AddressLibrary()
    try:
        addr_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'),
                          pe_version=sf_version,
                          expected_sha256=pe_layout.sha256)
    except FileNotFoundError as e:
        print('ERROR: {}'.format(e))
        sys.exit(1)
    if not addr_lib.sf_db:
        print('ERROR: Starfield address library loaded zero entries.')
        sys.exit(1)
    print('Address library: versionlib-{}.bin ({:,} entries)'.format(
        '-'.join(str(x) for x in (addr_lib.sf_version or sf_version)),
        len(addr_lib.sf_db)))

    # 2. Manifest symbol scan
    func_syms, label_syms = collect_id_symbols(RE_INCLUDE, addr_lib, verbose=True)

    # 3. Type extraction via libclang (best-effort)
    enums, structs, vtable_structs, template_source = _try_clang_types(verbose=True)

    # 4. Assemble SYMBOLS array
    symbols      = _make_symbols(func_syms, label_syms, pe_layout)
    symbols_json = _json.dumps(symbols, separators=(',', ':'))

    n_func  = sum(1 for s in symbols if s['t'] == 'func')
    n_label = sum(1 for s in symbols if s['t'] == 'label')
    print('\nSymbols: {} total ({} funcs, {} labels)'.format(
        len(symbols), n_func, n_label))

    # 5. Verify hand-checked vtable slot anchors before emitting.
    # Single-version pipeline today, but the seam exists so future SF
    # patch revisions can ship anchor CSVs that catch silent drift.
    # Skip when vtable_structs is empty (labels-only run without clang):
    # the verifier expects parsed vtables and would fail with "class not
    # found" on every anchor row.  Anchor drift is meaningless when no
    # vtables were inferred in the first place.
    if vtable_structs:
        from anchor_verifier import verify_or_exit as _verify_anchors_or_exit
        from sf_shift_manifest import (
            ANCHOR_VERSION as _SHIFT_ANCHOR_VERSION,
            load_validated as _load_validated_shift_map,
            map_path as _shift_map_path,
            version_token as _version_token,
        )

        # Apply per-version shift map (if one exists) to remap onto the
        # actual binary layout.  Single-version pipeline today but symmetric
        # with the SSE/F4 builds; future SF patches can drop in a shift map
        # without touching this code.
        normalized_version = tuple(sf_version) + (0,) * (4 - len(sf_version))
        normalized_version = normalized_version[:4]
        if normalized_version != _SHIFT_ANCHOR_VERSION:
            refs_dir = os.path.join(SCRIPT_DIR, 'refs')
            shift_map_path = _shift_map_path(refs_dir, normalized_version)
            ref_layout = os.path.join(
                refs_dir, 'sf_{}_vtables.csv.gz'.format(
                    _version_token(_SHIFT_ANCHOR_VERSION)))
            target_layout = os.path.join(
                refs_dir, 'sf_{}_vtables.csv.gz'.format(
                    _version_token(normalized_version)))
            if not os.path.isfile(shift_map_path):
                raise RuntimeError(
                    'No target-bound SF vtable shift map for {}.  Run '
                    '`python scripts/commonlibsf/sf_shift_check.py --preflight` '
                    'after importing/analyzing the target without applying '
                    'CommonLibSF names.'.format('.'.join(map(str, normalized_version))))
            shift_map = _load_validated_shift_map(
                shift_map_path, normalized_version, pe_layout.sha256,
                reference_layout=ref_layout, target_layout=target_layout,
                reference_versionlib=os.path.join(
                    PROJECT_DIR, 'addresslibrary', 'starfield',
                    'versionlib-{}.bin'.format(
                        _version_token(_SHIFT_ANCHOR_VERSION))),
                target_versionlib=os.path.join(
                    PROJECT_DIR, 'addresslibrary', 'starfield',
                    'versionlib-{}.bin'.format(
                        _version_token(normalized_version))))
            print('Applying validated SF vtable shift map: {}'.format(shift_map_path))
            from sf_vtable_policy import strict_patch_vtable_structs
            strict_patch_vtable_structs(
                vtable_structs, shift_map,
                'sf_' + _version_token(normalized_version).replace('-', '_'))
            anchors_path = os.path.join(
                SCRIPT_DIR, 'anchors', 'sf_{}.csv'.format(
                    _version_token(normalized_version)))
        else:
            print('SF target is the CommonLibSF anchor build; no shift map applies.')
            anchors_path = os.path.join(SCRIPT_DIR, 'anchors', 'sf.csv')

        _verify_anchors_or_exit(
            'sf_' + _version_token(normalized_version),
            vtable_structs, anchors_path)
    else:
        print('Skipping vtable anchor verification: no vtable_structs '
              '(labels-only run -- needs clang.exe for AST-based vtable '
              'inference to produce anchorable structs).')

    # 6. Fallback symbols: starfield.rename + the offline naming corpus.
    # Primary CommonLibSF symbols win on RVA collision at apply time
    # (fallbacks only rename FUN_/sub_ placeholders).
    print()
    fallback_symbols = _build_fallback_symbols(addr_lib, sf_version, pe_layout)
    primary_rvas = {s['sf'] for s in symbols if s.get('sf')}
    fallback_symbols = [s for s in fallback_symbols
                        if s['sf'] not in primary_rvas]
    print('Fallback symbols after primary-RVA dedup: {}'.format(
        len(fallback_symbols)))
    fallback_symbols_json = _json.dumps(fallback_symbols, separators=(',', ':'))

    # 7. Generate the Ghidra Jython import script
    from ghidra_import_gen import generate_script
    output_path = os.path.join(OUTPUT_DIR, 'CommonLibImport_SF.py')
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs,
        output_path,
        version='sf',
        symbols_json=symbols_json,
        fallback_symbols_json=fallback_symbols_json,
        template_source=template_source,
        project_name='CommonLibSF',
        target_manifest=_target_binding(sf_exe)[0],
    )
    print('\nWrote {}'.format(output_path))
    print('  {} enums, {} structs, {} vtable structs, {} symbols, {} fallback'.format(
        n_enums, n_structs, len(vtable_structs), len(symbols),
        len(fallback_symbols)))


if __name__ == '__main__':
    main()
