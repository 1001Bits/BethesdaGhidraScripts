#!/usr/bin/env python3
"""
Parse CommonLibSSE headers and generate Ghidra import scripts that create
struct/class/enum type definitions with function symbols and relocations.

Run with: python parse_commonlib_types.py

Pipeline:
  Types:        clang_types.py  (clang.exe AST dump + record layouts)
  Templates:    template_types.py  (template instantiation name discovery)
  Relocations:  reloc_parser.py  (regex-based, single-pass SE+AE from raw source)
  PDB symbols:  pdb_symbols.py  (identity-bound SkyrimSE.pdb public names via
                the repository's strict MSF 7 reader)
  AE names:     skyrimae.rename  (AE address ID → name mapping, fallback)
  Script gen:   ghidra_import_gen.py  (Ghidra Jython script emitter)

Generates importers for Skyrim SE, AE 1.6.640, AE 1.6.1170, AE 1.7.104, and VR.
"""

import os
import sys
import re
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))

from address_library import AddressLibrary, get_pe_version, unique_reverse_ids
from pdb_symbols import (
    load_pdb_names as load_se_pdb_names,
    unique_public_merge_target,
)
from ghidra_import_gen import (
    build_vtable_structs as _build_vtable_structs,
    inject_vtable_fields as _inject_vtable_fields,
    flatten_structs as _flatten_structs,
    apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
    generate_script,
)
from anchor_verifier import verify_or_exit as _verify_anchors_or_exit
from vtable_matcher import load_json as _load_shift_map_json
from vtable_patcher import patch_vtable_structs as _patch_vtable_structs

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
sys.path.append(os.path.join(os.path.dirname(SCRIPT_DIR), 'commonlibsf'))
from pe_layout import PELayout, attach_section, x64_runtime_function_starts
from bytesig_evidence import load_validated as _load_bytesig_evidence
from skyrim17_layouts import apply_ae17_layouts as _apply_ae17_layouts
from vtable_policy import allow_vtable_emission as _allow_vtable_emission
from vtable_label_check import validate_vtable_labels_for_layouts

COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSSE', 'include')
SKYRIM_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Skyrim.h')
RE_INCLUDE = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'ghidrascripts')

_TARGET_DIRS = {'se': 'se', 'ae': 'ae', '16640': '16640', '17104': '17104',
                'svr': 'vr'}
_TARGET_KEYS = {'se': 's', 'ae': 'a', '16640': '16640', '17104': '17104',
                'svr': 'v'}
# Address-library ID field per target key: SE 1.5.97 and VR 1.4.15 share the
# SE namespace, every AE runtime the AE one.  Never cross them.
RUNTIME_ID_FIELDS = {'s': ('si',), 'v': ('si',),
                     'a': ('ai',), '16640': ('ai',), '17104': ('ai',)}
_EXPECTED_VERSIONS = {
    'se': (1, 5, 97, 0), 'ae': (1, 6, 1170, 0),
    '16640': (1, 6, 640, 0),
    '17104': (1, 7, 104, 0),
    'svr': (1, 4, 15, 0),
}
SE_PDB_SHA256 = 'c7c168e9d7bbe481418bbca6749064687ede714f3b3e2468081f10ac59bbf252'
SE_PDB_DERIVED_HASHES = {
    'skyrimse_pdb_func_sigs.json': '1a03e991b7683b0a759826a831cdf2681d1a17efd161b419f60fb82ff16e5cff',
    'skyrimse_pdb_types.json': 'cbd938907fe95524ce420a38736afb849ffa4a7db441a4f69e332d2653b4542e',
    'skyrimse_pdb_enums.json': 'a38155d72fecade9e6272dfa6e4100a862e9c63f0ee71ca34c7157b52f0f77d9',
}


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _trusted_pdb_derived(path, pdb_identity_valid):
    expected = SE_PDB_DERIVED_HASHES.get(os.path.basename(path))
    return bool(pdb_identity_valid and expected and os.path.isfile(path) and
                _file_sha256(path) == expected)


def _target_binding(version):
    from binary_identity import (inspect_pe, load_fresh_lineage,
                                 prove_section_equivalence)
    directory = os.path.join(PROJECT_DIR, 'exes', 'skyrim',
                             _TARGET_DIRS[version])
    if not os.path.isdir(directory):
        return None, None
    sources = [os.path.join(directory, n) for n in sorted(os.listdir(directory))
               if n.lower().endswith('.exe') and 'unpacked' not in n.lower()]
    if len(sources) != 1:
        return None, None
    source = sources[0]
    stem = os.path.splitext(os.path.basename(source))[0]
    artifacts = [os.path.join(directory, n) for n in sorted(os.listdir(directory))
                 if 'unpacked' in n.lower() and n.lower().startswith(stem.lower())
                 and not n.lower().endswith('.identity.json')]
    # load_fresh_lineage recomputes the advisory function_starts from the
    # proven files: an old sidecar's start set predates the extractor fixes.
    fresh = [(p, lineage) for p, lineage in
             ((p, load_fresh_lineage(source, p)) for p in artifacts)
             if lineage is not None]
    if len(fresh) > 1:
        raise RuntimeError('multiple fresh Steamless artifacts for {}'.format(source))
    if fresh:
        analyzed, binding = fresh[0]
        # A Program imported from the packed source is the same image when every
        # section is byte-identical; record the proof so the importer accepts it.
        proof = prove_section_equivalence(source, analyzed)
        if proof is not None:
            binding['equivalence'] = proof
            print('  {}: source and Steamless artifact have byte-identical '
                  'sections ({} sections, {} bytes); source import accepted'.format(
                      version, proof['sections'], proof['section_bytes']))
    else:
        binding = inspect_pe(source)
        analyzed = source
    source_manifest = binding.get('source', binding)
    actual = tuple(source_manifest.get('file_version') or ())
    actual = (actual + (0, 0, 0, 0))[:4]
    if actual != _EXPECTED_VERSIONS[version]:
        raise RuntimeError('Skyrim {} executable version {} != expected {}'.format(
            version, actual, _EXPECTED_VERSIONS[version]))
    return binding, analyzed


def _load_target_layouts():
    out = {}
    for version, key in _TARGET_KEYS.items():
        _, analyzed = _target_binding(version)
        if analyzed is None:
            continue
        layout = PELayout.read(analyzed)
        if layout.pointer_size != 8 or layout.machine != 0x8664:
            raise RuntimeError('Skyrim {} target is not AMD64'.format(version))
        out[key] = layout
    return out


def _validate_symbol_offsets(symbol, declared_kind, layouts):
    for key in _TARGET_KEYS.values():
        layout = layouts.get(key)
        if key not in symbol or layout is None:
            continue
        actual, section = layout.classify_rva(symbol[key])
        if actual == 'unmapped' or actual != declared_kind:
            symbol.setdefault('rejected_offsets', {})[key] = actual
            del symbol[key]
            continue
        symbol.setdefault('sections', {})[key] = section
        symbol.setdefault('target_sha256', {})[key] = layout.sha256


def _report_dir():
    """Dropped-label reports are evidence: gitignored build/, never the source
    tree (``basename(SCRIPT_DIR)`` keeps the VR forks' reports apart)."""
    return os.path.join(PROJECT_DIR, 'build', 'evidence', 'vtable_labels',
                        os.path.basename(SCRIPT_DIR))


def validate_vtable_labels(symbols, layouts, class_labels=None):
    """Drop VTABLE_* offsets that the staged executable's own RTTI refutes.

    ``vtable[-1]`` -> CompleteObjectLocator -> TypeDescriptor names the class a
    vtable really belongs to (core/vtable_label_check.py).  The dropped list
    per runtime lands in build/evidence/vtable_labels/, with the ID of
    that runtime's own namespace (SE/VR: SE ID, AE family: AE ID).
    """
    return validate_vtable_labels_for_layouts(
        symbols, layouts, class_labels,
        report_dir=_report_dir(),
        id_fields=RUNTIME_ID_FIELDS)


def _classify_symbol_offsets(symbol, layouts):
    """Record the kind each staged runtime gives a symbol of UNKNOWN kind.

    ``skyrimae.rename`` names functions and data alike without saying which.
    Declaring every row ``func`` and validating against that deleted ~9k data
    names per AE runtime whenever no 1.6.1170 exe was staged to correct the
    guess.  The section role of the resolved RVA in THAT runtime's executable
    decides instead (``kinds[key]``); only unmapped RVAs are rejected.
    """
    for key in _TARGET_KEYS.values():
        layout = layouts.get(key)
        if key not in symbol or layout is None:
            continue
        actual, section = layout.classify_rva(symbol[key])
        if actual == 'unmapped':
            symbol.setdefault('rejected_offsets', {})[key] = actual
            del symbol[key]
            continue
        symbol.setdefault('kinds', {})[key] = actual
        symbol.setdefault('sections', {})[key] = section
        symbol.setdefault('target_sha256', {})[key] = layout.sha256


def specialise_kinds_for_runtime(symbols, key):
    """Return ``symbols`` with ``t`` set to the kind runtime ``key`` proved."""
    out = []
    for symbol in symbols:
        kinds = symbol.get('kinds')
        if kinds is None:
            out.append(symbol)
            continue
        specialised = {k: v for k, v in symbol.items() if k != 'kinds'}
        specialised['t'] = kinds.get(key, symbol['t'])
        out.append(specialised)
    return out

# ---------------------------------------------------------------------------
# AE rename database
# ---------------------------------------------------------------------------

def load_ae_rename_ids(file_path):
    """Load skyrimae.rename as ``{ae_id: name}`` (AE ID namespace).

    The ID is the identity of a row.  Reducing it to a 1.6.1170 RVA first lost
    every name whose ID 1.6.1170 no longer has (650 for 1.6.640).
    """
    result = {}
    if not os.path.exists(file_path):
        return result
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip version line
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) != 2:
            continue
        name = parts[1].rstrip('*').rstrip('_')
        try:
            ae_id = int(parts[0])
        except ValueError:
            continue
        result[ae_id] = name
    return result


def load_ae_rename_db(file_path, ae_db):
    """``{ae_db RVA: name}`` view of skyrimae.rename for one AE runtime."""
    result = {}  # ae_offset -> name
    for ae_id, name in load_ae_rename_ids(file_path).items():
        off = ae_db.get(ae_id)
        if off:
            result[off] = name
    return result


VERSIONS = {
    'se': {
        'defines':     [],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_SE.py'),
    },
    'ae': {
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE.py'),
    },
    '16640': {
        # Skyrim AE 1.6.640 -- AE ID namespace, same header configuration as
        # the other AE runtimes.  The powerof3 headers describe post-1.6.1130
        # layouts only, so types touched by that layout change are 1130+-shaped
        # here (see the pre-1130 caveat in the README).
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE_1_6_640.py'),
    },
    '17104': {
        # The pinned headers have no 1.7 switch: they parse to the 1.6 AE
        # shapes, which skyrim17_layouts rewrites to the 1.7.104 layouts.
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE_1_7_104.py'),
        'layout_patch': _apply_ae17_layouts,
    },
    'svr': {
        # Skyrim VR (1.4.15) — same headers as SE; symbols come from VR
        # offsets looked up via the SE-namespace ID (SE and VR share the
        # same ID space).  The powerof3 CommonLibSSE fork has no
        # VR-specific preprocessor define, so we parse with the SE define
        # set and just attach VR offsets at script-generation time.
        'defines':     [],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_VR.py'),
    },
}


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


def _enrich_symbols_with_sigs(symbols_json, structs):
    """Cross-reference symbols with AST method signatures.

    For each function symbol like 'Actor::AddSpell', look up the method
    signature from structs['Actor']['methods']['AddSpell'] and store
    structured pipeline type data for direct FunctionDefinitionDataType
    construction (bypasses CParserUtils).
    """
    import json as _json
    symbols = _json.loads(symbols_json)
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    improved = 0
    skipped = 0
    for sym in symbols:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        methods = st.get('methods', {})
        info = methods.get(method_name)
        if not info and method_name == 'operator':
            info = methods.get('operator()')
        if not info:
            continue
        ret, params, is_static = info
        if _has_unresolved_tparam(ret) or any(_has_unresolved_tparam(p[1]) for p in params):
            skipped += 1
            continue
        sym['sd'] = [ret, params, 1 if is_static else 0]
        improved += 1
    if improved:
        print('Improved {} symbols with AST method signatures'.format(improved))
    if skipped:
        print('Skipped {} symbols with uninstantiated template params in signature'.format(skipped))
    return _json.dumps(symbols, separators=(',', ':'))


def run_version(version, symbols_json, fallback_symbols_json='[]',
                address_lib_map=None, pdb_structs=None, pdb_enums=None,
                gog_variants=None, target_manifest=None):
    from clang_types import collect_types, _setup_include_paths

    cfg = VERSIONS[version]
    output_path = cfg['output']
    stub_dir = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir) + cfg['defines']

    print('\n=== {} ==='.format(version.upper()))

    if not os.path.isfile(SKYRIM_H):
        print('ERROR: Could not find Skyrim.h at', SKYRIM_H)
        sys.exit(1)

    # Capture types from sibling namespaces (REL, REX, SKSE) under the
    # CommonLibSSE include root — without this the AST extraction would skip
    # methods declared outside the RE/ subdirectory.
    enums, structs, template_source = collect_types(
        SKYRIM_H, RE_INCLUDE, parse_args,
        verbose=True,
        extra_scope_paths=[COMMONLIB_INCLUDE],
    )
    print('Found {} enums, {} structs/classes'.format(len(enums), len(structs)))

    # Merge SkyrimSE.pdb-derived enums (AST wins on name collision).
    if pdb_enums:
        n_added = n_members = 0
        for cls, en in pdb_enums.items():
            if cls in enums:
                continue
            en2 = dict(en)
            en2['values'] = [tuple(v) for v in en.get('values', [])]
            enums[cls] = en2
            n_added += 1
            n_members += len(en2['values'])
        if n_added:
            print('PDB enum merge: {} new ({} members)'.format(n_added, n_members))

    # Merge SkyrimSE.pdb-derived types into the clang AST result so SE/AE/VR
    # all inherit Bethesda's full internal class hierarchy (the parts
    # CommonLibSSE doesn't document).  Mirrors the FNV pdb-types merge.
    if pdb_structs:
        n_added = n_upgraded = 0
        for cls, st in pdb_structs.items():
            existing = structs.get(cls)
            if existing is None:
                structs[cls] = st
                n_added += 1
                continue
            ex_fields = existing.get('fields', [])
            non_vft = [f for f in ex_fields
                       if not f.get('name', '').startswith('__vftable')]
            if existing.get('size', 0) == 0 or not non_vft:
                # Empty clang stub -- upgrade with PDB layout, keep clang's
                # class methods + vtable info if any
                upgraded = dict(st)
                upgraded['vmethods']         = existing.get('vmethods', {})
                upgraded['methods']          = existing.get('methods', {})
                upgraded['has_vtable']       = existing.get('has_vtable', False)
                upgraded['bases']            = existing.get('bases', [])
                upgraded['_overload_aliases'] = existing.get('_overload_aliases', {})
                structs[cls] = upgraded
                n_upgraded += 1
        print('PDB type merge: {} new + {} upgraded (clang AST is authoritative '
              'for documented types)'.format(n_added, n_upgraded))
        # Re-run flatten so PDB-introduced bases cascade fields down into
        # their derived classes (mirrors FNV's post-PDB flatten pass).
        try:
            from ghidra_import_gen import flatten_structs as _flatten
            _flatten(structs)
        except Exception as e:
            print('  WARNING: post-PDB flatten failed: {}: {}'.format(
                type(e).__name__, e))

    # Per-runtime layout rewrite, once every record source is merged and
    # before vtables are built or bases flattened into derived records.
    layout_patch = cfg.get('layout_patch')
    if layout_patch is not None:
        layout_patch(structs, enums)

    symbols_json = _enrich_symbols_with_sigs(symbols_json, structs)

    shift_map_path = os.path.join(
        SCRIPT_DIR, 'refs', 'shift_{}.json'.format(version))
    anchors_csv = os.path.join(
        SCRIPT_DIR, 'anchors', '{}.csv'.format(version))
    emit_vtables, vtable_reason = _allow_vtable_emission(
        version, anchors_csv, shift_map_path)
    vtable_structs = _build_vtable_structs(structs) if emit_vtables else {}
    if emit_vtables:
        _inject_vtable_fields(structs, vtable_structs)
    else:
        print('VTABLES DISABLED: {}'.format(vtable_reason))
    _flatten_structs(structs)
    _apply_secondary_vtable_typing(structs)

    if emit_vtables:
        # No legacy map is accepted on the correctness path.  This branch is
        # retained for a future identity-bound map schema.
        shift_map = _load_shift_map_json(shift_map_path)
        if shift_map:
            raise RuntimeError('unvalidated shift map reached vtable emitter')
        if not os.path.isfile(anchors_csv):
            raise RuntimeError(
                'required vtable anchors are missing: {}'.format(anchors_csv))
        _verify_anchors_or_exit(version, vtable_structs, anchors_csv)

    print('Generating Ghidra script...')
    if target_manifest is None:
        raise RuntimeError('refusing to emit unbound Skyrim importer {}'.format(version))
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs, output_path, version, symbols_json,
        fallback_symbols_json, template_source,
        address_lib_map=address_lib_map,
        target_manifest=target_manifest)
    print('Output: {} ({} enums, {} structs)'.format(output_path, n_enums, n_structs))

    # --- GOG / extra-AE-build variants ---
    # ``gog_variants`` is [(label, build_db, rev_1170), ...].  Every AE-keyed
    # symbol is re-keyed through its address-library ID (stable across all
    # AE builds): 1.6.1170-RVA -> ID -> build-RVA.  Types/vtables are byte-
    # identical across the 1.6.x AE builds, so we reuse this parse's AST
    # results and only swap the offsets.  Closes the gap where the GOG Edition
    # binary was applied with Steam 1.6.1170 offsets.  NOT true for 1.7.x:
    # the pinned headers have no 1.7 switch, so the 17104 run rewrites the
    # records, enums and vtables that changed there (skyrim17_layouts).
    import json as _json
    for label, build_db, rev_1170 in (gog_variants or []):
        def _rekey(json_blob):
            out = []
            kept = dropped = 0
            for s in _json.loads(json_blob):
                a = s.get('a')
                ai = s.get('ai') or (rev_1170.get(a) if a else None)
                if ai is None or ai not in build_db:
                    dropped += 1
                    continue
                ns = dict(s)
                ns['a'] = build_db[ai]
                ns['ai'] = ai
                # Section/hash evidence described the 1.6.1170 source RVA and
                # must never be carried onto a re-keyed GOG address.
                ns.pop('sections', None)
                ns.pop('target_sha256', None)
                ns.pop('kind_mismatch', None)
                ns['address_library_variant'] = label
                out.append(ns)
                kept += 1
            return _json.dumps(out, separators=(',', ':')), kept, dropped
        sym_blob, k1, d1 = _rekey(symbols_json)
        fb_blob, k2, d2 = _rekey(fallback_symbols_json)
        variant_path = output_path.replace('.py', '_{}.py'.format(label))
        # A re-keyed database is not target identity.  Do not emit a GOG
        # importer without the exact GOG executable/artifact manifest.
        print('SKIP {}: exact target executable is required to bind this variant'.format(
            variant_path))
        continue
        print('Output: {} (re-keyed {} symbols + {} fallbacks; '
              'dropped {}+{} without a {} mapping)'.format(
                  variant_path, k1, k2, d1, d2, label))


def _detect_exe_versions():
    """Detect SE and AE exe versions from the exes directory."""
    exes_root = os.path.join(PROJECT_DIR, 'exes', 'skyrim')
    se_ver = ae_ver = None

    for ver_name, attr in [('se', 'se_ver'), ('ae', 'ae_ver')]:
        ver_dir = os.path.join(exes_root, ver_name)
        if not os.path.isdir(ver_dir):
            continue
        candidates = [
            os.path.join(ver_dir, fname)
            for fname in sorted(os.listdir(ver_dir))
            if (fname.lower().endswith('.exe') and
                'unpacked' not in fname.lower() and
                os.path.isfile(os.path.join(ver_dir, fname)))
        ]
        if len(candidates) > 1:
            raise RuntimeError(
                'ambiguous {} executables: {}'.format(
                    ver_name.upper(), ', '.join(
                        os.path.basename(path) for path in candidates)))
        if not candidates:
            continue
        v = get_pe_version(candidates[0])
        if not v:
            raise RuntimeError(
                'cannot read {} executable version: {}'.format(
                    ver_name.upper(), candidates[0]))
        print('  Detected {} exe version: {}'.format(
            ver_name.upper(), '.'.join(str(x) for x in v)))
        if attr == 'se_ver':
            se_ver = v
        else:
            ae_ver = v

    return se_ver, ae_ver


# Offset keys of the runtimes that live in the AE address-library ID namespace
# but are not the primary ``a`` (1.6.1170) target.
EXTRA_AE_RUNTIMES = ('16640', '17104')


def attach_extra_ae_offsets(symbol, ae_id, extra_dbs):
    """Resolve the extra AE runtimes through the AE ID namespace ONLY.

    An SE ID looked up in an AE-namespace database lands on an unrelated
    address (none of ~7,000 dual-ID symbols agree), so an SE-only symbol gets
    no offset for these runtimes instead of a wrong one.  That mix-up put 437
    wrong labels into the 1.7.104 importer (2026-09-21).
    """
    if ae_id is None:
        return
    for extra_key, extra_db in extra_dbs:
        extra_rva = extra_db.get(ae_id)
        if extra_rva:
            symbol[extra_key] = extra_rva


def assert_no_se_only_ae_offsets(symbols):
    """Fail generation if an SE-only symbol carries an AE-namespace offset."""
    bad = [s['n'] for s in symbols
           if s.get('ai') is None and any(k in s for k in EXTRA_AE_RUNTIMES)]
    if bad:
        raise RuntimeError(
            '{} symbol(s) without an AE ID carry an AE-namespace runtime '
            'offset (first: {}); SE IDs must never be resolved through an AE '
            'database'.format(len(bad), ', '.join(bad[:5])))


def _extra_ae_dbs(addr_lib):
    return (('16640', addr_lib.db_16640), ('17104', addr_lib.db_17104))


def symbol_from_parser(parsed, kind, target_layouts, addr_lib=None):
    """Build one importer symbol from a ``reloc_parser`` func/label dict.

    The parser read the IDs out of the source text, so they are carried as
    ``si`` / ``ai`` verbatim.  Deriving ``ai`` later from the 1.6.1170 RVA
    (``ae_rva_to_id[sym['a']]``) made 1.6.640 / 1.7.104 depend on 1.6.1170:
    an ID 1.6.1170 lacks, or an ``a`` offset the section check deleted, took
    the other AE runtimes down with it.
    """
    if kind == 'func':
        name = ('{}::{}'.format(parsed['class_'], parsed['name'])
                if parsed.get('class_') else parsed['name'])
        sig = ''
        if parsed.get('ret'):
            sig = '{}({})'.format(parsed['ret'], parsed.get('params', ''))
            if parsed.get('is_static'):
                sig = 'static ' + sig
    else:
        name, sig = parsed['name'], ''
    sym = {'n': name, 't': kind, 'sig': sig, 'src': 'CommonLibSSE'}
    if parsed.get('se_off'): sym['s'] = parsed['se_off']
    if parsed.get('ae_off'): sym['a'] = parsed['ae_off']
    if parsed.get('vr_off'): sym['v'] = parsed['vr_off']
    if parsed.get('se_id'): sym['si'] = parsed['se_id']
    if parsed.get('ae_id'):
        sym['ai'] = parsed['ae_id']
        if addr_lib is not None:
            attach_extra_ae_offsets(sym, sym['ai'], _extra_ae_dbs(addr_lib))
    _validate_symbol_offsets(sym, kind, target_layouts)
    return sym


def merge_ae_rename(symbols, name_to_syms, rename_ids, addr_lib, target_layouts):
    """Merge ``skyrimae.rename`` (``{ae_id: name}``) into ``symbols``.

    Everything is keyed on the AE ID: a row is new when no symbol owns that
    ID, and each AE runtime is resolved from the ID in its own database.
    Returns ``(added, merged)``.
    """
    extra_dbs = _extra_ae_dbs(addr_lib)
    seen_ai = {s['ai'] for s in symbols if s.get('ai') is not None}
    name_counts = {}
    for rename_name in rename_ids.values():
        name_counts[rename_name] = name_counts.get(rename_name, 0) + 1
    added = merged = 0
    for ae_id, name in rename_ids.items():
        if ae_id in seen_ai:
            continue
        resolved = {}
        if addr_lib.ae_db.get(ae_id):
            resolved['a'] = addr_lib.ae_db[ae_id]
        attach_extra_ae_offsets(resolved, ae_id, extra_dbs)
        if not resolved:
            continue
        candidates = name_to_syms.get(name, [])
        if len(candidates) == 1 and name_counts.get(name) == 1:
            existing = candidates[0]
            if existing.get('ai') is None and not existing.get('a'):
                existing.update(resolved)
                existing['ai'] = ae_id
                _validate_symbol_offsets(existing, existing['t'], target_layouts)
                rejected = existing.get('rejected_offsets', {})
                if (any(k in rejected for k in resolved) or
                        not any(k in existing for k in resolved)):
                    # A name-only match the binary contradicts in any AE
                    # runtime is not this symbol: undo the whole merge.
                    for key in resolved:
                        existing.pop(key, None)
                    del existing['ai']
                    continue
                seen_ai.add(ae_id)
                merged += 1
            continue
        sym = {'n': name, 't': 'func', 'sig': '', 'ai': ae_id,
               'src': 'skyrimae.rename'}
        sym.update(resolved)
        _classify_symbol_offsets(sym, target_layouts)
        if not any(k in sym for k in resolved):
            continue
        seen_ai.add(ae_id)
        symbols.append(sym)
        name_to_syms.setdefault(name, []).append(sym)
        added += 1
    return added, merged


def attach_address_library_ids(symbols, addr_lib, target_layouts):
    """Give every symbol its ``si`` / ``ai`` and the extra AE runtime offsets.

    A parser-provided ID wins; the unique reverse map only serves sources that
    know an RVA and nothing else (PDB publics).  No AE-namespace offset is ever
    attached without an AE ID.  Returns the number of symbols with an ID.
    """
    se_rva_to_id, ambiguous_se_rvas = unique_reverse_ids(addr_lib.se_db)
    ae_rva_to_id, ambiguous_ae_rvas = unique_reverse_ids(addr_lib.ae_db)
    if ambiguous_se_rvas or ambiguous_ae_rvas:
        print('Rejected ambiguous address-library reverse mappings: '
              'SE={} AE={}'.format(
                  len(ambiguous_se_rvas), len(ambiguous_ae_rvas)))
    extra_dbs = _extra_ae_dbs(addr_lib)
    id_count = 0
    for s in symbols:
        se_id = s.get('si')
        if se_id is None:
            se_id = se_rva_to_id.get(s.get('s'))
        ae_id = s.get('ai')
        if ae_id is None:
            ae_id = ae_rva_to_id.get(s.get('a'))
        if se_id is not None:
            s['si'] = se_id
        if ae_id is not None:
            s['ai'] = ae_id
        rejected = s.get('rejected_offsets', {})
        fresh = {}
        attach_extra_ae_offsets(fresh, ae_id, extra_dbs)
        for key, rva in fresh.items():
            if key not in s and key not in rejected:
                s[key] = rva
        if se_id is not None or ae_id is not None:
            id_count += 1
        if s.get('kinds') is not None or s.get('src') == 'skyrimae.rename':
            _classify_symbol_offsets(s, target_layouts)
        else:
            _validate_symbol_offsets(s, s['t'], target_layouts)
    assert_no_se_only_ae_offsets(symbols)
    return id_count


def _runtime_requested(version, selected, target_layouts):
    """True when ``version`` was asked for or its importer will be emitted."""
    if selected is not None:
        return version in selected
    return target_layouts.get(_TARGET_KEYS[version]) is not None


def main():
    import argparse as _argparse
    import json as _json

    ap = _argparse.ArgumentParser(description='Generate CommonLibSSE importers.')
    ap.add_argument('--only', action='append', metavar='VERSION',
                    help='generate just this runtime (se, ae, 16640, 17104, svr/vr; '
                         'repeatable).  Default: every Skyrim runtime.')
    cli = ap.parse_args()
    selected = None
    if cli.only:
        alias = {'vr': 'svr'}
        selected = {alias.get(v.lower(), v.lower()) for v in cli.only}
        unknown = selected - {'se', 'ae', '16640', '17104', 'svr'}
        if unknown:
            ap.error('unknown runtime(s): {} (known: se, ae, 16640, 17104, vr)'.format(
                ', '.join(sorted(unknown))))

    # Detect exe versions for address library selection
    print('=== Detecting exe versions ===')
    se_ver, ae_ver = _detect_exe_versions()
    norm_se = (tuple(se_ver) + (0, 0, 0, 0))[:4] if se_ver else None
    norm_ae = (tuple(ae_ver) + (0, 0, 0, 0))[:4] if ae_ver else None
    if norm_se and norm_se != (1, 5, 97, 0):
        raise RuntimeError(
            'Local Skyrim SE is {}, but CommonLibImport_SE.py is bound to '
            '1.5.97.0.  Refusing to substitute that address database.'.format(
                '.'.join(str(x) for x in se_ver)))
    if norm_ae and norm_ae != (1, 6, 1170, 0):
        raise RuntimeError(
            'Local Skyrim AE is {}, but the primary AE script is bound to '
            'Steam 1.6.1170.0.  Generate/select an exact relib-backed variant '
            'instead of applying 1170 RVAs.'.format('.'.join(str(x) for x in ae_ver)))

    # Load address databases (AddressLibrary picks fixed versions:
    # SE 1.5.97, AE 1.6.1170, VR 1.4.15 -- detected exe versions are
    # logged for diagnostics but don't currently feed the loader).
    # A runtime whose importer will be emitted (its exe is staged) needs its
    # database: without it every symbol of that runtime silently vanishes
    # and a types-only importer is reported as success.
    target_layouts = _load_target_layouts()
    addr_lib = AddressLibrary()
    addr_lib.load_all(
        os.path.join(PROJECT_DIR, 'addresslibrary'),
        require_17104=_runtime_requested('17104', selected, target_layouts),
        require_16640=_runtime_requested('16640', selected, target_layouts))
    print('SE entries: {}, AE entries: {}, 1.6.640 entries: {}, '
          '1.7.104 entries: {}'.format(
              len(addr_lib.se_db), len(addr_lib.ae_db),
              len(addr_lib.db_16640), len(addr_lib.db_17104)))

    print('\n=== Collecting symbols via regex relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, offset_id_map, static_methods, se_offset_map, ae_offset_map = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    src_dir = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSSE', 'src')
    if os.path.isdir(src_dir):
        src_func_syms = _rp.collect_src_relocations(
            src_dir, addr_lib, offset_id_map,
            se_offset_map=se_offset_map, ae_offset_map=ae_offset_map,
            verbose=True)
    else:
        src_func_syms = []
        print('  src/ dir not found, skipping')

    label_by_name = {}
    for lbl in label_syms:
        label_by_name.setdefault(lbl['name'], {
            'name': lbl['name'], 'se_off': None, 'ae_off': None, 'vr_off': None})
        entry = label_by_name[lbl['name']]
        for field in ('se_off', 'ae_off', 'vr_off', 'se_id', 'ae_id',
                      'vtable_class', 'vtable_index'):
            if lbl.get(field) is not None:
                entry[field] = lbl[field]

    merged_funcs = list(func_syms)
    seen_se = set(fs['se_off'] for fs in merged_funcs if fs.get('se_off'))
    seen_ae = set(fs['ae_off'] for fs in merged_funcs if fs.get('ae_off'))
    seen_ids = set((fs.get('se_id'), fs.get('ae_id')) for fs in merged_funcs)

    for fs in src_func_syms:
        if not fs.get('is_static') and fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    for fs in src_func_syms:
        se_off = fs.get('se_off')
        ae_off = fs.get('ae_off')
        if se_off and se_off in seen_se:
            continue
        if ae_off and ae_off in seen_ae:
            continue
        if (not se_off and not ae_off and
                (fs.get('se_id'), fs.get('ae_id')) in seen_ids):
            continue
        if se_off: seen_se.add(se_off)
        if ae_off: seen_ae.add(ae_off)
        seen_ids.add((fs.get('se_id'), fs.get('ae_id')))
        merged_funcs.append(fs)

    # Build SYMBOLS array
    symbols = []
    sym_seen_se = set()

    # Function symbols
    for fs in merged_funcs:
        if fs['se_off']: sym_seen_se.add(fs['se_off'])
        symbols.append(symbol_from_parser(fs, 'func', target_layouts, addr_lib))

    # RTTI/NiRTTI/VTABLE labels
    vtable_classes = {}
    for lbl in label_by_name.values():
        if lbl['se_off']: sym_seen_se.add(lbl['se_off'])
        if lbl.get('vtable_class'):
            vtable_classes[lbl['name']] = lbl['vtable_class']
        symbols.append(symbol_from_parser(lbl, 'label', target_layouts, addr_lib))
    validate_vtable_labels(symbols, target_layouts, vtable_classes)

    name_to_syms = {}
    for symbol in symbols:
        name_to_syms.setdefault(symbol['n'], []).append(symbol)

    # AE rename database fallback (keyed on the AE ID, never on a 1170 RVA)
    rename_db = os.path.join(PROJECT_DIR, 'extern', 'AddressLibraryDatabase', 'skyrimae.rename')
    rename_added, rename_merged = merge_ae_rename(
        symbols, name_to_syms, load_ae_rename_ids(rename_db), addr_lib,
        target_layouts)
    print('Added {} new symbols from AE rename, merged AE offset into {} existing'.format(
        rename_added, rename_merged))

    # SE PDB public symbols.  The loader verifies the target PE CodeView
    # GUID/age and applies OMAP_FROM_SRC.  A detached pretty-text dump is not
    # accepted because it cannot prove which executable its RVAs describe.
    se_pdb_path = os.path.join(PROJECT_DIR, 'extras', 'SkyrimSE.pdb')
    _se_binding, se_target_pe = _target_binding('se')
    pdb_file_valid = (os.path.isfile(se_pdb_path) and
                      _file_sha256(se_pdb_path) == SE_PDB_SHA256)
    # GUID/age are not cryptographic integrity: a modified PDB can retain
    # them.  Verify the pinned full-file hash before allowing its names into
    # the symbol pool, not merely before consuming derived JSON later.
    se_pdb_names = (load_se_pdb_names(se_pdb_path, pe_path=se_target_pe)
                    if se_target_pe and pdb_file_valid else {})
    pdb_identity_valid = bool(se_pdb_names and pdb_file_valid)
    if not se_pdb_names:
        print('  SkyrimSE PDB names unavailable or PE CodeView GUID/age did not match; '
              'unbound pretty-dump fallback is intentionally disabled.')
    pdb_added = pdb_merged = 0
    pdb_quarantined = 0
    for se_off, public in se_pdb_names.items():
        name = public.name
        if se_off in sym_seen_se:
            continue
        existing = unique_public_merge_target(
            public, name_to_syms.get(name, []))
        if (existing is not None and existing.get('t') == 'func' and
                not existing.get('s')):
            existing['s'] = se_off
            _validate_symbol_offsets(existing, existing['t'], target_layouts)
            if existing.get('s') == se_off:
                sym_seen_se.add(se_off)
                pdb_merged += 1
                continue
        # A same-name candidate already bound to another SE RVA is evidence of
        # a collision, not a reason to discard this exact PDB public.
        # Ambiguous overload/name-only records remain attached solely to the
        # exact SE RVA.  Decorated identity is retained as provenance, but no
        # AE/VR coordinate can be inherited through a display-name collision.
        sym = {
            'n': name, 't': 'func', 'sig': '', 's': se_off,
            'src': 'SkyrimSE.pdb',
            'pdb_decorated_name': public.decorated_name,
            'pdb_aliases': list(public.aliases),
            'pdb_merge_safe': public.merge_safe,
        }
        se_layout = target_layouts.get('s')
        if se_layout is not None:
            if not attach_section(sym, 's', se_layout, declared_kind='func'):
                continue
            sym.setdefault('target_sha256', {})['s'] = se_layout.sha256
        sym_seen_se.add(se_off)
        symbols.append(sym)
        name_to_syms.setdefault(name, []).append(sym)
        if not public.merge_safe or len(name_to_syms[name]) > 1:
            pdb_quarantined += 1
        pdb_added += 1
    print('Added {} new symbols from SE PDB, merged SE offset into {} existing'.format(
        pdb_added, pdb_merged))
    if pdb_quarantined:
        print('  Kept {} ambiguous PDB overload/alias records SE-only'.format(
            pdb_quarantined))

    # --- Structured signatures from SkyrimSE.pdb --globals ---
    # The globals stream is the only part of this PDB carrying full
    # function signatures (ret + callconv + args).  Attach parsed 'sd'
    # descriptors to every SE-keyed symbol so the generated scripts apply
    # typed signatures (mirrors FNV's Xbox-PDB sig pipeline).
    sigs_path = os.path.join(SCRIPT_DIR, 'refs', 'skyrimse_pdb_func_sigs.json')
    if _trusted_pdb_derived(sigs_path, pdb_identity_valid):
        import json as _j
        sys.path.insert(0, os.path.join(PROJECT_DIR, 'scripts', 'commonlibnvse'))
        try:
            from pdb_sig_to_structured import parse_sig as _parse_sig
            rva_sigs = _j.loads(open(sigs_path, encoding='utf-8').read())
            types_known = set()
            enums_known = set()
            tp = os.path.join(SCRIPT_DIR, 'refs', 'skyrimse_pdb_types.json')
            ep = os.path.join(SCRIPT_DIR, 'refs', 'skyrimse_pdb_enums.json')
            if _trusted_pdb_derived(tp, pdb_identity_valid):
                types_known = set(_j.loads(open(tp, encoding='utf-8').read()))
            if _trusted_pdb_derived(ep, pdb_identity_valid):
                for cls in _j.loads(open(ep, encoding='utf-8').read()):
                    enums_known.add(cls)
                    enums_known.add(cls.replace('::', '_'))
            n_sd = n_sd_fail = 0
            for s in symbols:
                if s.get('sd') or s.get('t') != 'func':
                    continue
                se_off = s.get('s')
                if not se_off:
                    continue
                rec = rva_sigs.get('0x{:08X}'.format(se_off))
                if not rec:
                    continue
                try:
                    sd = _parse_sig(rec['sig'], types_known, enums_known, {})
                except Exception:
                    sd = None
                if sd is not None:
                    s['sd'] = sd
                    n_sd += 1
                else:
                    n_sd_fail += 1
            print('Attached {} structured sigs from PDB globals '
                  '({} unparseable)'.format(n_sd, n_sd_fail))
        except ImportError as e:
            print('  WARNING: sig parser unavailable ({}); skipping '
                  'globals-sig attach'.format(e))

    # Preserve literal ``__``.  skyrimae.rename uses it for encoded template
    # arguments and inheritance paths; replacing every occurrence with ``::``
    # fabricated namespaces.  Parser/PDB names already carry genuine ``::``.

    # Attach address-library IDs: the parser's own ID first, the unique
    # RVA->ID reverse map only for RVA-only sources (PDB publics).
    id_count = attach_address_library_ids(symbols, addr_lib, target_layouts)
    print('Attached address-library IDs to {} of {} symbols'.format(id_count, len(symbols)))

    funcs = [s for s in symbols if s['t'] == 'func']
    with_sig = len([s for s in funcs if s.get('sig')])
    labels_count = len([s for s in symbols if s['t'] == 'label'])
    print('\nGenerated {} symbols:'.format(len(symbols)))
    print('  Functions: {} ({} with signatures)'.format(len(funcs), with_sig))
    print('  Labels: {}'.format(labels_count))

    _FALLBACK_SRCS = {'skyrimae.rename', 'SkyrimSE.pdb'}
    primary_symbols  = [s for s in symbols if s.get('src') not in _FALLBACK_SRCS]
    fallback_symbols = [s for s in symbols if s.get('src') in _FALLBACK_SRCS]
    print('  Primary: {}, Fallback (AE rename / SE PDB new): {}'.format(
        len(primary_symbols), len(fallback_symbols)))

    symbols_json = _json.dumps(primary_symbols, separators=(',', ':'))

    se_fallback = [s for s in fallback_symbols if s.get('src') == 'SkyrimSE.pdb']
    ae_fallback = [s for s in fallback_symbols if s.get('src') == 'skyrimae.rename']
    print('  SE fallback: {} (PDB), AE fallback: {} (rename DB)'.format(
        len(se_fallback), len(ae_fallback)))

    se_fallback_json = _json.dumps(se_fallback, separators=(',', ':'))
    # skyrimae.rename does not say whether a row is code or data; each AE
    # runtime gets the kind its own executable proves for the resolved RVA.
    ae_fallback_json_by_key = {
        key: _json.dumps(specialise_kinds_for_runtime(ae_fallback, key),
                         separators=(',', ':'))
        for key in ('a',) + EXTRA_AE_RUNTIMES}
    for key in ('a',) + EXTRA_AE_RUNTIMES:
        if target_layouts.get(key) is not None:
            kinds = [s.get('kinds', {}).get(key) for s in ae_fallback if key in s]
            print('  AE rename pool for {}: {} funcs, {} labels'.format(
                key, kinds.count('func'), kinds.count('label')))

    n_v = sum(1 for s in primary_symbols if s.get('v'))
    print('  VR coverage: {} symbols (SE-namespace IDs resolved against vr_db)'.format(n_v))

    fb_for = {
        'se':  se_fallback_json,
        'ae':  ae_fallback_json_by_key['a'],
        '16640': ae_fallback_json_by_key['16640'],
        '17104': ae_fallback_json_by_key['17104'],
        'svr': '[]',
    }

    # --- Persisted bytesig-port results (refs/bytesig_ported_<ver>.csv) ---
    # Written by commonlibsse/bytesig_port_combined.py --write-back-script.
    # Merging here makes the ported names survive regeneration: previously
    # they only lived inside the generated scripts and every regen wiped
    # them until the ~42-min port was re-run.
    def _merge_bytesig_csv(fb_json, csv_name, rva_key):
        csv_path = os.path.join(SCRIPT_DIR, 'refs', csv_name)
        if not os.path.isfile(csv_path):
            return fb_json
        layout = target_layouts.get(rva_key)
        if layout is None:
            print('  rejecting persisted bytesig evidence without exact target PE: {}'.format(
                csv_name))
            return fb_json
        target_manifest = {
            'sha256': layout.sha256, 'path': layout.path,
            'machine': layout.machine, 'pointer_size': layout.pointer_size,
            'image_base': layout.image_base, 'image_size': layout.image_size,
        }
        try:
            evidence_rows, _identity = _load_bytesig_evidence(
                csv_path, target_manifest)
            target_starts = x64_runtime_function_starts(layout.path)
        except (OSError, ValueError) as exc:
            print('  rejecting stale/unbound persisted bytesig evidence {}: {}'.format(
                csv_name, exc))
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
            existing.append({
                'n': row['name'], 't': 'func', 'sig': '',
                rva_key: rva,
                'src': row.get('source_tag') or 'bytesig-port',
                'sections': probe.get('sections', {}),
                'target_sha256': {rva_key: layout.sha256},
            })
            n_added += 1
        if n_added:
            print('  merged {} persisted bytesig names from {}'.format(
                n_added, csv_name))
        return _json.dumps(existing, separators=(',', ':'))

    fb_for['ae']  = _merge_bytesig_csv(fb_for['ae'],  'bytesig_ported_ae.csv', 'a')
    fb_for['16640'] = _merge_bytesig_csv(
        fb_for['16640'], 'bytesig_ported_16640.csv', '16640')
    fb_for['17104'] = _merge_bytesig_csv(
        fb_for['17104'], 'bytesig_ported_17104.csv', '17104')
    fb_for['svr'] = _merge_bytesig_csv(fb_for['svr'], 'bytesig_ported_vr.csv', 'v')
    fb_for['se']  = _merge_bytesig_csv(fb_for['se'],  'bytesig_ported_se.csv', 's')

    # --- SkyrimSE.pdb-derived type layouts (Bethesda's full class hierarchy) ---
    # Parse once, share across SE/AE/VR.  CommonLibSSE documents only the
    # public-facing classes; the PDB exposes ~19k internal Bethesda types
    # with full field layouts that lift every F4-style "empty stub" struct
    # to a real layout for Ghidra (same FNV gained from Fallout_Debug PDB).
    pdb_structs = {}
    pdb_types_json = os.path.join(SCRIPT_DIR, 'refs', 'skyrimse_pdb_types.json')
    if _trusted_pdb_derived(pdb_types_json, pdb_identity_valid):
        from pathlib import Path as _Path
        # Reuse the FNV converter -- pointer-size-agnostic, output 'ptr' is
        # resolved by Ghidra against the loaded program's pointer width.
        sys.path.insert(0, os.path.join(PROJECT_DIR, 'scripts', 'commonlibnvse'))
        from pdb_types_to_pipeline import convert_pdb_types as _convert_pdb_types
        try:
            pdb_structs, n_skipped, n_fields = _convert_pdb_types(
                _Path(pdb_types_json),
                category='/CommonLibSSE/PDB')
            print('\nLoaded {} PDB structs ({} fields total, skipped {} empty/anon)'.format(
                len(pdb_structs), n_fields, n_skipped))
        except Exception as e:
            print('WARNING: SkyrimSE PDB type load failed: {}: {}'.format(
                type(e).__name__, e))
            pdb_structs = {}
    else:
        if not pdb_identity_valid:
            print('\nSkipping SkyrimSE PDB type JSON: PDB/PE identity was not validated.')
        else:
            print('\nNo SkyrimSE.pdb types JSON at {} -- run '
                  'scripts/commonlibnvse/parse_pdb_pretty.py against the PDB '
                  'pretty dump first to populate it.'.format(pdb_types_json))

    # --- SkyrimSE.pdb-derived enums (Bethesda internal enums beyond CommonLibSSE) ---
    pdb_enums = {}
    pdb_enums_json = os.path.join(SCRIPT_DIR, 'refs', 'skyrimse_pdb_enums.json')
    if _trusted_pdb_derived(pdb_enums_json, pdb_identity_valid):
        try:
            with open(pdb_enums_json, encoding='utf-8') as f:
                pdb_enums = _json.load(f)
            # Re-tag category from FNV default to Skyrim bucket.
            for cls, en in pdb_enums.items():
                en['category'] = '/CommonLibSSE/PDB'
            print('Loaded {} PDB enums'.format(len(pdb_enums)))
        except Exception as e:
            print('WARNING: SkyrimSE PDB enum load failed: {}: {}'.format(
                type(e).__name__, e))
            pdb_enums = {}

    # --- GOG AE builds from skyrimae.relib (meh321's all-builds ID DB) ---
    # The relib carries per-build ID->RVA maps for every AE release.  We
    # emit re-keyed variants of the AE script for the GOG builds so the
    # GOG Edition binary gets correct offsets instead of Steam 1.6.1170's.
    gog_variants = []
    relib_path = os.path.join(PROJECT_DIR, 'extern',
                              'AddressLibraryDatabase', 'skyrimae.relib')
    if os.path.isfile(relib_path):
        from address_library import load_relib_versions
        rev_1170, ambiguous_1170 = unique_reverse_ids(addr_lib.ae_db)
        if ambiguous_1170:
            print('Rejected {} ambiguous AE 1.6.1170 reverse RVAs'.format(
                len(ambiguous_1170)))
        requested_gog = (
            ('GOG_1_6_1179', (1, 6, 1179, 0)),
            ('GOG_1_6_1170', (1, 6, 1170, 0, 1)),
        )
        relib_databases = load_relib_versions(
            relib_path, [build for _label, build in requested_gog])
        for label, build in requested_gog:
            db = relib_databases.get(build, {})
            if db:
                gog_variants.append((label, db, rev_1170))
                print('Loaded relib build {}: {:,} entries'.format(
                    '.'.join(str(x) for x in build), len(db)))

    for version in ('se', 'ae', '16640', '17104', 'svr'):
        if selected is not None and version not in selected:
            continue
        binding, _artifact = _target_binding(version)
        if binding is None:
            print('\nSKIP {}: no single exact executable; refusing to emit an unbound importer'.format(
                version.upper()))
            continue
        run_version(version, symbols_json, fb_for[version],
                    pdb_structs=pdb_structs, pdb_enums=pdb_enums,
                    gog_variants=gog_variants if version == 'ae' else None,
                    target_manifest=binding)


if __name__ == '__main__':
    main()
