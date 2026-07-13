#!/usr/bin/env python3
"""Versioned, target-bound schema for Havok record layouts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = 'havok-layouts-v2'

# Reviewed metadata for committed pre-schema files.  This compatibility map
# is intentionally filename-specific; arbitrary legacy JSON is rejected.
LEGACY_MANIFESTS = {
    'havok_layouts.json': {
        'sha256': '6e44f16c9bef2e26bedc55c8586f5f63817a238e25bfaabfa28c3aba44c5a418',
        'pointer_size': 8, 'architecture': 'x64', 'abi': 'msvc',
        'havok_version': '2014', 'targets': ['Fallout4.exe'],
        'source': 'Havok 2014 SDK record-layout dump',
    },
    'havok_layouts_f4_planck.json': {
        'sha256': 'c6535089f41aa66981cea4cffb3e9ea4e6389fecf268bc85e8a789c6a0a08422',
        'pointer_size': 8, 'architecture': 'x64', 'abi': 'msvc',
        'havok_version': '2014', 'targets': ['Fallout4.exe'],
        'source': 'Fallout 4 Planck/Havok SDK layouts',
    },
    'havok_layouts_fnv_710_full.json': {
        'sha256': 'd506a683eea49bce7e115c25e8be75a4f8bb60b54d583030304d106e694f4bbf',
        'pointer_size': 4, 'architecture': 'x86', 'abi': 'msvc',
        'havok_version': '7.1.0', 'targets': ['FalloutNV.exe'],
        'source': 'FNV Havok 7.1 reflection/layout corpus',
    },
    'havok_layouts_sf_2018.json': {
        'sha256': 'd5852951defc128a80f26230eec284ca96c07c2d249f4fd1d3f7540d15a516e3',
        'pointer_size': 8, 'architecture': 'x64', 'abi': 'msvc',
        'havok_version': '2018', 'targets': ['Starfield.exe'],
        'source': 'Starfield Havok 2018 layouts',
    },
    'havok_layouts_skyrim_2010.json': {
        'sha256': '935eefdfaa5f595d44da44c4a8e8ffa235d9ea6591baba39f2450f6a0436bdb0',
        'pointer_size': 8, 'architecture': 'x64', 'abi': 'msvc',
        'havok_version': '2010', 'targets': ['SkyrimSE.exe', 'SkyrimVR.exe'],
        'source': 'Skyrim Havok 2010 layouts',
    },
    'havok_layouts_6_6_x86.json': {
        'sha256': 'eb7857e295ec5662b84f7a185434336b238899b9fed6aea6979b69f4c046bf6f',
        'pointer_size': 4, 'architecture': 'x86', 'abi': 'msvc',
        'havok_version': '6.6', 'targets': [],
        'source': 'generic Havok 6.6 SDK layouts (target must be declared)',
    },
}


def make_document(records, *, pointer_size, havok_version, targets,
                  source, architecture=None, abi='msvc', **extra):
    meta = {
        'pointer_size': int(pointer_size),
        'architecture': architecture or ('x64' if int(pointer_size) == 8 else 'x86'),
        'abi': abi,
        'havok_version': str(havok_version),
        'targets': list(targets),
        'source': str(source),
    }
    meta.update(extra)
    return {'schema': SCHEMA, 'metadata': meta, 'records': records}


def load_document(path):
    path = Path(path)
    content = path.read_bytes()
    raw = json.loads(content.decode('utf-8-sig'))
    if isinstance(raw, dict) and raw.get('schema') == SCHEMA:
        meta = raw.get('metadata') or {}
        records = raw.get('records') or {}
    else:
        meta = LEGACY_MANIFESTS.get(path.name)
        if meta is None:
            raise ValueError('legacy Havok layout has no reviewed manifest: %s' % path)
        meta = dict(meta)
        # Hash normalized JSON semantics so Git's LF/CRLF checkout policy
        # cannot invalidate a reviewed corpus on another platform.
        canonical = json.dumps(
            raw, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')
        actual_sha256 = hashlib.sha256(canonical).hexdigest()
        if actual_sha256 != meta.get('sha256'):
            raise ValueError(
                'legacy Havok layout content hash mismatch: %s' % path)
        records = raw
    if not isinstance(records, dict):
        raise ValueError('Havok records must be a JSON object')
    for required in ('pointer_size', 'architecture', 'abi', 'havok_version',
                     'targets', 'source'):
        if required not in meta:
            raise ValueError('Havok metadata is missing %s' % required)
    if int(meta['pointer_size']) not in (4, 8):
        raise ValueError('invalid Havok pointer_size %r' % meta['pointer_size'])
    return records, meta


def _program_names(program):
    names = {str(program.getName()).lower()}
    try:
        names.add(Path(str(program.getExecutablePath())).name.lower())
    except Exception:
        pass
    return names


def validate_program(program, metadata):
    ptr = int(program.getDefaultPointerSize())
    expected = int(metadata['pointer_size'])
    if ptr != expected:
        raise ValueError('layout is %d-bit but program is %d-bit' %
                         (expected * 8, ptr * 8))
    if str(metadata.get('abi', '')).lower() != 'msvc':
        raise ValueError('only MSVC Havok layouts are supported')
    targets = [str(t).lower() for t in metadata.get('targets', [])]
    if not targets:
        raise ValueError('layout metadata has no target executable allowlist')
    names = _program_names(program)
    if not names.intersection(targets):
        raise ValueError('layout targets %s, program is %s' %
                         (', '.join(metadata['targets']), ', '.join(sorted(names))))
