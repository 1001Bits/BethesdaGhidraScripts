"""Versioned, binary-bound Starfield vtable shift-map schema."""
from __future__ import annotations

import hashlib
import csv
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Optional, Sequence, Tuple


SCHEMA_VERSION = 3
LAYOUT_SCHEMA_VERSION = 2
ANCHOR_VERSION = (1, 16, 236, 0)


def normalize_version(version: Sequence[int]) -> Tuple[int, int, int, int]:
    parts = tuple(int(x) for x in version) + (0, 0, 0, 0)
    return parts[:4]


def version_token(version: Sequence[int]) -> str:
    return '-'.join(str(x) for x in normalize_version(version))


def map_path(refs_dir: os.PathLike, version: Sequence[int]) -> Path:
    return Path(refs_dir) / 'shift_sf_{}.json'.format(version_token(version))


def file_sha256(path: os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def layout_identity_path(layout_path: os.PathLike) -> Path:
    return Path(str(layout_path) + '.identity.json')


def _write_json_atomic(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp',
                                    dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def write_layout_identity(layout_path: os.PathLike,
                          target_version: Sequence[int],
                          target_sha256: str,
                          program_path: str = '',
                          versionlib_path: Optional[os.PathLike] = None,
                          enumeration_method: str = '',
                          function_names_included: bool = False,
                          fingerprint_mode: str = 'none') -> dict:
    """Bind a layout artifact to the exact executable that produced it."""
    layout_path = Path(layout_path)
    if not layout_path.is_file():
        raise ValueError('cannot bind missing SF layout {}'.format(layout_path))
    sha = target_sha256.lower()
    if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('invalid target SHA-256 for SF layout')
    doc = {
        'schema_version': LAYOUT_SCHEMA_VERSION,
        'artifact': layout_path.name,
        'layout_sha256': file_sha256(layout_path),
        'target_version': list(normalize_version(target_version)),
        'target_sha256': sha,
        'program_path': program_path,
        'function_names_included': bool(function_names_included),
        'fingerprint_mode': str(fingerprint_mode),
    }
    if versionlib_path is not None:
        versionlib_path = Path(versionlib_path)
        if not versionlib_path.is_file():
            raise ValueError('missing layout version library {}'.format(
                versionlib_path))
        doc['versionlib'] = versionlib_path.name
        doc['versionlib_sha256'] = file_sha256(versionlib_path)
    if enumeration_method:
        doc['enumeration_method'] = str(enumeration_method)
    _write_json_atomic(layout_identity_path(layout_path), doc)
    return doc


def _layout_evidence_columns(layout_path: Path) -> Tuple[bool, bool]:
    opener = gzip.open if str(layout_path).endswith('.gz') else open
    any_name = False
    any_fingerprint = False
    with opener(layout_path, 'rt', encoding='utf-8', newline='') as fh:
        reader = csv.DictReader(fh)
        fields = set(reader.fieldnames or [])
        if not {'func_name', 'fingerprint'} <= fields:
            raise ValueError('SF layout lacks name/fingerprint evidence columns')
        for row in reader:
            any_name = any_name or bool((row.get('func_name') or '').strip())
            any_fingerprint = any_fingerprint or bool(
                (row.get('fingerprint') or '').strip())
            if any_name and any_fingerprint:
                break
    return any_name, any_fingerprint


def load_layout_identity(layout_path: os.PathLike,
                         target_version: Sequence[int],
                         target_sha256: Optional[str] = None,
                         versionlib_path: Optional[os.PathLike] = None,
                         require_function_names_included: Optional[bool] = None,
                         require_fingerprint_mode: Optional[str] = None) -> dict:
    """Validate a layout's sidecar, content hash, version, and optional PE."""
    layout_path = Path(layout_path)
    identity_path = layout_identity_path(layout_path)
    with identity_path.open('r', encoding='utf-8') as fh:
        doc = json.load(fh)
    if doc.get('schema_version') != LAYOUT_SCHEMA_VERSION:
        raise ValueError('unsupported/missing SF layout identity schema')
    if doc.get('artifact') != layout_path.name:
        raise ValueError('SF layout identity names a different artifact')
    if doc.get('target_version') != list(normalize_version(target_version)):
        raise ValueError('SF layout identity has the wrong target version')
    bound_sha = str(doc.get('target_sha256', '')).lower()
    if (len(bound_sha) != 64 or
            any(character not in '0123456789abcdef' for character in bound_sha)):
        raise ValueError('SF layout identity has no target SHA-256')
    if target_sha256 is not None and bound_sha != target_sha256.lower():
        raise ValueError('SF layout was produced from another executable SHA-256')
    if not layout_path.is_file() or doc.get('layout_sha256') != file_sha256(layout_path):
        raise ValueError('SF layout content does not match its identity sidecar')
    if versionlib_path is not None:
        versionlib_path = Path(versionlib_path)
        if not versionlib_path.is_file():
            raise ValueError('exact SF layout version library is missing')
        if (doc.get('versionlib') != versionlib_path.name or
                doc.get('versionlib_sha256') != file_sha256(versionlib_path)):
            raise ValueError('SF layout enumeration version library changed')
    names_included = doc.get('function_names_included')
    fingerprint_mode = doc.get('fingerprint_mode')
    if not isinstance(names_included, bool):
        raise ValueError('SF layout identity has no function-name policy')
    if fingerprint_mode not in ('none', 'raw-bytes-32'):
        raise ValueError('SF layout identity has an invalid fingerprint mode')
    if (require_function_names_included is not None and
            names_included is not require_function_names_included):
        raise ValueError('SF layout function-name policy is unsafe for this role')
    if (require_fingerprint_mode is not None and
            fingerprint_mode != require_fingerprint_mode):
        raise ValueError('SF layout fingerprint policy is unsafe for this role')
    if (require_function_names_included is not None or
            require_fingerprint_mode is not None):
        any_name, any_fingerprint = _layout_evidence_columns(layout_path)
        if require_function_names_included is True and not any_name:
            raise ValueError('anchor SF layout contains no function-name evidence')
        if require_function_names_included is False and any_name:
            raise ValueError(
                'non-anchor SF layout contains self-confirming function names')
        if require_fingerprint_mode == 'raw-bytes-32' and not any_fingerprint:
            raise ValueError('SF layout contains no fingerprint evidence')
    return doc


def _rebuild_semantic_map(reference_layout: os.PathLike,
                          target_layout: os.PathLike,
                          target_version: Sequence[int]) -> dict:
    """Return the deterministic matcher result for two exact layouts."""
    core_dir = Path(__file__).resolve().parent.parent / 'core'
    if str(core_dir) not in sys.path:
        sys.path.insert(0, str(core_dir))
    from vtable_layout import load_csv
    from vtable_matcher import build_shift_map
    reference_label = 'sf'
    target_label = 'sf_' + version_token(target_version).replace('-', '_')
    return build_shift_map(
        load_csv(str(reference_layout), reference_label),
        load_csv(str(target_layout), target_label)).to_json()


def _require_semantic_match(doc: dict, expected: dict) -> None:
    for key in ('reference', 'target', 'classes', 'vtables'):
        if doc.get(key) != expected.get(key):
            raise ValueError(
                'SF shift map semantic content does not match bound layouts')


def load_validated(path: os.PathLike, target_version: Sequence[int],
                   target_sha256: str, reference_layout: Optional[os.PathLike] = None,
                   target_layout: Optional[os.PathLike] = None,
                   reference_versionlib: Optional[os.PathLike] = None,
                   target_versionlib: Optional[os.PathLike] = None) -> dict:
    """Load a shift map only when all available target identity fields match."""
    with open(path, 'r', encoding='utf-8') as fh:
        doc = json.load(fh)
    if doc.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('unsupported/missing SF shift schema in {}'.format(path))
    expected_version = list(normalize_version(target_version))
    if doc.get('reference_version') != list(ANCHOR_VERSION):
        raise ValueError('SF shift map has the wrong reference version')
    if doc.get('target_version') != expected_version:
        raise ValueError('SF shift target version {} != {}'.format(
            doc.get('target_version'), expected_version))
    if doc.get('target_sha256', '').lower() != target_sha256.lower():
        raise ValueError('SF shift map target SHA-256 does not match the executable')
    if not isinstance(doc.get('classes'), dict):
        raise ValueError('SF shift map contains no classes object')
    if reference_layout is not None:
        reference_identity = load_layout_identity(
            reference_layout, ANCHOR_VERSION,
            versionlib_path=reference_versionlib,
            require_function_names_included=True,
            require_fingerprint_mode='raw-bytes-32')
        actual = file_sha256(reference_layout)
        if doc.get('reference_layout_sha256') != actual:
            raise ValueError('SF reference vtable layout changed after map creation')
        if doc.get('reference_sha256') != reference_identity.get('target_sha256'):
            raise ValueError('SF shift map reference executable provenance changed')
    if target_layout is not None:
        load_layout_identity(
            target_layout, target_version, target_sha256,
            versionlib_path=target_versionlib,
            require_function_names_included=False,
            require_fingerprint_mode='raw-bytes-32')
        actual = file_sha256(target_layout)
        if doc.get('target_layout_sha256') != actual:
            raise ValueError('SF target vtable layout changed after map creation')
    # The layout hashes prove which observations the map claims to derive
    # from, but do not prove that the stored mapping is actually their
    # deterministic diff.  Rebuild the semantic map before accepting it so
    # an edited/high-coverage JSON cannot launder arbitrary slot mappings by
    # retaining the old identity fields.
    if reference_layout is not None and target_layout is not None:
        _require_semantic_match(
            doc, _rebuild_semantic_map(
                reference_layout, target_layout, target_version))
    return doc


def bind_generated_map(path: os.PathLike, target_version: Sequence[int],
                       target_sha256: str, reference_layout: os.PathLike,
                       target_layout: os.PathLike) -> dict:
    """Add target identity to build_shift_map.py output and replace atomically."""
    path = Path(path)
    with path.open('r', encoding='utf-8') as fh:
        doc = json.load(fh)
    if not isinstance(doc.get('classes'), dict):
        raise ValueError('generated shift map contains no classes object')
    _require_semantic_match(
        doc, _rebuild_semantic_map(
            reference_layout, target_layout, target_version))
    maps = doc.get('vtables') if isinstance(doc.get('vtables'), dict) \
        else doc['classes']
    matched = sum(len(item.get('ref_to_target', {}))
                  for item in maps.values() if isinstance(item, dict))
    unmatched = sum(len(item.get('unmatched_ref_slots', []))
                    for item in maps.values() if isinstance(item, dict))
    total = matched + unmatched
    critical = {'Actor', 'TESForm', 'PlayerCharacter'}
    missing_critical = [name for name in critical
                        if not isinstance(doc['classes'].get(name), dict)
                        or not doc['classes'][name].get('ref_to_target')]
    if (matched < 10000 or total <= 0 or matched / float(total) < 0.25 or
            missing_critical):
        raise ValueError(
            'generated SF shift map failed coverage validation: '
            'matched={} total={} missing critical={}'.format(
                matched, total, sorted(missing_critical)))
    reference_identity = load_layout_identity(
        reference_layout, ANCHOR_VERSION,
        require_function_names_included=True,
        require_fingerprint_mode='raw-bytes-32')
    load_layout_identity(
        target_layout, target_version, target_sha256,
        require_function_names_included=False,
        require_fingerprint_mode='raw-bytes-32')
    doc.update({
        'schema_version': SCHEMA_VERSION,
        'reference': 'sf',
        'target': 'sf_' + version_token(target_version).replace('-', '_'),
        'reference_version': list(ANCHOR_VERSION),
        'target_version': list(normalize_version(target_version)),
        'target_sha256': target_sha256.lower(),
        'reference_sha256': reference_identity['target_sha256'],
        'reference_layout_sha256': file_sha256(reference_layout),
        'target_layout_sha256': file_sha256(target_layout),
    })
    _write_json_atomic(path, doc)
    return doc
