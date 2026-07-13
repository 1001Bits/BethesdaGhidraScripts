#!/usr/bin/env python3
"""Portable input/tool paths for optional FNV research artifacts.

Nothing in the generated pipeline may silently depend on one developer's
drive layout.  Set ``BGS_FNV_ARTIFACTS`` to a directory containing extracted
PDB/PE intermediates, or place them under ``artifacts/fnv`` in the repository.
Individual executables can be overridden with the documented environment
variables below.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
from pathlib import Path
from typing import Iterable, Optional

from addressing import VTableRecord, load_vtable_records

SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent.parent
ARTIFACTS = Path(os.environ.get('BGS_FNV_ARTIFACTS',
                                str(REPO / 'artifacts' / 'fnv')))


def artifact(name: str) -> Path:
    return ARTIFACTS / name


def env_path(variable: str, default: Path) -> Path:
    return Path(os.environ.get(variable, str(default)))


PC_EXE = env_path('BGS_FNV_EXE', REPO / 'exes' / 'fnv' / 'og' / 'FalloutNV.exe')
XBOX_EXE = env_path('BGS_FNV_XBOX_EXE', artifact('Fallout_Debug.exe'))

FNV_VERSION = [1, 4, 0, 525]
FNV_IMAGE_BASE = 0x00400000
FNV_MAX_IMAGE_SIZE = 0x02000000

# These two reviewed corpora describe the exact PC memory layout consumed by
# pdb_naming.py: 3,269 distinct vtables and 54,346 slot pointers.  No reviewed
# FalloutNV.exe file hash is stored in this repository, and requiring one
# would unnecessarily reject harmless SteamStub/header-only transformations.
# Attesting every pointer instead proves the property the fixed-RVA corpus
# actually needs: that the analyzed image has the same mapped code/data
# layout.  The normalized digest also protects class/subobject identities and
# is independent of checkout line endings or comments.
FNV_LAYOUT_CORPUS = (
    SCRIPT_DIR / 'refs' / 'fnv_pc_vtables.txt',
    SCRIPT_DIR / 'refs' / 'fnv_pc_vtables_rtti_extra.txt',
)
FNV_LAYOUT_TABLE_COUNT = 3269
FNV_LAYOUT_SLOT_COUNT = 54346
FNV_LAYOUT_CORPUS_SHA256 = (
    '233f26d57ecc18171bf0856593e57bf4b084dee3688be2c20f055d4f34bfb833')


class FNVLayoutError(ValueError):
    """The target PE does not match the reviewed fixed-address corpus."""


def _normalized_vtable_digest(records: Iterable[VTableRecord]) -> str:
    payload = [{
        'source': record.source,
        'table_rva': record.table_rva,
        'class_name': record.class_name,
        'declared_slots': record.declared_slots,
        'occurrence': record.occurrence,
        'subobject': record.subobject,
        'slots': record.slots,
    } for record in records]
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True,
        separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _section_for_span(manifest, rva: int, size: int, *, physical=False):
    if rva < 0 or size <= 0:
        return None
    for section in manifest.get('sections', []):
        start = int(section.get('rva', 0))
        span = (int(section.get('raw_size', 0)) if physical else
                max(int(section.get('virtual_size', 0)),
                    int(section.get('raw_size', 0))))
        if start <= rva and rva + size <= start + span:
            return section
    return None


def attest_pc_corpus_layout(executable: Path, manifest=None,
                            records: Optional[Iterable[VTableRecord]] = None,
                            expected_tables: int = FNV_LAYOUT_TABLE_COUNT,
                            expected_slots: int = FNV_LAYOUT_SLOT_COUNT,
                            expected_digest: Optional[str] =
                            FNV_LAYOUT_CORPUS_SHA256):
    """Prove that *executable* has the PC layout used by the FNV corpus.

    Every reviewed vtable slot is checked against the file-backed PE bytes.
    This rejects a same-version GOG/no-CD/hotfix layout before any fixed RVA is
    embedded in a generated importer, while accepting an identity-bound
    Steamless artifact whose mapped image is unchanged.

    ``manifest`` and ``records`` are injectable for focused synthetic tests.
    Production callers omit them and receive the full reviewed-corpus gate.
    The validated manifest is returned for reuse by the caller.
    """
    executable = Path(executable)
    if manifest is None:
        import sys
        core = REPO / 'scripts' / 'core'
        if str(core) not in sys.path:
            sys.path.insert(0, str(core))
        from binary_identity import inspect_pe
        manifest = inspect_pe(str(executable))
    _validate_fnv_manifest(manifest, 'corpus target')

    if records is None:
        try:
            records = load_vtable_records(FNV_LAYOUT_CORPUS)
        except (OSError, ValueError) as exc:
            raise FNVLayoutError(
                'reviewed FNV vtable corpus is missing or malformed: {}'.format(
                    exc)) from exc
    records = list(records)
    slot_count = sum(len(record.slots) for record in records)
    if len(records) != expected_tables or slot_count != expected_slots:
        raise FNVLayoutError(
            'reviewed FNV layout coverage changed: {} tables/{} slots; '
            'expected {}/{}'.format(
                len(records), slot_count, expected_tables, expected_slots))
    if expected_digest is not None:
        actual_digest = _normalized_vtable_digest(records)
        if actual_digest.lower() != expected_digest.lower():
            raise FNVLayoutError(
                'reviewed FNV vtable corpus identity changed: {} != {}'.format(
                    actual_digest, expected_digest))

    try:
        blob = executable.read_bytes()
    except OSError as exc:
        raise FNVLayoutError(
            'cannot read FNV corpus target {}: {}'.format(executable, exc)) from exc

    image_base = int(manifest['image_base'])
    seen_tables = set()
    seen_slots = {}
    checked = 0
    for record in records:
        if record.table_rva in seen_tables:
            raise FNVLayoutError(
                'duplicate physical vtable RVA 0x{:X}'.format(record.table_rva))
        seen_tables.add(record.table_rva)
        indices = [int(slot) for slot, _rva in record.slots]
        if (record.declared_slots != len(record.slots) or
                indices != list(range(record.declared_slots))):
            raise FNVLayoutError(
                '{} has non-contiguous or incomplete slots'.format(
                    record.identity))

        table_size = record.declared_slots * 4
        section = _section_for_span(
            manifest, int(record.table_rva), table_size, physical=True)
        if (section is None or not section.get('readable') or
                section.get('executable')):
            raise FNVLayoutError(
                '{} is not fully file-backed readable data'.format(
                    record.identity))
        raw_offset = (int(section['raw_offset']) +
                      int(record.table_rva) - int(section['rva']))
        if raw_offset < 0 or raw_offset + table_size > len(blob):
            raise FNVLayoutError(
                '{} extends beyond the target file'.format(record.identity))

        for slot, function_rva in record.slots:
            key = (int(record.table_rva), int(slot))
            prior = seen_slots.get(key)
            if prior is not None and prior != int(function_rva):
                raise FNVLayoutError(
                    'conflicting corpus claims at vtable RVA 0x{:X} slot {}'.format(
                        record.table_rva, slot))
            seen_slots[key] = int(function_rva)
            code = _section_for_span(
                manifest, int(function_rva), 1, physical=True)
            if code is None or not code.get('executable'):
                raise FNVLayoutError(
                    '{} slot {} targets non-executable RVA 0x{:X}'.format(
                        record.identity, slot, function_rva))
            actual = struct.unpack_from('<I', blob, raw_offset + int(slot) * 4)[0]
            expected = image_base + int(function_rva)
            if actual != expected:
                raise FNVLayoutError(
                    '{} slot {} pointer mismatch: file 0x{:08X}, reviewed '
                    '0x{:08X}'.format(record.identity, slot, actual, expected))
            checked += 1

    if checked != expected_slots or len(seen_slots) != expected_slots:
        raise FNVLayoutError(
            'FNV layout attestation checked {} unique slots; expected {}'.format(
                len(seen_slots), expected_slots))
    return manifest


def executable(variable: str, name: str, repo_relative: str = '') -> Path:
    configured = os.environ.get(variable)
    if configured:
        return Path(configured)
    found = shutil.which(name)
    if found:
        return Path(found)
    if repo_relative:
        return REPO / repo_relative
    return Path(name)


def require_file(path: Path, description: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(
            '%s not found at %s (set BGS_FNV_ARTIFACTS or the relevant '
            'BGS_FNV_* environment variable)' % (description, path))
    return path


def _validate_fnv_manifest(manifest, description='target'):
    """Reject a semantically wrong PE before binding fixed xNVSE VAs to it."""
    reasons = []
    if int(manifest.get('machine', 0)) != 0x14C:
        reasons.append('machine is not i386')
    if int(manifest.get('pointer_size', 0)) != 4:
        reasons.append('pointer size is not 4')
    if int(manifest.get('image_base', 0)) != FNV_IMAGE_BASE:
        reasons.append('image base is not 0x%X' % FNV_IMAGE_BASE)
    image_size = int(manifest.get('image_size', 0))
    if not (0x1000 < image_size <= FNV_MAX_IMAGE_SIZE):
        reasons.append('image size 0x%X is outside the reviewed bound' % image_size)
    if list(manifest.get('file_version') or []) != FNV_VERSION:
        reasons.append('file version is not 1.4.0.525')
    if reasons:
        raise ValueError('%s is not the reviewed FalloutNV.exe 1.4.0.525: %s' %
                         (description, '; '.join(reasons)))
    return manifest


def resolve_pc_target_binding():
    """Return ``(analyzed_path, lineage_sidecar_or_none)`` for generation.

    A fresh Steamless sidecar wins over the original PE.  Freshness is an
    exact source-manifest comparison, never filename/mtime inference.
    """
    original = require_file(PC_EXE, 'exact FalloutNV.exe target binary')
    import sys
    core = REPO / 'scripts' / 'core'
    if str(core) not in sys.path:
        sys.path.insert(0, str(core))
    from binary_identity import artifact_is_fresh, inspect_pe, read_manifest
    _validate_fnv_manifest(inspect_pe(str(original)), 'source executable')
    fresh = []
    for candidate in sorted(original.parent.glob(original.stem + '*unpacked*')):
        if not candidate.is_file() or candidate.name.endswith('.identity.json'):
            continue
        sidecar = Path(str(candidate) + '.identity.json')
        if sidecar.is_file() and artifact_is_fresh(str(original), str(candidate),
                                                   str(sidecar)):
            lineage = read_manifest(str(sidecar))
            _validate_fnv_manifest(lineage.get('artifact') or {},
                                   'Steamless artifact')
            fresh.append((candidate, lineage))
    if len(fresh) > 1:
        raise RuntimeError('multiple fresh Steamless artifacts for {}: {}'.format(
            original, ', '.join(str(path.name) for path, _ in fresh)))
    if fresh:
        analyzed, lineage = fresh[0]
        attest_pc_corpus_layout(analyzed, lineage.get('artifact') or None)
        return analyzed, lineage
    attest_pc_corpus_layout(original)
    return original, None
