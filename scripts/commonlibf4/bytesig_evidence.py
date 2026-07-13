"""Identity-bound persisted byte-signature evidence for Fallout 4."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path


SCHEMA_VERSION = 1
FIELDS = ('target_rva', 'name', 'source_tag', 'source_sha256', 'source_rva')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _identity_path(path: Path) -> Path:
    return Path(str(path) + '.identity.json')


def _manifest(manifest: dict, role: str) -> dict:
    if not isinstance(manifest, dict):
        raise ValueError('{} manifest is required'.format(role))
    sha = str(manifest.get('sha256', '')).lower()
    if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('{} manifest has no valid SHA-256'.format(role))
    result = dict(manifest)
    result['sha256'] = sha
    return result


# ``load_validated`` reads only ``sha256`` back from the bound manifests.  A full
# ``inspect_pe`` payload carries ``function_starts`` (~300k RVAs) that nothing
# reads, bloating each sidecar by megabytes, so persist a slim projection.
_HEAVY_MANIFEST_KEYS = ('function_starts',)


def _slim_manifest(manifest: dict) -> dict:
    slim = dict(manifest)
    for key in _HEAVY_MANIFEST_KEYS:
        slim.pop(key, None)
    return slim


def _read_rows(path: Path):
    with path.open('r', encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError('legacy/unrecognized byte-signature CSV schema')
        rows = []
        for raw in reader:
            try:
                target_rva = int(raw['target_rva'], 0)
                source_rva = int(raw['source_rva'], 0)
            except (TypeError, ValueError):
                raise ValueError('invalid RVA in byte-signature evidence')
            source_sha = str(raw.get('source_sha256', '')).lower()
            name = str(raw.get('name', '')).strip()
            if target_rva <= 0 or source_rva <= 0 or not name:
                raise ValueError('incomplete byte-signature evidence row')
            rows.append({
                'target_rva': target_rva,
                'name': name,
                'source_tag': str(raw.get('source_tag', '')),
                'source_sha256': source_sha,
                'source_rva': source_rva,
            })
    return rows


def _reciprocal(rows):
    """Drop every name/target claim participating in a contradiction."""
    targets = defaultdict(set)
    names = defaultdict(set)
    for row in rows:
        targets[row['target_rva']].add(row['name'])
        names[row['name']].add(row['target_rva'])
    accepted = []
    seen = set()
    for row in rows:
        if len(targets[row['target_rva']]) != 1 or len(names[row['name']]) != 1:
            continue
        key = (row['target_rva'], row['name'], row['source_sha256'],
               row['source_rva'])
        if key in seen:
            continue
        seen.add(key)
        accepted.append(row)
    return accepted


def load_validated(path, target_manifest: dict):
    """Load only evidence bound to ``target_manifest`` and its own bytes."""
    path = Path(path)
    target = _manifest(target_manifest, 'target')
    identity_path = _identity_path(path)
    with identity_path.open('r', encoding='utf-8') as stream:
        identity = json.load(stream)
    if identity.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('legacy/unbound byte-signature evidence')
    if identity.get('artifact') != path.name:
        raise ValueError('byte-signature identity names another artifact')
    bound_target = _manifest(identity.get('target'), 'bound target')
    if bound_target['sha256'] != target['sha256']:
        raise ValueError('byte-signature evidence targets another executable')
    if not path.is_file() or identity.get('artifact_sha256') != _sha256(path):
        raise ValueError('byte-signature CSV content changed after binding')
    sources = identity.get('sources')
    if not isinstance(sources, dict) or not sources:
        raise ValueError('byte-signature evidence has no source identities')
    normalized_sources = {
        sha.lower(): _manifest(manifest, 'source')
        for sha, manifest in sources.items()
    }
    rows = _read_rows(path)
    for row in rows:
        source_sha = row['source_sha256']
        if source_sha not in normalized_sources:
            raise ValueError('byte-signature row has an unbound source')
        if normalized_sources[source_sha]['sha256'] != source_sha:
            raise ValueError('byte-signature source key/manifest mismatch')
    accepted = _reciprocal(rows)
    if len(accepted) != len(rows):
        raise ValueError('persisted byte-signature evidence is not reciprocal')
    return rows, identity


def _atomic_json(path: Path, value: dict) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp',
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def persist(path, ported, source_tag: str, source_manifest: dict,
            target_manifest: dict, source_rvas: dict | None = None):
    """Persist proposals, replacing stale targets and reconciling all sources."""
    path = Path(path)
    source = _manifest(source_manifest, 'source')
    target = _manifest(target_manifest, 'target')
    source_rvas = source_rvas or {}
    rows = []
    sources = {}
    try:
        rows, identity = load_validated(path, target)
        sources.update(identity.get('sources', {}))
    except (OSError, ValueError, json.JSONDecodeError):
        # Missing, legacy, corrupt, or another target identity: it must not be
        # unioned into evidence for the current executable.
        rows = []
    sources[source['sha256']] = source
    # A rerun of the same exact source is a replacement, not an append-only
    # union.  Matcher improvements must be able to retract an old proposal.
    rows = [row for row in rows
            if row['source_sha256'] != source['sha256']]

    for name, target_rva in ported:
        source_rva = source_rvas.get(name)
        if not source_rva:
            continue
        rows.append({
            'target_rva': int(target_rva),
            'name': name,
            'source_tag': source_tag,
            'source_sha256': source['sha256'],
            'source_rva': int(source_rva),
        })
    rows = _reciprocal(rows)

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp',
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            for row in sorted(rows, key=lambda item: (
                    item['target_rva'], item['name'], item['source_sha256'])):
                encoded = dict(row)
                encoded['target_rva'] = '0x{:08X}'.format(row['target_rva'])
                encoded['source_rva'] = '0x{:08X}'.format(row['source_rva'])
                writer.writerow(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    identity = {
        'schema_version': SCHEMA_VERSION,
        'artifact': path.name,
        'artifact_sha256': _sha256(path),
        'row_count': len(rows),
        'target': _slim_manifest(target),
        'sources': {sha: _slim_manifest(m) for sha, m in sources.items()},
    }
    _atomic_json(_identity_path(path), identity)
    return rows
