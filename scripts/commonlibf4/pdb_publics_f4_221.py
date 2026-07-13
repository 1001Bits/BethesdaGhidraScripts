"""Load demangled publics from the F4 1.11.221 community symbol PDB.

Source: a community-generated, public-symbol-only
``Fallout4_1_11_221_for_debug.pdb``.  It is not an original compiler debug
database and contains no types, locals, compilands, or source lines.  The raw
third-party PDB is not bundled while its redistribution permission is unknown;
its SHA-256-bound public corpus is checked into
``refs/f4_221_pdb_publics.txt`` with one symbol per line:

    public [0xRVA] DemangledQualifiedName(args)

RVAs are image-relative (Fallout4.exe has image base 0x140000000;
0x02215dc0 above is the offset within the image).  Direct match for
the import script's ``base_addr.add(off)`` symbol-application path.

Aliases at one RVA and display names used at multiple RVAs are quarantined.
Exact-target imports retain mapped data names and executable names, while the
cross-version byte-signature pool is further restricted to linker-owned x64
runtime-function starts.
"""
from __future__ import annotations

import os
import re
import hashlib
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Iterator, List, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REFS_DIR   = os.path.join(SCRIPT_DIR, 'refs')
PUBLICS_TXT = os.path.join(REFS_DIR, 'f4_221_pdb_publics.txt')
IDENTITY_JSON = PUBLICS_TXT + '.identity.json'
CORE_DIR = str(Path(SCRIPT_DIR).parent / 'core')
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)


_LINE_RE = re.compile(
    r'^\s*public\s+'
    r'\[0x(?P<rva>[0-9A-Fa-f]+)\]\s+'
    r'(?P<name>\S.*?)\s*$'
)


def _iter_lines(path: str) -> Iterator[Tuple[int, str]]:
    if not os.path.isfile(path):
        return
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            m = _LINE_RE.match(ln)
            if not m:
                continue
            try:
                rva = int(m.group('rva'), 16)
            except ValueError:
                continue
            if rva == 0:
                continue
            name = m.group('name').strip()
            if not name:
                continue
            yield rva, name


def _looks_like_label(name: str) -> bool:
    """vftable / RTTI / typeinfo / strings are data, not code."""
    return any(h in name for h in (
        'RTTI_', "::`vftable'", "::`RTTI",
        '`vector-deleting-destructor-init',
        'type_info::', '`typeinfo for',
    ))


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_identity(target_pe_path: str, target_sha256: str) -> dict:
    from binary_identity import inspect_pe
    from pdb_identity import read_pe_codeview
    if not os.path.isfile(IDENTITY_JSON):
        raise ValueError('F4 221 PDB-public dump has no identity sidecar')
    with open(IDENTITY_JSON, 'r', encoding='utf-8') as stream:
        identity = json.load(stream)
    if identity.get('schema_version') != 2:
        raise ValueError('unsupported F4 221 PDB-public identity schema')
    if identity.get('artifact') != os.path.basename(PUBLICS_TXT):
        raise ValueError('F4 221 PDB-public identity names another artifact')
    if identity.get('artifact_sha256') != _sha256(PUBLICS_TXT):
        raise ValueError('F4 221 PDB-public dump changed after binding')
    source = identity.get('source')
    pdb = identity.get('pdb')
    counts = identity.get('counts')
    if not isinstance(source, dict) or not isinstance(pdb, dict) \
            or not isinstance(counts, dict):
        raise ValueError('F4 221 PDB-public identity is incomplete')
    source_hash = str(source.get('sha256') or '').lower()
    if (not re.fullmatch(r'[0-9a-f]{64}', source_hash) or
            source.get('kind') != 'community-generated public-symbol-only PDB'):
        raise ValueError('F4 221 PDB source provenance is invalid')
    sha = target_sha256.lower()
    allowed = {
        str(target.get('sha256') or '').lower()
        for target in identity.get('targets', [])
        if isinstance(target, dict)
    }
    if sha not in allowed or _sha256(target_pe_path) != sha:
        raise ValueError('F4 221 PDB-public dump targets another executable')
    manifest = inspect_pe(target_pe_path, include_sha256=False)
    matched_target = next(
        target for target in identity['targets']
        if str(target.get('sha256') or '').lower() == sha)
    if (int(matched_target.get('image_size', -1)) !=
            int(manifest.get('image_size', -2)) or
            int(matched_target.get('machine', -1)) !=
            int(manifest.get('machine', -2))):
        raise ValueError('F4 221 target layout differs from corpus identity')
    codeview = read_pe_codeview(target_pe_path)
    if (codeview.get('guid') != pdb.get('guid') or
            int(codeview.get('age', -1)) != int(pdb.get('age', -2))):
        raise ValueError('F4 221 PE CodeView identity does not match the PDB dump')
    return identity


def _unambiguous_rows(rows: List[Tuple[int, str]]) -> tuple[
        List[Tuple[int, str]], dict]:
    """Return deterministic reciprocal-unique records plus quarantine stats."""
    by_rva = defaultdict(set)
    by_name = defaultdict(set)
    for rva, name in set(rows):
        by_rva[rva].add(name)
        by_name[name].add(rva)
    ambiguous_rvas = {rva for rva, names in by_rva.items() if len(names) > 1}
    ambiguous_names = {
        name for name, rvas in by_name.items() if len(rvas) > 1}
    selected = sorted(
        (rva, name) for rva, name in set(rows)
        if rva not in ambiguous_rvas and name not in ambiguous_names)
    return selected, {
        'same_rva_alias_groups': len(ambiguous_rvas),
        'same_name_multi_rva_groups': len(ambiguous_names),
        'quarantined_records': len(set(rows)) - len(selected),
    }


def _section_for_rva(manifest: dict, rva: int):
    for section in manifest.get('sections', []):
        start = int(section['rva'])
        span = max(int(section['virtual_size']), int(section['raw_size']))
        if start <= rva < start + span:
            return section
    return None


def load_publics(target_pe_path: str, target_sha256: str) -> List[dict]:
    """Return symbols shaped for ``fallback_symbols_json`` (F4 1.11.221).

    Schema mirrors the FNV pdb_naming output: ``{n, t, sig, 221, src}``
    where ``221`` is the per-version RVA key the generated F4_221 import
    script's ``version_key`` lookup expects.
    """
    from binary_identity import inspect_pe
    from pe_unwind import validated_runtime_function_starts
    identity = _validate_identity(target_pe_path, target_sha256)
    rows = list(_iter_lines(PUBLICS_TXT))
    if len(rows) != int(identity['counts'].get('publics', -1)):
        raise ValueError('F4 221 PDB-public count differs from identity')
    selected, quarantine = _unambiguous_rows(rows)
    expected = {
        key: int(identity['counts'].get(key, -1)) for key in quarantine}
    if quarantine != expected:
        raise ValueError('F4 221 PDB ambiguity counts differ from identity')
    manifest = inspect_pe(target_pe_path, include_sha256=False)
    runtime_starts = validated_runtime_function_starts(target_pe_path)
    out: List[dict] = []
    for rva, name in selected:
        section = _section_for_rva(manifest, rva)
        if section is None:
            continue
        executable = bool(section['executable'])
        out.append({
            'n':   name,
            't':   'func' if executable else 'label',
            'sig': '',
            '221': rva,
            'src': 'f4_221_community_pdb',
            'confidence': 'medium',
            'verified_entry': executable and rva in runtime_starts,
            'sections': {'221': section['name']},
            'target_sha256': {'221': target_sha256.lower()},
        })
    return out


def load_executable_name_rvas(target_pe_path: str,
                              target_sha256: str) -> dict[str, int]:
    """Reciprocal-unique, linker-start-safe names for cross-version ports."""
    records = load_publics(target_pe_path, target_sha256)
    return {
        record['n']: int(record['221']) for record in records
        if record['t'] == 'func' and record.get('verified_entry')
    }


if __name__ == '__main__':
    raise SystemExit('Pass an exact F4 1.11.221 PE through the generator; '
                     'detached dump loading is intentionally disabled.')
