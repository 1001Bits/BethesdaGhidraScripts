"""Skyrim SE / AE / VR address library database loader.

SE (1.5.97) and AE (1.6.1170) ship as compressed meh321 V1/V2 files;
AE (1.7.104) uses the flat-indexed V5 format.  VR (1.4.15) ships as a flat
CSV with a metadata row.  All
three share the SE-derived ID namespace, so a single ID can be looked up
across all three DBs.
"""

from __future__ import annotations

import csv
import os
import struct
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
from pe_version import get_pe_version  # noqa: E402


def _read_exact(f, size: int, context: str) -> bytes:
    if size < 0:
        raise ValueError('negative read size in {}'.format(context))
    value = f.read(size)
    if len(value) != size:
        raise ValueError('truncated relib while reading {}'.format(context))
    return value


def _read_dotnet_string(f, file_size: int, context: str) -> str:
    """Read a bounded .NET BinaryWriter 7-bit length-prefixed string."""
    length = 0
    for index in range(5):
        byte = _read_exact(f, 1, context + ' length')[0]
        if index == 4 and byte > 0x0F:
            raise ValueError('overflowing relib string length in {}'.format(context))
        length |= (byte & 0x7F) << (index * 7)
        if not (byte & 0x80):
            break
    else:
        raise ValueError('unterminated relib string length in {}'.format(context))
    remaining = file_size - f.tell()
    if length > remaining or length > 1024 * 1024:
        raise ValueError('invalid relib string length in {}'.format(context))
    try:
        return _read_exact(f, length, context).decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('invalid UTF-8 relib string in {}'.format(context)) from exc


def _parse_relib(relib_path: str, requested_versions=None):
    """Validate an entire relib and retain only requested version maps."""
    if not os.path.exists(relib_path):
        return [], {}
    requested = {tuple(version) for version in (requested_versions or ())}
    retained = {}
    versions = []
    seen_versions = set()
    file_size = os.path.getsize(relib_path)
    with open(relib_path, 'rb') as f:
        fmt_version = struct.unpack(
            '<i', _read_exact(f, 4, 'format version'))[0]
        if fmt_version not in (1, 2):
            raise ValueError('unsupported relib format {}'.format(fmt_version))
        high_vid = struct.unpack('<Q', _read_exact(f, 8, 'high ID'))[0]
        if high_vid <= 0:
            raise ValueError('relib has an invalid high ID')
        pointer_size = struct.unpack(
            '<i', _read_exact(f, 4, 'pointer size'))[0]
        if pointer_size != 8:
            raise ValueError(
                'Skyrim relib pointer size is {}'.format(pointer_size))

        has_module = _read_exact(f, 1, 'module flag')[0]
        if has_module not in (0, 1):
            raise ValueError('invalid relib module flag')
        if has_module:
            _read_dotnet_string(f, file_size, 'module name')

        num_versions = struct.unpack(
            '<i', _read_exact(f, 4, 'version count'))[0]
        if num_versions < 0 or num_versions > 10000:
            raise ValueError('invalid relib version count {}'.format(num_versions))

        for version_index in range(num_versions):
            context = 'version {}'.format(version_index)
            n_components = struct.unpack(
                '<i', _read_exact(f, 4, context + ' component count'))[0]
            if n_components <= 0 or n_components > 16:
                raise ValueError(
                    'invalid relib version component count {}'.format(n_components))
            if n_components * 4 > file_size - f.tell():
                raise ValueError('truncated relib version components')
            version = tuple(struct.unpack(
                '<{}I'.format(n_components),
                _read_exact(f, n_components * 4, context + ' components')))
            if version in seen_versions:
                raise ValueError('duplicate relib version {}'.format(version))
            seen_versions.add(version)
            versions.append(version)

            has_overwrite = _read_exact(f, 1, context + ' overwrite flag')[0]
            if has_overwrite not in (0, 1):
                raise ValueError('invalid relib module-overwrite flag')
            if has_overwrite:
                _read_dotnet_string(f, file_size, context + ' module overwrite')

            base_address = struct.unpack(
                '<q', _read_exact(f, 8, context + ' image base'))[0]
            if base_address <= 0:
                raise ValueError('invalid relib image base {}'.format(base_address))
            value_count = struct.unpack(
                '<i', _read_exact(f, 4, context + ' value count'))[0]
            if value_count < 0 or value_count > (file_size - f.tell()) // 12:
                raise ValueError('invalid relib value count {}'.format(value_count))

            keep = version in requested
            database = {} if keep else None
            seen_ids = set()
            value_bytes = _read_exact(
                f, value_count * 12, context + ' values')
            for value_index, (relocation_id, offset) in enumerate(
                    struct.iter_unpack('<QI', value_bytes)):
                if relocation_id <= 0 or relocation_id > high_vid:
                    raise ValueError(
                        'relib relocation ID {} exceeds declared range'.format(
                            relocation_id))
                if relocation_id in seen_ids:
                    raise ValueError(
                        'duplicate relib relocation ID {} in {}'.format(
                            relocation_id, version))
                seen_ids.add(relocation_id)
                # Offsets are encoded as uint32 RVAs; retain the explicit
                # bound here so a format change cannot silently widen them.
                if offset > 0xFFFFFFFF:
                    raise ValueError('relib RVA is outside the uint32 range')
                if database is not None:
                    database[relocation_id] = offset
            if database is not None:
                retained[version] = database

            if fmt_version == 2:
                hash_count = struct.unpack(
                    '<i', _read_exact(f, 4, context + ' hash count'))[0]
                remaining = file_size - f.tell()
                if hash_count < 0 or hash_count > remaining // 16:
                    raise ValueError('invalid relib hash count {}'.format(hash_count))
                _read_exact(f, hash_count * 16, context + ' hashes')

        if f.tell() != file_size:
            raise ValueError(
                'unexpected trailing bytes in relib ({})'.format(
                    file_size - f.tell()))
    return versions, retained


def load_relib_versions(relib_path: str, target_versions) -> Dict[Tuple[int, ...], Dict[int, int]]:
    """Load requested version maps after validating the complete relib."""
    requested = {tuple(version) for version in target_versions}
    _versions, retained = _parse_relib(relib_path, requested)
    return {version: retained.get(version, {}) for version in requested}


def load_relib_version(relib_path: str, target_version: Tuple[int, ...]) -> Dict[int, int]:
    """Load one version only after validating the complete relib."""
    target = tuple(target_version)
    return load_relib_versions(relib_path, (target,)).get(target, {})


def list_relib_versions(relib_path: str) -> list:
    """List versions only after validating the complete relib."""
    versions, _retained = _parse_relib(relib_path)
    return versions


def unique_reverse_ids(database: Dict[int, int]):
    """Return (RVA->ID, ambiguous RVAs), never selecting a last-wins ID."""
    reverse = {}
    ambiguous = set()
    for relocation_id, rva in database.items():
        if rva in ambiguous:
            continue
        if rva in reverse:
            reverse.pop(rva, None)
            ambiguous.add(rva)
        else:
            reverse[rva] = relocation_id
    return reverse, ambiguous


class AddressLibrary:
    """Loads address-library databases mapping relocation IDs to RVAs."""

    def __init__(self):
        self.se_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}
        self.db_17104: Dict[int, int] = {}
        self.vr_db: Dict[int, int] = {}

    def load_bin(self, file_path: str,
                 expected_version: Optional[Tuple[int, ...]] = None) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            def read_exact(size: int) -> bytes:
                value = f.read(size)
                if len(value) != size:
                    raise ValueError('truncated SSE address library {} at byte {}'.format(
                        file_path, f.tell()))
                return value

            fmt = struct.unpack('<I', read_exact(4))[0]
            if fmt not in (1, 2, 5):
                raise ValueError('unsupported SSE address-library format {} in {}'.format(
                    fmt, file_path))
            embedded_version = tuple(struct.unpack('<4I', read_exact(16)))
            if expected_version is not None:
                expected = tuple(expected_version) + (0,) * (4 - len(expected_version))
                if embedded_version != expected[:4]:
                    raise ValueError(
                        'SSE address-library version mismatch in {}: {} != {}'.format(
                            file_path, embedded_version, expected[:4]))
            if fmt == 5:
                # V5 stores a fixed 64-byte module label followed by a
                # uint64 pointer size and an RVA array indexed directly by
                # relocation ID.  A zero entry means the ID is unmapped.
                read_exact(64)
                ptr_size = struct.unpack('<Q', read_exact(8))[0]
                if ptr_size != 8:
                    raise ValueError(
                        'Skyrim V5 address library has pointer size {} in {}'.format(
                            ptr_size, file_path))
                addr_count = struct.unpack('<I', read_exact(4))[0]
                remaining = os.path.getsize(file_path) - f.tell()
                expected_bytes = addr_count * 4
                if expected_bytes != remaining:
                    raise ValueError(
                        'invalid Skyrim V5 address table in {}: expected {} '
                        'bytes, found {}'.format(
                            file_path, expected_bytes, remaining))
                values = read_exact(expected_bytes)
                for relocation_id, (offset,) in enumerate(
                        struct.iter_unpack('<I', values)):
                    if offset:
                        db[relocation_id] = offset
                return db
            name_len = struct.unpack('<I', read_exact(4))[0]
            if name_len > os.path.getsize(file_path) - f.tell():
                raise ValueError('invalid module-name length {} in {}'.format(
                    name_len, file_path))
            read_exact(name_len)
            ptr_size   = struct.unpack('<I', read_exact(4))[0]
            if ptr_size != 8:
                raise ValueError(
                    'Skyrim x64 address library has pointer size {} in {}'.format(
                        ptr_size, file_path))
            addr_count = struct.unpack('<I', read_exact(4))[0]
            pvid = 0; poffset = 0
            for _ in range(addr_count):
                type_byte = struct.unpack('<B', read_exact(1))[0]
                low = type_byte & 0xF; high = type_byte >> 4
                if   low == 0: id_val = struct.unpack('<Q', read_exact(8))[0]
                elif low == 1: id_val = pvid + 1
                elif low == 2: id_val = pvid + struct.unpack('<B', read_exact(1))[0]
                elif low == 3: id_val = pvid - struct.unpack('<B', read_exact(1))[0]
                elif low == 4: id_val = pvid + struct.unpack('<H', read_exact(2))[0]
                elif low == 5: id_val = pvid - struct.unpack('<H', read_exact(2))[0]
                elif low == 6: id_val = struct.unpack('<H', read_exact(2))[0]
                elif low == 7: id_val = struct.unpack('<I', read_exact(4))[0]
                else:
                    raise ValueError(
                        'invalid relocation-ID encoding {} in {}'.format(
                            low, file_path))
                tpoffset = (poffset // ptr_size) if (high & 8) != 0 else poffset
                h_type = high & 7
                if   h_type == 0: off_val = struct.unpack('<Q', read_exact(8))[0]
                elif h_type == 1: off_val = tpoffset + 1
                elif h_type == 2: off_val = tpoffset + struct.unpack('<B', read_exact(1))[0]
                elif h_type == 3: off_val = tpoffset - struct.unpack('<B', read_exact(1))[0]
                elif h_type == 4: off_val = tpoffset + struct.unpack('<H', read_exact(2))[0]
                elif h_type == 5: off_val = tpoffset - struct.unpack('<H', read_exact(2))[0]
                elif h_type == 6: off_val = struct.unpack('<H', read_exact(2))[0]
                elif h_type == 7: off_val = struct.unpack('<I', read_exact(4))[0]
                if (high & 8) != 0: off_val *= ptr_size
                if (id_val < 0 or id_val > 0xFFFFFFFFFFFFFFFF or
                        off_val < 0 or off_val > 0xFFFFFFFFFFFFFFFF):
                    raise ValueError(
                        'underflow/overflow in SSE address library {}'.format(
                            file_path))
                if id_val in db:
                    raise ValueError(
                        'duplicate relocation ID {} in {}'.format(
                            id_val, file_path))
                db[id_val] = off_val; pvid = id_val; poffset = off_val
            if f.read(1):
                raise ValueError(
                    'unexpected trailing bytes in SSE address library {}'.format(
                        file_path))
        return db

    @staticmethod
    def load_csv(file_path: str, expected_count: int = 13949,
                 expected_marker: str = '0.211.0') -> Dict[int, int]:
        """Read the exact Skyrim VR ``id,offset`` address-library CSV.

        The community VR address libraries (Old, etc.) ship as CSV rather
        than the meh321 binary format.  Format:

          id,offset                          # header line
          <entry-count>,<library-version>    # required metadata row
          <id>,<hex-offset>                  # entries

        ``offset`` is parsed as hex without a ``0x`` prefix.  Malformed rows,
        duplicate IDs, incorrect metadata, and partial corpora are rejected;
        duplicate offsets are legitimate aliases and remain allowed.
        """
        if not os.path.exists(file_path):
            return {}
        db: Dict[int, int] = {}
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            rows = csv.reader(f)
            try:
                header = next(rows)
                metadata = next(rows)
            except StopIteration as exc:
                raise ValueError(
                    'truncated Skyrim VR address library {}'.format(file_path)) from exc
            if header != ['id', 'offset']:
                raise ValueError(
                    'invalid Skyrim VR address-library header in {}'.format(
                        file_path))
            if len(metadata) != 2:
                raise ValueError(
                    'invalid Skyrim VR address-library metadata in {}'.format(
                        file_path))
            try:
                declared_count = int(metadata[0], 10)
            except ValueError as exc:
                raise ValueError(
                    'invalid Skyrim VR address-library entry count') from exc
            if (declared_count != int(expected_count) or
                    metadata[1] != expected_marker):
                raise ValueError(
                    'Skyrim VR address-library metadata mismatch: '
                    '{} / {} != {} / {}'.format(
                        declared_count, metadata[1], expected_count,
                        expected_marker))
            for line_number, row in enumerate(rows, 3):
                if len(row) != 2:
                    raise ValueError(
                        'malformed Skyrim VR address-library row {} in {}'.format(
                            line_number, file_path))
                try:
                    relocation_id = int(row[0], 10)
                    offset = int(row[1], 16)
                except ValueError as exc:
                    raise ValueError(
                        'invalid Skyrim VR address-library row {} in {}'.format(
                            line_number, file_path)) from exc
                if relocation_id < 0 or offset < 0:
                    raise ValueError(
                        'negative Skyrim VR address-library value on row {}'.format(
                            line_number))
                if relocation_id in db:
                    raise ValueError(
                        'duplicate Skyrim VR relocation ID {} on row {}'.format(
                            relocation_id, line_number))
                db[relocation_id] = offset
        if len(db) != declared_count:
            raise ValueError(
                'Skyrim VR address-library row count {} != metadata {}'.format(
                    len(db), declared_count))
        return db

    def load_all(self, base_path: str, require_17104: bool = False) -> None:
        sse_dir = os.path.join(base_path, 'sse')
        self.se_db = self.load_bin(
            os.path.join(sse_dir, 'version-1-5-97-0.bin'), (1, 5, 97, 0))
        self.ae_db = self.load_bin(
            os.path.join(sse_dir, 'versionlib-1-6-1170-0.bin'), (1, 6, 1170, 0))
        self.db_17104 = self.load_bin(
            os.path.join(sse_dir, 'versionlib-1-7-104-0.bin'), (1, 7, 104, 0))
        self.vr_db = self.load_csv(os.path.join(sse_dir, 'version-1-4-15-0.csv'))
        missing = [name for name, db in (
            ('SE 1.5.97', self.se_db), ('AE 1.6.1170', self.ae_db),
            ('VR 1.4.15', self.vr_db)) if not db]
        if require_17104 and not self.db_17104:
            missing.append('AE 1.7.104')
        if missing:
            raise FileNotFoundError('Missing or empty Skyrim address libraries: {}'.format(
                ', '.join(missing)))
