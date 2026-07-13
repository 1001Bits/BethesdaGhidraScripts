"""Fallout 4 address library loader (libxse/commonlibf4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count x (uint64 id, uint64 offset) pairs, sorted by id

Loads OG (1.10.163), NG (1.10.984), AE (1.11.191), and VR (1.2.72).

OG and AE/NG IDs share the same meh321-maintained namespace: a single ID
resolves to a function's offset in whichever DBs it exists in.  VR uses a
disjoint community-maintained namespace and ships as a flat CSV.  Looking
up an AE-namespace ID against the VR DB only ever finds coincidental
low-ID matches that point at the wrong functions, so VR symbols are only
populated when CommonLibF4 explicitly references a VR ID.

CommonLibF4's headers carry NG/AE IDs (1.10.984 / 1.11.191), so symbol
resolution for OG/VR scripts comes from types and labels only; function
addresses must be reconstructed via a separate post-pass (e.g. byte-sig
porting from AE).
"""

from __future__ import annotations

import csv
import os
import struct
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
from pe_version import get_pe_version  # noqa: E402


class F4AddressLibrary:
    """Loads Fallout 4 address library databases (OG / NG / AE / VR)."""

    def __init__(self):
        self.og_db: Dict[int, int] = {}
        self.ng_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}
        self.vr_db: Dict[int, int] = {}
        self.db_221: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db: Dict[int, int] = {}
        with open(file_path, 'rb') as f:
            data = f.read()
        if len(data) < 8:
            raise ValueError('truncated F4 address-library header: {}'.format(file_path))
        count = struct.unpack_from('<Q', data, 0)[0]
        expected = 8 + count * 16
        if expected != len(data):
            raise ValueError(
                'invalid F4 address-library length for {}: header declares '
                '{} entries ({} bytes), file has {} bytes'.format(
                    file_path, count, expected, len(data)))
        previous_id = -1
        for index in range(count):
            id_, offset = struct.unpack_from('<QQ', data, 8 + index * 16)
            if id_ <= previous_id:
                raise ValueError(
                    'F4 address-library IDs are not strictly increasing at '
                    'entry {} in {}'.format(index, file_path))
            if offset == 0:
                raise ValueError('zero RVA for ID {} in {}'.format(id_, file_path))
            previous_id = id_
            db[id_] = offset
        return db

    @staticmethod
    def load_csv(file_path: str, expected_count: int = 93858,
                 expected_marker: str = '1.13.1') -> Dict[int, int]:
        """Read the exact community Fallout 4 VR address-library CSV.

        The community VR address library ships as CSV rather than the
        meh321 binary format.  Format:

          id,offset                          # header line
          <entry-count>,<library-version>    # required metadata row
          <id>,<hex-offset>                  # entries

        ``offset`` is parsed as hex without a ``0x`` prefix.  Every row and
        the declared corpus identity must validate; duplicate offsets are
        legitimate aliases, but duplicate IDs are rejected.
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
                    'truncated F4 VR address library {}'.format(file_path)) from exc
            if header != ['id', 'offset']:
                raise ValueError(
                    'invalid F4 VR address-library header in {}'.format(file_path))
            if len(metadata) != 2:
                raise ValueError(
                    'invalid F4 VR address-library metadata in {}'.format(file_path))
            try:
                declared_count = int(metadata[0], 10)
            except ValueError as exc:
                raise ValueError('invalid F4 VR address-library entry count') from exc
            if (declared_count != int(expected_count) or
                    metadata[1] != expected_marker):
                raise ValueError(
                    'F4 VR address-library metadata mismatch: {} / {} != {} / {}'.format(
                        declared_count, metadata[1], expected_count,
                        expected_marker))
            for line_number, row in enumerate(rows, 3):
                if len(row) != 2:
                    raise ValueError(
                        'malformed F4 VR address-library row {} in {}'.format(
                            line_number, file_path))
                try:
                    relocation_id = int(row[0], 10)
                    offset = int(row[1], 16)
                except ValueError as exc:
                    raise ValueError(
                        'invalid F4 VR address-library row {} in {}'.format(
                            line_number, file_path)) from exc
                if relocation_id < 0 or offset < 0:
                    raise ValueError(
                        'negative F4 VR address-library value on row {}'.format(
                            line_number))
                if relocation_id in db:
                    raise ValueError(
                        'duplicate F4 VR relocation ID {} on row {}'.format(
                            relocation_id, line_number))
                db[relocation_id] = offset
        if len(db) != declared_count:
            raise ValueError(
                'F4 VR address-library row count {} != metadata {}'.format(
                    len(db), declared_count))
        return db

    def load_all(self, base_path: str,
                 ng_version: Tuple[int, int, int, int] = (1, 10, 984, 0)) -> None:
        """Load the exact databases used by the generated script variants.

        NG 1.10.980 and 1.10.984 are similar but not interchangeable.  The
        old loader silently preferred 984 and fell back to 980 while still
        labelling its output ``f4_ng``.  Require the requested revision so a
        missing database fails closed instead of shifting every NG symbol.
        """
        self.og_db = self.load_bin(os.path.join(base_path, 'version-1-10-163-0.bin'))
        ng_label = '-'.join(str(x) for x in ng_version)
        ng_path = os.path.join(base_path, 'version-{}.bin'.format(ng_label))
        if not os.path.isfile(ng_path):
            raise FileNotFoundError(
                'Missing exact Fallout 4 NG address library {}.  Refusing '
                'to substitute a different patch revision.'.format(ng_path))
        self.ng_db = self.load_bin(ng_path)
        self.ae_db = self.load_bin(os.path.join(base_path, 'version-1-11-191-0.bin'))
        self.vr_db = self.load_csv(os.path.join(base_path, 'version-1-2-72-0.csv'))
        self.db_221 = self.load_bin(os.path.join(base_path, 'version-1-11-221-0.bin'))

        required = {
            'OG 1.10.163': self.og_db,
            'NG {}'.format('.'.join(str(x) for x in ng_version)): self.ng_db,
            'AE 1.11.191': self.ae_db,
            'VR 1.2.72': self.vr_db,
            '1.11.221': self.db_221,
        }
        missing = [label for label, db in required.items() if not db]
        if missing:
            raise FileNotFoundError(
                'Missing or empty Fallout 4 address libraries: {}'.format(
                    ', '.join(missing)))

    def get_ae(self, id_: int) -> Optional[int]:
        return self.ae_db.get(id_) if id_ else None

    def resolve_desktop(self, id_: int) -> Dict[str, int]:
        """Resolve a shared desktop ID without ever probing the VR namespace."""
        if not id_:
            return {}
        out = {}
        for attr, key in (('og_db', 'og'), ('ng_db', 'ng'),
                          ('ae_db', 'a'), ('db_221', '221')):
            value = getattr(self, attr).get(id_)
            if value:
                out[key] = value
        return out
