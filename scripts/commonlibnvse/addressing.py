#!/usr/bin/env python3
"""Address-coordinate helpers for the 32-bit Fallout New Vegas image.

The FNV improvement sources historically mixed absolute virtual addresses
(VAs) and image-relative virtual addresses (RVAs), sometimes in the same
file.  Downstream code must never guess which coordinate a number uses.
This module is the single conversion boundary used by the FNV tools.

New generated text files should include one of these directives::

    # ADDRESS_COORDINATE=RVA
    # VTABLE_ADDRESS_COORDINATE=RVA
    # VFUNC_ADDRESS_COORDINATE=RVA

Legacy checked-in vtable files are supported through an explicit filename
schema.  Unknown files without a directive are rejected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

FNV_IMAGE_BASE = 0x00400000
# FalloutNV.exe 1.4.0.525 is smaller than this.  Keeping a modest guard band
# catches double-subtraction/addition while allowing every known section.
FNV_MAX_RVA = 0x02000000


class AddressError(ValueError):
    """Raised when an address is ambiguous or outside the target image."""


def normalize_address(value: int, coordinate: str, *,
                      image_base: int = FNV_IMAGE_BASE,
                      max_rva: Optional[int] = FNV_MAX_RVA,
                      allow_zero: bool = False) -> int:
    """Convert an explicitly-tagged VA/RVA to a validated RVA."""
    coord = coordinate.strip().upper()
    if coord == 'VA':
        rva = value - image_base
    elif coord == 'RVA':
        rva = value
    else:
        raise AddressError('address coordinate must be VA or RVA, got %r' % coordinate)
    if rva < 0 or (rva == 0 and not allow_zero):
        raise AddressError('address 0x%X (%s) is below the image' % (value, coord))
    if max_rva is not None and rva >= max_rva:
        raise AddressError('RVA 0x%X is outside the FNV image bound 0x%X' %
                           (rva, max_rva))
    return rva


_DIRECTIVE = re.compile(
    r'^\s*#\s*(?:(VTABLE|VFUNC)_)?ADDRESS_COORDINATE\s*=\s*(VA|RVA)\s*$',
    re.I)


def coordinate_directives(lines: Iterable[str]) -> dict:
    """Return ``{'address'|'vtable'|'vfunc': 'VA'|'RVA'}`` directives."""
    out = {}
    for line in lines:
        m = _DIRECTIVE.match(line)
        if not m:
            continue
        key = (m.group(1) or 'address').lower()
        out[key] = m.group(2).upper()
    return out


def coordinate_for_file(path: Path, kind: str = 'address') -> str:
    """Resolve a coordinate from directives or a reviewed legacy schema."""
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    directives = coordinate_directives(lines[:32])
    if kind in directives:
        return directives[kind]
    if 'address' in directives:
        return directives['address']

    # Explicit compatibility for the two committed pre-schema corpora.
    legacy = {
        'fnv_pc_vtables.txt': {'vtable': 'VA', 'vfunc': 'VA'},
        'fnv_pc_vtables_rtti_extra.txt': {'vtable': 'VA', 'vfunc': 'RVA'},
        # This CSV was generated from the main table before its VA/RVA bug was
        # fixed.  New output carries ADDRESS_COORDINATE=RVA.
        'fnv_commonlib_vtable_methods.csv': {'address': 'VA'},
    }
    schema = legacy.get(path.name)
    if schema and kind in schema:
        return schema[kind]
    if schema and 'address' in schema:
        return schema['address']
    raise AddressError('%s has no address-coordinate directive' % path)


@dataclass
class VTableRecord:
    """One physical vtable; class names are deliberately not dictionary keys."""
    table_rva: int
    class_name: str
    declared_slots: int
    source: str
    occurrence: int
    subobject: str = ''
    slots: List[Tuple[int, int]] = field(default_factory=list)  # (slot, fn RVA)

    @property
    def identity(self) -> str:
        suffix = (':' + self.subobject) if self.subobject else ''
        return '%s:0x%08X:%s%s' % (
            self.source, self.table_rva, self.class_name, suffix)


_VT_HDR = re.compile(
    r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|(\d+)\s+vfuncs(?:\|([^|]+))?\s*$')
_VT_ROW = re.compile(
    r'^\s+VFUNC\|0x([0-9A-Fa-f]+)\|.+?::vf(?:unc_)?(\d+)\s*$')


def load_vtable_records(paths: Iterable[Path]) -> List[VTableRecord]:
    """Parse physical PC vtables while retaining address/subobject identity."""
    out: List[VTableRecord] = []
    class_counts = {}
    for path in paths:
        if not path.is_file():
            continue
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        vt_coord = coordinate_for_file(path, 'vtable')
        fn_coord = coordinate_for_file(path, 'vfunc')
        current = None
        for line_no, line in enumerate(lines, 1):
            m = _VT_HDR.match(line)
            if m:
                try:
                    table_rva = normalize_address(int(m.group(1), 16), vt_coord)
                except AddressError as exc:
                    raise AddressError('%s:%d: %s' % (path, line_no, exc)) from exc
                cls = m.group(2).strip()
                subobject = (m.group(4) or '').strip()
                key = (path.name, cls)
                occurrence = class_counts.get(key, 0)
                class_counts[key] = occurrence + 1
                current = VTableRecord(
                    table_rva=table_rva, class_name=cls,
                    declared_slots=int(m.group(3)), source=path.name,
                    occurrence=occurrence, subobject=subobject)
                out.append(current)
                continue
            m = _VT_ROW.match(line)
            if m and current is not None:
                try:
                    fn_rva = normalize_address(int(m.group(1), 16), fn_coord)
                except AddressError as exc:
                    raise AddressError('%s:%d: %s' % (path, line_no, exc)) from exc
                current.slots.append((int(m.group(2)), fn_rva))
        for record in out:
            if record.source == path.name and record.declared_slots != len(record.slots):
                raise AddressError(
                    '%s: vtable %s declares %d slots but contains %d' %
                    (path, record.identity, record.declared_slots, len(record.slots)))
    return out

