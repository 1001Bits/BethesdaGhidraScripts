"""Per-binary vtable layout data model + CSV I/O.

A vtable layout is "the actual slot-by-slot contents of a class's vtable in a
specific binary build" -- ground truth, extracted from the binary itself.
Distinct from CommonLib's *header-described* layout, which assumes a single
canonical version and silently breaks for patches that re-shuffle slots
(Skyrim VR +2, F4 NG/AE/VR all drift in different ways).

CSV format (one file per binary, one row per slot):

    class,vtable_id,subobject_offset,is_primary,vtable_addr,slot,func_addr,func_name,fingerprint
    PlayerCharacter,PlayerCharacter|primary|0x0,0x0,1,0x1416635e0,0,0x140f58870,...
    ...

- `slot` is decimal slot index (not hex, not byte offset).
- `vtable_id` + `subobject_offset` preserve secondary-base identity instead of
  flattening every table for a repeated class name into one slot map.  Legacy
  CSVs without these columns load as primary tables.
- `func_name` may be empty when the binary's PDB doesn't name the function;
  the matcher uses `fingerprint` to align such slots across versions.
- `fingerprint` is a Ghidra-style masked byte pattern (hex bytes separated
  by spaces, `?` for unknown / relocation-masked bytes).  First ~32 bytes
  is usually enough for unique cross-version matching of vfunc bodies.
"""
from __future__ import annotations

import csv
import contextlib
import io
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SlotEntry:
    """One slot's contents in a class's vtable, as observed in a binary."""
    slot: int           # 0-based slot index
    func_addr: int      # function pointer stored at this slot
    func_name: str      # PDB / Ghidra-resolved name, or '' if unknown
    fingerprint: str    # masked byte pattern of the pointed-to function

    @property
    def slot_hex(self) -> str:
        return '0x{:X}'.format(self.slot)

    @property
    def byte_offset(self) -> int:
        return self.slot * 8


@dataclass
class ClassVtable:
    """One exact class/subobject vtable in one binary."""
    class_name: str
    vtable_addr: int
    slots: Dict[int, SlotEntry] = field(default_factory=dict)
    vtable_id: str = ''
    subobject_offset: int = 0
    is_primary: bool = True

    def add(self, entry: SlotEntry) -> None:
        if entry.slot < 0:
            raise ValueError('vtable slot cannot be negative')
        if entry.slot in self.slots:
            raise ValueError(
                'duplicate slot {} in {}'.format(entry.slot, self.vtable_id))
        self.slots[entry.slot] = entry

    def slot(self, idx: int) -> Optional[SlotEntry]:
        return self.slots.get(idx)

    @property
    def max_slot(self) -> int:
        return max(self.slots.keys()) if self.slots else -1


@dataclass
class BinaryLayout:
    """All extracted class vtables for one binary."""
    binary_label: str                              # 'f4_ng', 'svr', etc
    binary_path: str = ''                          # informational
    classes: Dict[str, ClassVtable] = field(default_factory=dict)
    vtables: Dict[str, ClassVtable] = field(default_factory=dict)

    def get(self, class_name: str) -> Optional[ClassVtable]:
        return self.classes.get(class_name)

    def upsert(self, class_name: str, vtable_addr: int, vtable_id: str = '',
               subobject_offset: int = 0, is_primary: bool = True) -> ClassVtable:
        identity = vtable_id or '{}|{}|0x{:X}'.format(
            class_name, 'primary' if is_primary else 'secondary', subobject_offset)
        cv = self.vtables.get(identity)
        if cv is None:
            if is_primary and class_name in self.classes:
                raise ValueError(
                    'multiple primary vtables for {} require a reviewed '
                    'unambiguous identity'.format(class_name))
            cv = ClassVtable(
                class_name=class_name, vtable_addr=vtable_addr,
                vtable_id=identity, subobject_offset=subobject_offset,
                is_primary=is_primary)
            self.vtables[identity] = cv
            if is_primary and class_name not in self.classes:
                self.classes[class_name] = cv
        elif (cv.class_name != class_name or
              cv.vtable_addr != vtable_addr or
              cv.subobject_offset != subobject_offset or
              cv.is_primary != is_primary):
            raise ValueError(
                'conflicting physical vtable identity {}'.format(identity))
        return cv


def _parse_hex_or_dec(s: str) -> int:
    s = (s or '').strip()
    if not s:
        raise ValueError('empty numeric field')
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def _open_csv_read(path: str):
    """Transparent gzip support: ``.csv.gz`` is auto-decompressed."""
    if path.endswith('.gz'):
        import gzip
        return gzip.open(path, 'rt', encoding='utf-8', newline='')
    return open(path, newline='', encoding='utf-8')


@contextlib.contextmanager
def _open_csv_write(path: str):
    if path.endswith('.gz'):
        import gzip
        raw = open(path, 'wb')
        try:
            compressed = gzip.GzipFile(
                filename='', mode='wb', fileobj=raw, mtime=0)
            text = io.TextIOWrapper(
                compressed, encoding='utf-8', newline='', write_through=True)
            try:
                yield text
            finally:
                text.close()
                raw.flush()
                os.fsync(raw.fileno())
        finally:
            raw.close()
        return
    with open(path, 'w', newline='', encoding='utf-8') as stream:
        yield stream
        stream.flush()
        os.fsync(stream.fileno())


def load_csv(path: str, binary_label: str) -> BinaryLayout:
    """Load a per-binary vtable layout CSV.  Missing file -> empty layout.

    Transparently handles ``.csv.gz`` (gzip-compressed) inputs -- the SF
    reference layout commits compressed since the raw form is ~45 MB.
    """
    layout = BinaryLayout(binary_label=binary_label, binary_path=path)
    if not os.path.isfile(path):
        return layout
    with _open_csv_read(path) as f:
        reader = csv.DictReader(f)
        required = {'class', 'vtable_addr', 'slot', 'func_addr'}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                '{} is missing vtable columns: {}'.format(
                    path, ', '.join(sorted(missing))))
        for row in reader:
            cls = (row.get('class') or '').strip()
            if not cls:
                raise ValueError(
                    '{}:{} has an empty class'.format(path, reader.line_num))
            try:
                vt_addr = _parse_hex_or_dec(row.get('vtable_addr', '0'))
                slot = _parse_hex_or_dec(row.get('slot', ''))
                func_addr = _parse_hex_or_dec(row.get('func_addr', '0'))
            except ValueError as exc:
                raise ValueError(
                    '{}:{} has an invalid address/slot: {}'.format(
                        path, reader.line_num, exc)) from exc
            if vt_addr < 0 or func_addr < 0 or slot < 0:
                raise ValueError(
                    '{}:{} has a negative address or slot'.format(
                        path, reader.line_num))
            vtable_id = (row.get('vtable_id') or '').strip()
            try:
                subobject_offset = _parse_hex_or_dec(row.get('subobject_offset', '0'))
            except ValueError as exc:
                raise ValueError(
                    '{}:{} has an invalid subobject offset'.format(
                        path, reader.line_num)) from exc
            primary_text = (row.get('is_primary') or '1').strip().lower()
            if primary_text not in ('0', 'false', 'no', '1', 'true', 'yes'):
                raise ValueError(
                    '{}:{} has invalid is_primary {!r}'.format(
                        path, reader.line_num, primary_text))
            is_primary = primary_text in ('1', 'true', 'yes')
            cv = layout.upsert(
                cls, vt_addr, vtable_id=vtable_id,
                subobject_offset=subobject_offset, is_primary=is_primary)
            cv.add(SlotEntry(
                slot=slot,
                func_addr=func_addr,
                func_name=(row.get('func_name') or '').strip(),
                fingerprint=(row.get('fingerprint') or '').strip(),
            ))
    return layout


def save_csv(layout: BinaryLayout, path: str) -> int:
    """Write a per-binary layout to CSV.  Returns row count.

    ``.csv.gz`` paths are written as gzip-compressed CSV.
    """
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    os.makedirs(directory, exist_ok=True)
    suffix = '.csv.gz' if path.endswith('.gz') else '.csv'
    fd, temp_path = tempfile.mkstemp(
        prefix='.vtable-layout-', suffix=suffix, dir=directory)
    os.close(fd)
    rows = 0
    try:
        with _open_csv_write(temp_path) as f:
            writer = csv.writer(f)
            writer.writerow(['class', 'vtable_id', 'subobject_offset', 'is_primary',
                             'vtable_addr', 'slot', 'func_addr', 'func_name', 'fingerprint'])
            tables = layout.vtables or {
                cv.vtable_id or cls_name: cv for cls_name, cv in layout.classes.items()
            }
            for identity in sorted(tables):
                cv = tables[identity]
                for slot in sorted(cv.slots):
                    e = cv.slots[slot]
                    writer.writerow([
                        cv.class_name,
                        cv.vtable_id or identity,
                        '0x{:X}'.format(cv.subobject_offset),
                        1 if cv.is_primary else 0,
                        '0x{:X}'.format(cv.vtable_addr),
                        e.slot,
                        '0x{:X}'.format(e.func_addr),
                        e.func_name,
                        e.fingerprint,
                    ])
                    rows += 1
        os.replace(temp_path, path)
        return rows
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
