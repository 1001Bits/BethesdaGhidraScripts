"""Small dependency-free PE layout reader used by offline symbol sources.

The generated importer performs the final memory-block check inside Ghidra,
but generators must not claim that a known data RVA is a function in the
first place.  This module provides enough PE metadata to classify an RVA and
to bind derived evidence to the exact executable that was inspected.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Iterable, Optional, Tuple


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    size: int
    characteristics: int
    raw_offset: int
    raw_size: int

    def contains(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + self.size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


@dataclass(frozen=True)
class PELayout:
    path: str
    machine: int
    pointer_size: int
    image_base: int
    image_size: int
    timestamp: int
    sha256: str
    sections: Tuple[Section, ...]

    def section_for_rva(self, rva: int) -> Optional[Section]:
        return next((s for s in self.sections if s.contains(rva)), None)

    def classify_rva(self, rva: int) -> Tuple[str, Optional[str]]:
        section = self.section_for_rva(rva)
        if section is None:
            return 'unmapped', None
        return ('func' if section.executable else 'label'), section.name

    def read_rva(self, rva: int, size: int) -> bytes:
        section = self.section_for_rva(rva)
        if section is None:
            raise ValueError('RVA {:#x} is unmapped'.format(rva))
        delta = rva - section.rva
        if delta < 0 or delta + size > section.raw_size:
            raise ValueError('RVA {:#x} has no file-backed bytes'.format(rva))
        with open(self.path, 'rb') as stream:
            stream.seek(section.raw_offset + delta)
            value = stream.read(size)
        if len(value) != size:
            raise ValueError('truncated file-backed RVA {:#x}'.format(rva))
        return value

    def msvc_vtable_subobject_offset(self, vtable_rva: int) -> int:
        """Read and validate the MSVC x64 COL referenced by ``vtable[-1]``."""
        if self.pointer_size != 8:
            raise ValueError('MSVC COL vtable validation requires PE32+')
        locator_va = struct.unpack('<Q', self.read_rva(vtable_rva - 8, 8))[0]
        locator_rva = locator_va - self.image_base
        if locator_rva <= 0 or locator_rva + 24 > self.image_size:
            raise ValueError('vtable has an invalid CompleteObjectLocator')
        raw = self.read_rva(locator_rva, 24)
        signature, subobject_offset, _cd_offset, type_rva, chd_rva, self_rva = \
            struct.unpack('<6I', raw)
        if signature not in (0, 1):
            raise ValueError('vtable COL has an invalid signature')
        if signature == 1 and self_rva != locator_rva:
            raise ValueError('vtable COL self RVA is inconsistent')
        if (type_rva <= 0 or type_rva >= self.image_size or
                chd_rva <= 0 or chd_rva >= self.image_size):
            raise ValueError('vtable COL metadata RVAs are invalid')
        return subobject_offset

    @classmethod
    def read(cls, path: str) -> "PELayout":
        with open(path, 'rb') as fh:
            data = fh.read()
        if len(data) < 0x40 or data[:2] != b'MZ':
            raise ValueError('not a valid DOS/PE image: {}'.format(path))
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b'PE\0\0':
            raise ValueError('missing or truncated PE signature: {}'.format(path))
        machine, n_sections, timestamp = struct.unpack_from('<HHI', data, pe_off + 4)
        opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
        opt_off = pe_off + 24
        if opt_off + opt_size > len(data) or opt_size < 64:
            raise ValueError('truncated PE optional header: {}'.format(path))
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic == 0x20B:
            pointer_size = 8
            image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
        elif magic == 0x10B:
            pointer_size = 4
            image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
        else:
            raise ValueError('unsupported PE optional-header magic {:#x}'.format(magic))
        image_size = struct.unpack_from('<I', data, opt_off + 56)[0]
        sec_off = opt_off + opt_size
        if sec_off + n_sections * 40 > len(data):
            raise ValueError('truncated PE section table: {}'.format(path))
        sections = []
        for index in range(n_sections):
            off = sec_off + index * 40
            raw_name = data[off:off + 8].split(b'\0', 1)[0]
            name = raw_name.decode('ascii', errors='replace') or '<unnamed>'
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                '<IIII', data, off + 8)
            characteristics = struct.unpack_from('<I', data, off + 36)[0]
            size = max(virtual_size, raw_size)
            if size:
                sections.append(Section(name, rva, size, characteristics,
                                        raw_offset, raw_size))
        if not sections or image_size == 0:
            raise ValueError('PE has no mapped sections: {}'.format(path))
        return cls(
            path=path,
            machine=machine,
            pointer_size=pointer_size,
            image_base=image_base,
            image_size=image_size,
            timestamp=timestamp,
            sha256=hashlib.sha256(data).hexdigest(),
            sections=tuple(sections),
        )


def attach_section(symbol: dict, rva_key: str, layout: PELayout,
                   declared_kind: Optional[str] = None) -> bool:
    """Attach per-target section provenance and normalize the symbol kind.

    Returns ``False`` for unmapped RVAs.  A declared data label is never
    promoted to a function merely because it happens to point into code;
    executable classification only promotes sources that claimed code.
    """
    rva = symbol.get(rva_key)
    if not isinstance(rva, int) or rva <= 0:
        return False
    actual_kind, section_name = layout.classify_rva(rva)
    if actual_kind == 'unmapped':
        return False
    symbol.setdefault('sections', {})[rva_key] = section_name
    if declared_kind == 'label':
        symbol['t'] = 'label'
    else:
        symbol['t'] = actual_kind
    if declared_kind and declared_kind != actual_kind:
        symbol.setdefault('kind_mismatch', {})[rva_key] = {
            'declared': declared_kind, 'actual': actual_kind,
        }
    return True


def x64_runtime_function_starts(path: str) -> set[int]:
    """Return function begin RVAs from the PE's ``.pdata`` runtime table.

    This is deliberately conservative: x64 leaf functions without unwind
    records are omitted.  Cross-build evidence may lose coverage, but it can
    no longer land in the middle of an instruction sequence and be emitted as
    an address-library function entry.
    """
    with open(path, 'rb') as fh:
        data = fh.read()
    if len(data) < 0x40 or data[:2] != b'MZ':
        raise ValueError('not a PE image: {}'.format(path))
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        raise ValueError('missing PE signature: {}'.format(path))
    machine, n_sections = struct.unpack_from('<HH', data, pe_off + 4)
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    if machine != 0x8664:
        raise ValueError('.pdata function starts require AMD64 PE input')
    sec_off = pe_off + 24 + opt_size
    pdata = None
    image_size = struct.unpack_from('<I', data, pe_off + 24 + 56)[0]
    for index in range(n_sections):
        off = sec_off + index * 40
        if off + 40 > len(data):
            raise ValueError('truncated section table in {}'.format(path))
        name = data[off:off + 8].split(b'\0', 1)[0]
        if name == b'.pdata':
            raw_size, raw_off = struct.unpack_from('<II', data, off + 16)
            if raw_off + raw_size > len(data):
                raise ValueError('truncated .pdata in {}'.format(path))
            pdata = data[raw_off:raw_off + raw_size]
            break
    if pdata is None:
        raise ValueError('no .pdata section in {}'.format(path))
    starts = set()
    for off in range(0, len(pdata) - 11, 12):
        begin, end, unwind = struct.unpack_from('<III', pdata, off)
        if begin == end == unwind == 0:
            continue
        if 0 < begin < end <= image_size and unwind < image_size:
            starts.add(begin)
    if not starts:
        raise ValueError('no valid runtime-function entries in {}'.format(path))
    return starts
