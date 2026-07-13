"""Small, strict MSF 7/PDB public-symbol reader.

This module intentionally implements only the records needed to bind a PDB
and extract ``S_PUB32`` records.  It is used for reproducible community-symbol
corpora; it is not a replacement for Ghidra's or LLVM's complete PDB parser.
Malformed block maps, stream directories, DBI headers, section tables, OMAP
streams, and CodeView records fail closed.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
import struct
import uuid
from pathlib import Path
from typing import Optional, Sequence, Tuple


MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
S_PUB32 = 0x110E
NIL_STREAM = 0xFFFF
DBI_HEADER = struct.Struct("<iIIHHHHHHiiiiiIiiHHI")
SECTION_HEADER_SIZE = 40


class PDBMSFError(ValueError):
    """The input is not a structurally valid supported MSF 7/PDB file."""


@dataclass(frozen=True)
class PDBSection:
    name: str
    virtual_size: int
    rva: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def span(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class PDBPublic:
    rva: int
    name: str
    flags: int
    segment: int
    offset: int
    section: str
    executable: bool


@dataclass(frozen=True)
class PDBPublicCorpus:
    guid: str
    age: int
    signature: int
    pdb_version: int
    machine: int
    type_record_count: int
    module_info_size: int
    sections: Tuple[PDBSection, ...]
    publics: Tuple[PDBPublic, ...]


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def read_msf_streams(path: str | Path) -> Tuple[Optional[bytes], ...]:
    """Return every MSF stream after validating the complete block directory."""
    data = Path(path).read_bytes()
    if len(data) < 56 or data[:32] != MSF7_MAGIC:
        raise PDBMSFError("not an MSF 7.0 PDB")
    (block_size, free_map_block, block_count, directory_size,
     reserved, block_map_block) = struct.unpack_from("<6I", data, 32)
    if (block_size < 512 or block_size > 65536 or
            block_size & (block_size - 1)):
        raise PDBMSFError("invalid MSF block size")
    if reserved != 0 or block_count == 0:
        raise PDBMSFError("invalid MSF superblock")
    if block_count * block_size != len(data):
        raise PDBMSFError("MSF block count does not match file size")
    if free_map_block >= block_count or block_map_block >= block_count:
        raise PDBMSFError("MSF special block lies outside the file")
    directory_blocks_count = _ceil_div(directory_size, block_size)
    if directory_blocks_count > block_size // 4:
        raise PDBMSFError("unsupported oversized MSF directory block map")
    map_start = block_map_block * block_size
    map_end = map_start + directory_blocks_count * 4
    if map_end > len(data):
        raise PDBMSFError("truncated MSF directory block map")
    directory_blocks = struct.unpack_from(
        "<{}I".format(directory_blocks_count), data, map_start)
    if (len(set(directory_blocks)) != len(directory_blocks) or
            any(block >= block_count for block in directory_blocks)):
        raise PDBMSFError("invalid MSF directory block list")
    directory = b"".join(
        data[block * block_size:(block + 1) * block_size]
        for block in directory_blocks)[:directory_size]
    if len(directory) < 4:
        raise PDBMSFError("truncated MSF stream directory")
    stream_count = struct.unpack_from("<I", directory, 0)[0]
    sizes_end = 4 + stream_count * 4
    if stream_count > 1_000_000 or sizes_end > len(directory):
        raise PDBMSFError("invalid MSF stream count")
    sizes = struct.unpack_from(
        "<{}I".format(stream_count), directory, 4)
    cursor = sizes_end
    streams: list[Optional[bytes]] = []
    claimed_blocks = set(directory_blocks)
    for size in sizes:
        if size == 0xFFFFFFFF:
            streams.append(None)
            continue
        blocks_needed = _ceil_div(size, block_size)
        blocks_end = cursor + blocks_needed * 4
        if blocks_end > len(directory):
            raise PDBMSFError("truncated MSF stream block list")
        blocks = struct.unpack_from(
            "<{}I".format(blocks_needed), directory, cursor)
        cursor = blocks_end
        if (len(set(blocks)) != len(blocks) or
                any(block >= block_count for block in blocks) or
                any(block in claimed_blocks for block in blocks)):
            raise PDBMSFError("invalid or multiply claimed MSF stream block")
        claimed_blocks.update(blocks)
        stream = b"".join(
            data[block * block_size:(block + 1) * block_size]
            for block in blocks)[:size]
        if len(stream) != size:
            raise PDBMSFError("truncated MSF stream")
        streams.append(stream)
    if any(byte not in (0, 0xFF) for byte in directory[cursor:]):
        raise PDBMSFError("unexpected data after MSF stream directory")
    return tuple(streams)


def _required_stream(streams: Sequence[Optional[bytes]], index: int,
                     label: str) -> bytes:
    if index < 0 or index >= len(streams) or streams[index] is None:
        raise PDBMSFError("PDB is missing {} stream {}".format(label, index))
    return streams[index] or b""


def _pdb_identity(streams: Sequence[Optional[bytes]]) -> tuple[int, int, int, str]:
    info = _required_stream(streams, 1, "info")
    if len(info) < 28:
        raise PDBMSFError("truncated PDB info stream")
    version, signature, age = struct.unpack_from("<III", info, 0)
    try:
        guid = str(uuid.UUID(bytes_le=info[12:28])).upper()
    except ValueError as exc:
        raise PDBMSFError("invalid PDB GUID") from exc
    return version, signature, age, guid


def read_pdb_identity_native(path: str | Path) -> dict[str, object]:
    """Read GUID/age without invoking an external PDB utility."""
    version, signature, age, guid = _pdb_identity(read_msf_streams(path))
    return {"guid": guid, "age": age, "signature": signature,
            "version": version}


def _parse_sections(data: bytes) -> Tuple[PDBSection, ...]:
    if not data or len(data) % SECTION_HEADER_SIZE:
        raise PDBMSFError("malformed PDB section-header stream")
    sections = []
    previous_end = 0
    for offset in range(0, len(data), SECTION_HEADER_SIZE):
        (raw_name, virtual_size, rva, raw_size, raw_offset,
         _relocations, _line_numbers, _reloc_count, _line_count,
         characteristics) = struct.unpack_from("<8sIIIIIIHHI", data, offset)
        name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="strict")
        if not name or rva < previous_end:
            raise PDBMSFError("invalid or overlapping PDB sections")
        section = PDBSection(name, virtual_size, rva, raw_size,
                             raw_offset, characteristics)
        if section.span <= 0:
            raise PDBMSFError("empty PDB section")
        previous_end = rva + section.span
        sections.append(section)
    return tuple(sections)


def _parse_omap(data: bytes) -> Tuple[tuple[int, int], ...]:
    if len(data) % 8:
        raise PDBMSFError("malformed OMAP_FROM_SRC stream")
    rows = tuple(struct.unpack_from("<II", data, offset)
                 for offset in range(0, len(data), 8))
    if any(rows[index][0] >= rows[index + 1][0]
           for index in range(len(rows) - 1)):
        raise PDBMSFError("OMAP source RVAs are not strictly increasing")
    return rows


def _map_from_source(rva: int, omap: Sequence[tuple[int, int]]) -> Optional[int]:
    if not omap:
        return rva
    starts = [row[0] for row in omap]
    index = bisect.bisect_right(starts, rva) - 1
    if index < 0 or omap[index][1] == 0:
        return None
    return omap[index][1] + rva - omap[index][0]


def read_pdb_publics(path: str | Path) -> PDBPublicCorpus:
    """Extract validated ``S_PUB32`` records and their image RVAs."""
    streams = read_msf_streams(path)
    pdb_version, signature, age, guid = _pdb_identity(streams)
    dbi = _required_stream(streams, 3, "DBI")
    if len(dbi) < DBI_HEADER.size:
        raise PDBMSFError("truncated DBI header")
    values = DBI_HEADER.unpack_from(dbi, 0)
    (version_signature, _dbi_version, dbi_age, _global_stream, _build,
     _public_stream, _dll_version, symbol_stream, _dll_rebuild,
     module_size, contribution_size, section_map_size, source_info_size,
     type_server_size, _mfc_index, debug_header_size, ec_size,
     _flags, machine, _reserved) = values
    substream_sizes = (module_size, contribution_size, section_map_size,
                       source_info_size, type_server_size, ec_size,
                       debug_header_size)
    if version_signature != -1 or dbi_age != age or any(
            size < 0 for size in substream_sizes):
        raise PDBMSFError("invalid DBI header")
    debug_offset = (DBI_HEADER.size + module_size + contribution_size +
                    section_map_size + source_info_size + type_server_size +
                    ec_size)
    if (debug_header_size < 12 or debug_header_size % 2 or
            debug_offset + debug_header_size != len(dbi)):
        raise PDBMSFError("invalid DBI optional-debug header")
    debug_indices = struct.unpack_from(
        "<{}H".format(debug_header_size // 2), dbi, debug_offset)
    omap_index = debug_indices[4] if len(debug_indices) > 4 else NIL_STREAM
    section_index = debug_indices[5] if len(debug_indices) > 5 else NIL_STREAM
    original_section_index = (
        debug_indices[10] if len(debug_indices) > 10 else NIL_STREAM)
    omap: Tuple[tuple[int, int], ...] = ()
    if omap_index != NIL_STREAM:
        omap = _parse_omap(_required_stream(streams, omap_index,
                                            "OMAP_FROM_SRC"))
        section_index = original_section_index
    if section_index == NIL_STREAM:
        raise PDBMSFError("PDB has no section-header stream")
    sections = _parse_sections(
        _required_stream(streams, section_index, "section-header"))
    symbols = _required_stream(streams, symbol_stream, "symbol-record")
    publics = []
    cursor = 0
    while cursor < len(symbols):
        if cursor + 4 > len(symbols):
            raise PDBMSFError("truncated CodeView symbol record")
        record_length, record_type = struct.unpack_from("<HH", symbols, cursor)
        record_end = cursor + 2 + record_length
        if record_length < 2 or record_end > len(symbols):
            raise PDBMSFError("invalid CodeView symbol record length")
        if record_type == S_PUB32:
            if cursor + 14 > record_end:
                raise PDBMSFError("truncated S_PUB32 record")
            flags, section_offset, segment = struct.unpack_from(
                "<IIH", symbols, cursor + 4)
            name_bytes = symbols[cursor + 14:record_end]
            terminator = name_bytes.find(b"\0")
            if terminator < 0 or any(name_bytes[terminator + 1:]):
                raise PDBMSFError("invalid S_PUB32 name/padding")
            try:
                name = name_bytes[:terminator].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise PDBMSFError("non-UTF-8 S_PUB32 name") from exc
            if not name or not 1 <= segment <= len(sections):
                raise PDBMSFError("invalid S_PUB32 name or segment")
            section = sections[segment - 1]
            if section_offset >= section.span:
                raise PDBMSFError("S_PUB32 offset lies outside its section")
            source_rva = section.rva + section_offset
            rva = _map_from_source(source_rva, omap)
            if rva is not None:
                publics.append(PDBPublic(
                    rva, name, flags, segment, section_offset,
                    section.name, section.executable))
        cursor = record_end
    tpi = _required_stream(streams, 2, "TPI")
    type_record_count = 0
    if len(tpi) >= 16:
        type_begin, type_end = struct.unpack_from("<II", tpi, 8)
        if type_end < type_begin:
            raise PDBMSFError("invalid TPI type-index range")
        type_record_count = type_end - type_begin
    return PDBPublicCorpus(
        guid=guid, age=age, signature=signature, pdb_version=pdb_version,
        machine=machine, type_record_count=type_record_count,
        module_info_size=module_size, sections=sections,
        publics=tuple(publics))
