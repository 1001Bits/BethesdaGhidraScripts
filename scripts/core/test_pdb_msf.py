import struct
import uuid

import pytest

from pdb_msf import PDBMSFError, read_pdb_identity_native, read_pdb_publics


def _record(name=b"Test::Function", flags=2, offset=0x20, segment=1):
    payload = struct.pack("<HIIH", 0x110E, flags, offset, segment) + name + b"\0"
    while (len(payload) + 2) % 4:
        payload += b"\0"
    return struct.pack("<H", len(payload)) + payload


def _minimal_pdb(path, symbol_record=None):
    block_size = 512
    guid = uuid.UUID("22776620-B648-4C12-98F7-D51833DAFFC9")
    info = struct.pack("<III", 20000404, 1234, 1) + guid.bytes_le
    tpi = bytearray(56)
    struct.pack_into("<IIII", tpi, 0, 20040203, 56, 0x1000, 0x1000)
    debug = [0xFFFF] * 11
    debug[5] = 9
    dbi = struct.pack(
        "<iIIHHHHHHiiiiiIiiHHI", -1, 19990903, 1,
        0xFFFF, 0, 0xFFFF, 0, 8, 0,
        0, 0, 0, 0, 0, 0, 22, 0, 4, 0x8664, 0)
    dbi += struct.pack("<11H", *debug)
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", 0x1000, 0x1000,
        0x1000, 0x400, 0, 0, 0, 0, 0x60000020)
    streams = [b"", info, bytes(tpi), dbi, b"", b"", b"", b"",
               symbol_record or _record(), section]
    stream_blocks = []
    next_block = 4
    for stream in streams:
        count = (len(stream) + block_size - 1) // block_size
        blocks = list(range(next_block, next_block + count))
        next_block += count
        stream_blocks.append(blocks)
    directory = struct.pack("<I", len(streams))
    directory += struct.pack("<{}I".format(len(streams)),
                             *(len(stream) for stream in streams))
    for blocks in stream_blocks:
        if blocks:
            directory += struct.pack("<{}I".format(len(blocks)), *blocks)
    assert len(directory) <= block_size
    image = bytearray(next_block * block_size)
    image[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    struct.pack_into("<6I", image, 32, block_size, 1, next_block,
                     len(directory), 0, 2)
    struct.pack_into("<I", image, 2 * block_size, 3)
    image[3 * block_size:3 * block_size + len(directory)] = directory
    for stream, blocks in zip(streams, stream_blocks):
        for index, block in enumerate(blocks):
            chunk = stream[index * block_size:(index + 1) * block_size]
            image[block * block_size:block * block_size + len(chunk)] = chunk
    path.write_bytes(image)
    return guid


def test_native_msf_identity_and_public_round_trip(tmp_path):
    path = tmp_path / "test.pdb"
    guid = _minimal_pdb(path)
    assert read_pdb_identity_native(path) == {
        "guid": str(guid).upper(), "age": 1,
        "signature": 1234, "version": 20000404}
    corpus = read_pdb_publics(path)
    assert corpus.machine == 0x8664
    assert corpus.type_record_count == 0
    assert len(corpus.publics) == 1
    public = corpus.publics[0]
    assert (public.rva, public.name, public.flags, public.section) == (
        0x1020, "Test::Function", 2, ".text")


def test_native_msf_rejects_truncated_symbol_record(tmp_path):
    path = tmp_path / "bad.pdb"
    _minimal_pdb(path, struct.pack("<HH", 0x100, 0x110E))
    with pytest.raises(PDBMSFError, match="record length"):
        read_pdb_publics(path)


def test_native_msf_rejects_file_size_not_bound_to_superblock(tmp_path):
    path = tmp_path / "bad-size.pdb"
    _minimal_pdb(path)
    path.write_bytes(path.read_bytes() + b"extra")
    with pytest.raises(PDBMSFError, match="block count"):
        read_pdb_publics(path)


def test_uninitialised_pad_bytes_are_accepted_but_a_missing_terminator_is_not(tmp_path):
    """MSVC leaves S_PUB32 pad bytes uninitialised; only the terminator counts."""
    name = b"Padded::Fn"
    payload = struct.pack("<HIIH", 0x110E, 2, 0x20, 1) + name + b"\0"
    pad = 0
    while (len(payload) + 2) % 4:
        pad += 1
        payload += bytes([0xF0 + pad])
    assert pad, "pick a name that needs padding"
    path = tmp_path / "padded.pdb"
    _minimal_pdb(path, struct.pack("<H", len(payload)) + payload)
    assert read_pdb_publics(path).publics[0].name == "Padded::Fn"

    # MSVC leaves the pad bytes uninitialised (0x61 'a' is common in the
    # wild); only a missing terminator is corruption.
    stray = payload[:-1] + b"a"
    _minimal_pdb(path, struct.pack("<H", len(stray)) + stray)
    assert read_pdb_publics(path).publics[0].name == "Padded::Fn"

    unterminated = struct.pack("<HIIH", 0x110E, 2, 0x20, 1) + b"NoTerminator"
    _minimal_pdb(path, struct.pack("<H", len(unterminated)) + unterminated)
    with pytest.raises(PDBMSFError, match="padding"):
        read_pdb_publics(path)


def test_directory_block_map_spanning_several_pages(tmp_path):
    """A 1 KiB-block, 400 MB PDB needs 7 block-map pages (LLVM refuses these)."""
    block_size = 512
    entries_per_page = block_size // 4
    # A directory of 300 blocks needs 3 map pages: give one stream 38,000
    # blocks so its block list alone is ~150 KB.
    big_stream_blocks = 38_000
    guid = uuid.UUID("22776620-B648-4C12-98F7-D51833DAFFC9")
    info = struct.pack("<III", 20000404, 1234, 1) + guid.bytes_le
    streams = [b"", info, b"\0" * (big_stream_blocks * block_size)]
    directory = struct.pack("<I", len(streams))
    directory += struct.pack("<{}I".format(len(streams)),
                             *(len(s) for s in streams))
    first_data_block = 64
    info_block = first_data_block
    big_blocks = list(range(info_block + 1, info_block + 1 + big_stream_blocks))
    directory += struct.pack("<I", info_block)
    directory += struct.pack("<{}I".format(big_stream_blocks), *big_blocks)
    dir_blocks_count = (len(directory) + block_size - 1) // block_size
    assert dir_blocks_count > entries_per_page          # needs > 1 map page
    map_pages_count = (dir_blocks_count + entries_per_page - 1) // entries_per_page
    dir_first = big_blocks[-1] + 1
    dir_blocks = list(range(dir_first, dir_first + dir_blocks_count))
    map_pages = list(range(3, 3 + map_pages_count))
    total_blocks = dir_blocks[-1] + 1
    image = bytearray(total_blocks * block_size)
    image[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    struct.pack_into("<6I", image, 32, block_size, 1, total_blocks,
                     len(directory), 0, map_pages[0])
    struct.pack_into("<{}I".format(map_pages_count), image, 52, *map_pages)
    map_bytes = struct.pack("<{}I".format(dir_blocks_count), *dir_blocks)
    for index, page in enumerate(map_pages):
        chunk = map_bytes[index * block_size:(index + 1) * block_size]
        image[page * block_size:page * block_size + len(chunk)] = chunk
    for index, block in enumerate(dir_blocks):
        chunk = directory[index * block_size:(index + 1) * block_size]
        image[block * block_size:block * block_size + len(chunk)] = chunk
    image[info_block * block_size:info_block * block_size + len(info)] = info
    path = tmp_path / "big.pdb"
    path.write_bytes(image)
    assert read_pdb_identity_native(path)["guid"] == str(guid).upper()
