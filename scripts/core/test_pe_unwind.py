import struct

import pytest

import binary_identity
import pe_unwind
import pe_unwind_enrich


def test_parse_unwind_handler_and_alloc_small():
    # version=1, EHANDLER, one ALLOC_SMALL(info=3), one alignment slot,
    # followed by a handler RVA.
    data = bytes([0x09, 7, 1, 0, 4, 0x32, 0, 0]) + struct.pack("<I", 0x1234)
    info = pe_unwind.parse_unwind_info(data)
    assert info["version"] == 1
    assert info["flags"] == pe_unwind.UNW_FLAG_EHANDLER
    assert info["codes"][0]["op_name"] == "ALLOC_SMALL"
    assert info["codes"][0]["value"] == 32
    assert info["handler_rva"] == 0x1234


def test_parse_unwind_rejects_incompatible_flags():
    data = bytes([0x29, 0, 0, 0]) + b"\0" * 12
    with pytest.raises(ValueError, match="CHAININFO"):
        pe_unwind.parse_unwind_info(data)


def _section(name, virtual_size, rva, raw_size, raw_offset, chars):
    return struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\0"), virtual_size,
                       rva, raw_size, raw_offset, 0, 0, 0, 0, chars)


def _minimal_amd64_pe(path):
    data = bytearray(0xA00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0x12345678,
                     0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<I", data, opt + 56, 0x4000)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 3 * 8, 0x2000, 12)
    sh = opt + 0xF0
    data[sh:sh + 40] = _section(b".text", 0x200, 0x1000, 0x200, 0x400,
                                0x60000020)
    data[sh + 40:sh + 80] = _section(b".pdata", 0x200, 0x2000, 0x200,
                                     0x600, 0x40000040)
    data[sh + 80:sh + 120] = _section(b".xdata", 0x200, 0x3000, 0x200,
                                      0x800, 0x40000040)
    struct.pack_into("<III", data, 0x600, 0x1000, 0x1010, 0x3000)
    data[0x800:0x804] = bytes([1, 0, 0, 0])
    path.write_bytes(data)


def test_extract_runtime_function_from_minimal_pe(tmp_path):
    pe = tmp_path / "fixture.exe"
    _minimal_amd64_pe(pe)
    result = pe_unwind.extract_runtime_functions(str(pe))
    assert result["rejected"] == []
    assert len(result["runtime_functions"]) == 1
    row = result["runtime_functions"][0]
    assert (row["begin_rva"], row["end_rva"], row["size"]) == (
        0x1000, 0x1010, 0x10)
    assert row["unwind"]["version"] == 1
    assert binary_identity.inspect_pe(str(pe))["function_starts"] == [0x1000]


def test_extract_ignores_pdata_without_exception_directory(tmp_path):
    pe = tmp_path / "fixture.exe"
    _minimal_amd64_pe(pe)
    blob = bytearray(pe.read_bytes())
    opt = 0x98
    struct.pack_into("<II", blob, opt + 112 + 3 * 8, 0, 0)
    pe.write_bytes(blob)
    result = pe_unwind.extract_runtime_functions(str(pe))
    assert result["runtime_functions"] == []
    assert result["note"] == "no PE exception directory"
    assert binary_identity.inspect_pe(str(pe))["function_starts"] == []


def test_parse_unwind_rejects_reserved_opcode():
    data = bytes([1, 1, 1, 0, 0, 0x0B, 0, 0])
    with pytest.raises(ValueError, match="unsupported unwind opcode"):
        pe_unwind.parse_unwind_info(data)


def test_unwind_mutator_treats_command_failure_as_fatal():
    with pytest.raises(RuntimeError, match="rolling back"):
        pe_unwind_enrich._require_command_success(False, "function creation")
