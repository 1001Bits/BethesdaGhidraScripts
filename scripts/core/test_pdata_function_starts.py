"""`.pdata` function-START sets must exclude chained unwind fragments (I1) and
agree on UWOP_SET_FPREG with a reserved non-zero OpInfo (I8); an absolute
S_PUB32 must not discard a whole PDB (I2)."""

import importlib.util
import os
import struct
import sys

import pytest

_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
_SF_DIR = os.path.join(os.path.dirname(_CORE_DIR), 'commonlibsf')
sys.path.insert(0, _CORE_DIR)

import binary_identity  # noqa: E402
import pe_unwind  # noqa: E402
from pdb_msf import (MAX_SKIPPED_PUBLICS, PDBMSFError,  # noqa: E402
                     SkippedPublicsWarning, read_pdb_publics)
from test_pdb_msf import _minimal_pdb, _record  # noqa: E402


def _load_sf_pe_layout():
    spec = importlib.util.spec_from_file_location(
        'bgs_sf_pe_layout', os.path.join(_SF_DIR, 'pe_layout.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # dataclasses resolve cls.__module__
    spec.loader.exec_module(module)
    return module


def _section(name, virtual_size, rva, raw_size, raw_offset, chars):
    return struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\0"), virtual_size,
                       rva, raw_size, raw_offset, 0, 0, 0, 0, chars)


def _pe(path, runtime_functions, unwind_blobs):
    """AMD64 PE with .text@0x1000, .pdata@0x2000, .xdata@0x3000."""
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
    struct.pack_into("<II", data, opt + 112 + 3 * 8, 0x2000,
                     12 * len(runtime_functions))
    sh = opt + 0xF0
    data[sh:sh + 40] = _section(b".text", 0x200, 0x1000, 0x200, 0x400,
                                0x60000020)
    data[sh + 40:sh + 80] = _section(b".pdata", 0x200, 0x2000, 0x200,
                                     0x600, 0x40000040)
    data[sh + 80:sh + 120] = _section(b".xdata", 0x200, 0x3000, 0x200,
                                      0x800, 0x40000040)
    for index, row in enumerate(runtime_functions):
        struct.pack_into("<III", data, 0x600 + 12 * index, *row)
    for offset, blob in unwind_blobs.items():
        data[0x800 + offset:0x800 + offset + len(blob)] = blob
    path.write_bytes(data)
    return str(path)


def _chained_fixture(tmp_path):
    # 0x1000-0x1040: real function.  0x1040-0x1080: a CHAININFO fragment of
    # it (flags = 4 -> first byte 0x21), chained back to the parent record.
    parent = bytes([0x01, 0, 0, 0])
    fragment = bytes([0x21, 0, 0, 0]) + struct.pack(
        "<III", 0x1000, 0x1040, 0x3000)
    return _pe(tmp_path / "chained.exe",
               [(0x1000, 0x1040, 0x3000), (0x1040, 0x1080, 0x3010)],
               {0x00: parent, 0x10: fragment})


def test_chained_fragment_is_not_a_function_start_in_any_extractor(tmp_path):
    pe = _chained_fixture(tmp_path)
    assert binary_identity.inspect_pe(pe)["function_starts"] == [0x1000]
    assert pe_unwind.validated_runtime_function_starts(pe) == {0x1000}
    assert _load_sf_pe_layout().x64_runtime_function_starts(pe) == {0x1000}


def test_chained_fragment_stays_available_as_a_range(tmp_path):
    pe = _chained_fixture(tmp_path)
    assert pe_unwind.validated_runtime_function_starts(
        pe, include_chained=True) == {0x1000, 0x1040}
    result = pe_unwind.extract_runtime_functions(pe)
    assert result["rejected"] == []
    rows = {row["begin_rva"]: row for row in result["runtime_functions"]}
    assert sorted(rows) == [0x1000, 0x1040]
    # pe_unwind_enrich.py reads exactly this shape.
    assert rows[0x1040]["unwind"]["chained"] == {
        "begin_rva": 0x1000, "end_rva": 0x1040, "unwind_rva": 0x3000}
    assert pe_unwind.is_function_start(rows[0x1000])
    assert not pe_unwind.is_function_start(rows[0x1040])


def test_old_sidecar_fragment_starts_are_recomputed_on_load(tmp_path):
    """function_starts is advisory: a pre-filter sidecar keeps verifying, but
    its stale start set must never reach an importer (1.7.104: 122,238 stored
    starts vs 93,770 real ones)."""
    pe = _chained_fixture(tmp_path)
    actual = binary_identity.inspect_pe(pe)
    legacy = dict(actual, function_starts=[0x1000, 0x1040])
    assert binary_identity.manifest_matches(legacy, actual) == (True, [])
    assert "function_starts" not in binary_identity.canonical_identity(legacy)

    source = tmp_path / "packed.exe"
    source.write_bytes(open(pe, "rb").read())
    sidecar = binary_identity.make_artifact_sidecar(
        str(source), pe, cache_policy=1, arguments=[],
        producer={"name": "Steamless.CLI", "sha256": "c" * 64})
    for side in ("source", "artifact"):
        sidecar[side]["function_starts"] = [0x1000, 0x1040]   # old extractor
    binary_identity.write_manifest(pe + ".identity.json", sidecar)

    assert binary_identity.artifact_is_fresh(str(source), pe)
    lineage = binary_identity.load_fresh_lineage(str(source), pe)
    assert lineage["artifact"]["function_starts"] == [0x1000]
    assert lineage["source"]["function_starts"] == [0x1000]
    assert lineage["artifact"]["sha256"] == actual["sha256"]

    source.write_bytes(open(pe, "rb").read() + b"\0")        # source drifted
    assert binary_identity.load_fresh_lineage(str(source), pe) is None


def test_set_fpreg_with_reserved_op_info_is_still_a_start(tmp_path):
    # one UWOP_SET_FPREG (op 3) whose reserved OpInfo nibble is non-zero,
    # frame register RBP (5).
    unwind = bytes([0x01, 4, 1, 0x05, 4, 0x13, 0, 0])
    pe = _pe(tmp_path / "fpreg.exe", [(0x1000, 0x1040, 0x3000)],
             {0x00: unwind})
    expected = {0x1000}
    assert set(binary_identity.inspect_pe(pe)["function_starts"]) == expected
    assert pe_unwind.validated_runtime_function_starts(pe) == expected
    assert _load_sf_pe_layout().x64_runtime_function_starts(pe) == expected


def test_absolute_public_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "absolute.pdb"
    symbols = (_record() +
               _record(name=b"__guard_fids_table", offset=0, segment=2) +
               _record(name=b"__tls_array", offset=0x58, segment=0))
    _minimal_pdb(path, symbols)
    with pytest.warns(SkippedPublicsWarning, match="skipped 2 .* of 3"):
        corpus = read_pdb_publics(path)
    assert [public.name for public in corpus.publics] == ["Test::Function"]
    assert corpus.skipped_publics == 2


def test_mostly_sectionless_publics_refuse_the_pdb(tmp_path):
    path = tmp_path / "wrong_sections.pdb"
    symbols = _record() + b"".join(
        _record(name="abs_{}".format(i).encode(), offset=i, segment=0)
        for i in range(MAX_SKIPPED_PUBLICS + 1))
    _minimal_pdb(path, symbols)
    with pytest.raises(PDBMSFError, match="name no image section"):
        read_pdb_publics(path)
