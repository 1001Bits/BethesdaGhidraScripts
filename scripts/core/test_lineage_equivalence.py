"""Evidence-bound lineage: a source import is accepted only on a byte-level proof."""
import shutil
import struct
from pathlib import Path

import pytest

import binary_identity
import ghidra_import_gen

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "exes" / "skyrim" / "17104" / "SkyrimSE.exe"
ARTIFACT = REPO / "exes" / "skyrim" / "17104" / "SkyrimSE.exe.unpacked.exe"
staged = pytest.mark.skipif(
    not (SOURCE.is_file() and ARTIFACT.is_file()),
    reason="Skyrim 1.7.104 source/artifact pair is not staged")


@staged
def test_header_only_steamless_artifact_is_proved_equivalent():
    proof = binary_identity.prove_section_equivalence(str(SOURCE), str(ARTIFACT))
    assert proof["proof"] == "all sections byte-identical"
    assert proof["source_sha256"] != proof["artifact_sha256"]
    assert proof["sections"] == 9 and proof["section_bytes"] > 30_000_000


@staged
def test_one_differing_section_byte_refutes_the_proof(tmp_path):
    tampered = tmp_path / "tampered.exe"
    shutil.copyfile(ARTIFACT, tampered)
    layout = binary_identity.inspect_pe(str(tampered))
    offset = int(layout["sections"][0]["raw_offset"]) + 0x1000
    with open(tampered, "r+b") as handle:
        handle.seek(offset)
        byte = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([byte[0] ^ 0xFF]))
    assert binary_identity.prove_section_equivalence(str(SOURCE), str(tampered)) is None


def _manifest(sha, name):
    return {"sha256": sha, "file_size": 10, "pointer_size": 8, "image_base": 0x140000000,
            "image_size": 0x3000, "machine": 0x8664, "file_name": name,
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x100,
                          "raw_size": 0x200}],
            "anchors": [{"rva": 0x1000, "bytes": "90", "section": ".text"}],
            "function_starts": []}


def _generate(tmp_path, lineage):
    out = tmp_path / "importer.py"
    ghidra_import_gen.generate_script(
        {}, {}, {}, str(out), "17104", "[]", "[]", "",
        target_manifest=lineage)
    return out.read_text(encoding="utf-8")


def test_proved_source_becomes_a_second_allowed_identity(tmp_path):
    from importer_binding import extract_target_manifests
    source, artifact = _manifest("a" * 64, "packed.exe"), _manifest("b" * 64, "unpacked.exe")
    proof = {"proof": "all sections byte-identical", "source_sha256": "a" * 64,
             "artifact_sha256": "b" * 64, "sections": 1, "section_bytes": 0x200,
             "sections_sha256": "c" * 64}
    out = tmp_path / "importer.py"
    ghidra_import_gen.generate_script(
        {}, {}, {}, str(out), "17104", "[]", "[]", "",
        target_manifest={"source": source, "artifact": artifact, "equivalence": proof})
    manifests = extract_target_manifests(out)
    assert [m["sha256"] for m in manifests] == ["b" * 64, "a" * 64]
    assert manifests[1]["equivalent_to"] == "b" * 64
    assert "equivalent_to" not in manifests[0]


def test_lineage_without_a_proof_still_accepts_only_the_artifact(tmp_path):
    from importer_binding import extract_target_manifests
    out = tmp_path / "importer.py"
    ghidra_import_gen.generate_script(
        {}, {}, {}, str(out), "17104", "[]", "[]", "",
        target_manifest={"source": _manifest("a" * 64, "p.exe"),
                         "artifact": _manifest("b" * 64, "u.exe")})
    assert [m["sha256"] for m in extract_target_manifests(out)] == ["b" * 64]


def test_a_proof_for_other_files_is_rejected(tmp_path):
    proof = {"proof": "all sections byte-identical", "source_sha256": "d" * 64,
             "artifact_sha256": "b" * 64, "sections_sha256": "c" * 64}
    with pytest.raises(ValueError, match="equivalence proof"):
        ghidra_import_gen.generate_script(
            {}, {}, {}, str(tmp_path / "x.py"), "17104", "[]", "[]", "",
            target_manifest={"source": _manifest("a" * 64, "p.exe"),
                             "artifact": _manifest("b" * 64, "u.exe"),
                             "equivalence": proof})


@staged
def test_real_pair_differs_only_in_steamless_header_fields():
    proof = binary_identity.prove_section_equivalence(str(SOURCE), str(ARTIFACT))
    assert proof["header_differences"] == ["entry_point", "checksum"]
    assert proof["source_entry_rva"] != proof["artifact_entry_rva"]
    # The artifact's entry is not in a live .bind stub: never the other way.
    assert binary_identity.prove_section_equivalence(str(ARTIFACT), str(SOURCE)) is None


# --- synthetic packed/unpacked pair: .text + .bind, headers under test -------
_OPT = 0x98                      # optional header offset (e_lfanew 0x80 + 24)


def _write_pair_pe(path, entry, checksum=0x1234, import_rva=0x1100,
                   dos_stub=b"stub"):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    data[0x40:0x40 + len(dos_stub)] = dos_stub
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0x12345678, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, _OPT, 0x20B)
    struct.pack_into("<I", data, _OPT + 16, entry)
    struct.pack_into("<Q", data, _OPT + 24, 0x140000000)
    struct.pack_into("<I", data, _OPT + 56, 0x3000)
    struct.pack_into("<I", data, _OPT + 64, checksum)
    struct.pack_into("<I", data, _OPT + 108, 16)
    struct.pack_into("<II", data, _OPT + 112 + 8, import_rva, 0x28)  # import dir
    sh = _OPT + 0xF0
    for index, (name, rva, raw) in enumerate(((b".text", 0x1000, 0x400),
                                              (b".bind", 0x2000, 0x600))):
        struct.pack_into("<8sIIIIIIHHI", data, sh + 40 * index, name, 0x200,
                         rva, 0x200, raw, 0, 0, 0, 0, 0x60000020)
    data[0x400:0x404] = b"\xCC\xCC\xC3\x90"
    data[0x600:0x604] = b"\xE9\x00\x00\x00"
    path.write_bytes(data)
    return str(path)


def test_header_only_pair_is_equivalent_but_data_directories_must_agree(tmp_path):
    source = _write_pair_pe(tmp_path / "packed.exe", entry=0x2010)
    artifact = _write_pair_pe(tmp_path / "unpacked.exe", entry=0x1000,
                              checksum=0, dos_stub=b"\0\0\0\0")
    proof = binary_identity.prove_section_equivalence(source, artifact)
    assert proof["header_differences"] == ["entry_point", "checksum"]

    moved_imports = _write_pair_pe(tmp_path / "imports.exe", entry=0x1000,
                                   checksum=0, import_rva=0x1180)
    assert binary_identity.prove_section_equivalence(source, moved_imports) is None


def test_entry_point_may_only_move_out_of_a_live_bind_stub(tmp_path):
    artifact = _write_pair_pe(tmp_path / "unpacked.exe", entry=0x1000)
    not_bind = _write_pair_pe(tmp_path / "other.exe", entry=0x1010)
    assert binary_identity.prove_section_equivalence(not_bind, artifact) is None
    source = _write_pair_pe(tmp_path / "packed.exe", entry=0x2010)
    into_bind = _write_pair_pe(tmp_path / "rebound.exe", entry=0x2020)
    assert binary_identity.prove_section_equivalence(source, into_bind) is None
    same = _write_pair_pe(tmp_path / "same.exe", entry=0x2010)
    assert binary_identity.prove_section_equivalence(source, same)[
        "header_differences"] == []
