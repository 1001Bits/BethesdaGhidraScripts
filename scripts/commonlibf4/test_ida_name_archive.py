from __future__ import annotations

import json
from pathlib import Path

import pytest

import ida_name_archive as corpus


APPROVED_221 = (
    "428f9996cc4248e26c0f62f9fdd3eaf0e5eb305834b67ee5996538e593218b61")


def _manifest() -> dict:
    return {
        "sha256": APPROVED_221,
        "file_name": "Fallout4.exe",
        "file_size": 0x7000,
        "machine": 0x8664,
        "pointer_size": 8,
        "image_base": 0x140000000,
        "image_size": 0x7000,
        "timestamp": 123456,
        "file_version": [1, 11, 221, 0],
        "version_string": "1.11.221.0",
        "sections": [
            {
                "name": ".text", "rva": 0x1000,
                "virtual_size": 0x2000, "raw_size": 0x2000,
                "raw_offset": 0x400, "characteristics": 0x60000020,
                "readable": True, "writable": False, "executable": True,
            },
            {
                "name": ".data", "rva": 0x4000,
                "virtual_size": 0x1000, "raw_size": 0x1000,
                "raw_offset": 0x2400, "characteristics": 0xC0000040,
                "readable": True, "writable": True, "executable": False,
            },
        ],
        "anchors": [{"rva": 0x1000, "bytes": "90" * 16,
                     "section": ".text"}],
        "function_starts": [0x1100, 0x1200, 0x1400, 0x1500, 0x1600,
                            0x1700],
    }


def _raw(address: int, name: str, line: int) -> dict:
    return {
        "source_address": address,
        "raw_name": "{}_{:06X}".format(name, address),
        "line": line,
    }


def _locked_source(version: str = "1.11.221.0") -> dict:
    lock = corpus.load_source_lock()
    entry = next(
        row for row in lock["entries"] if row["version"] == version)
    return {
        "archive_name": lock["artifact"]["name"],
        "archive_sha256": lock["artifact"]["sha256"],
        "entry_name": entry["name"],
        "entry_sha256": entry["sha256"],
        "license": "unknown",
        "redistribution_allowed": False,
        "raw_input_policy": "local-only",
    }


def test_source_lock_pins_unlicensed_external_input():
    lock = corpus.load_source_lock()
    assert lock["artifact"] == {
        "name": "ida-import-fallout4.zip",
        "sha256": (
            "274ac8d9d917f25c1dce93618f4fa6749a83cb85f361d277b45d5136e08b43d6"),
        "size": 401821,
        "image_base": 0x140000000,
        "entry_count": 7,
    }
    assert lock["provenance"]["license"] == "unknown"
    assert lock["provenance"]["redistribution_allowed"] is False
    assert lock["provenance"]["raw_input_policy"] == "local-only"
    assert len(lock["entries"]) == 7
    by_version = {row["version"]: row for row in lock["entries"]}
    assert by_version["1.11.191.0"]["records"] == 3825
    assert by_version["1.11.191.0"]["bare_rva_records"] == 75
    assert by_version["1.11.221.0"]["sha256"] == (
        "475cf101acb697c752569fb5ee0b2cb241bff3d13f73998b5707f12bd36106ca")
    # Unknown target identities remain unusable even though their source
    # entries are hash-pinned.
    assert by_version["1.10.984.0"]["approved_target_sha256"] == []


def test_ast_parser_accepts_only_the_generated_constant_call_grammar():
    source = b"""\
def NAME(ea, name):
    idc.set_name(ea, name, SN_CHECK)

print('Importing names...')
NAME(0x140001100, 'SafeName_140001100')
print('Done with name import')
"""
    assert corpus._parse_ida_script(source, "safe.py") == [{
        "source_address": 0x140001100,
        "raw_name": "SafeName_140001100",
        "line": 5,
    }]
    with pytest.raises(corpus.IDANameArchiveError, match="non-allowlisted"):
        corpus._parse_ida_script(
            source.replace(b"print('Importing names...')",
                           b"import os\nprint('Importing names...')"),
            "unsafe.py")
    with pytest.raises(corpus.IDANameArchiveError, match="unexpected NAME"):
        corpus._parse_ida_script(
            source.replace(b"idc.set_name", b"open"), "unsafe.py")


def test_mixed_va_rva_normalization_is_section_and_boundary_aware():
    base = 0x140000000
    rows = [
        _raw(base + 0x1100, "UniqueVA", 1),
        _raw(0x1200, "UniqueRVA", 2),
        _raw(base + 0x1300, "NotAValidatedStart", 3),
        _raw(base + 0x4100, "GlobalLabel", 4),
        _raw(base + 0x1400, "Duplicate", 5),
        _raw(base + 0x1500, "Duplicate", 6),
        _raw(base + 0x1600, "AliasOne", 7),
        _raw(base + 0x1600, "AliasTwo", 8),
        _raw(base + 0x9000, "Outside", 9),
        {
            "source_address": base + 0x1700,
            "raw_name": "BrokenSuffix_DEADBEEF", "line": 10,
        },
    ]
    payload = corpus._normalize_records(
        rows, "1.11.221.0", _manifest(), _locked_source())
    accepted = payload["records"]
    assert [(row["rva"], row["name"], row["kind"]) for row in accepted] == [
        (0x1100, "UniqueVA", "func"),
        (0x1200, "UniqueRVA", "func"),
        (0x4100, "GlobalLabel", "label"),
    ]
    assert accepted[0]["source_coordinate"] == "VA"
    assert accepted[1]["source_coordinate"] == "RVA"
    assert payload["counts"]["functions"] == 2
    assert payload["counts"]["labels"] == 1
    assert payload["counts"]["quarantined_records"] == 7
    reasons = payload["counts"]["quarantine_reasons"]
    assert reasons["not_runtime_function_start"] == 1
    assert reasons["same_name_multiple_rvas"] == 2
    assert reasons["same_rva_alias"] == 2
    assert reasons["address_suffix_mismatch"] == 1


def test_normalized_loader_requires_content_source_and_exact_target(tmp_path):
    base = 0x140000000
    payload = corpus._normalize_records(
        [_raw(base + 0x1100, "Function", 1),
         _raw(base + 0x4100, "Global", 2)],
        "1.11.221.0", _manifest(), _locked_source())
    path = tmp_path / "normalized.json"
    corpus._atomic_json(path, payload)
    corpus.bind_for_hash(
        str(path), corpus.KIND, APPROVED_221,
        program_name="Fallout4.exe", image_base=base, pointer_size=8,
        address_coordinate="RVA")

    records = corpus.load_normalized_evidence(
        path, _manifest(), expected_version="1.11.221.0")
    assert [(row["rva"], row["kind"]) for row in records] == [
        (0x1100, "func"), (0x4100, "label")]

    another = dict(_manifest())
    another["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="another PE"):
        corpus.load_normalized_evidence(path, another)

    value = json.loads(path.read_text(encoding="utf-8"))
    value["records"][0]["name"] = "Tampered"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="content changed"):
        corpus.load_normalized_evidence(path, _manifest())


def test_hash_qualified_selection_keeps_packed_and_unpacked_separate(tmp_path):
    version = "1.11.221.0"
    packed = _manifest()
    unpacked = dict(packed)
    unpacked["sha256"] = (
        "488015e2010308bfa164d3720cb618deea7e1c098b1d61af530d258a6f17d27b")
    base = int(packed["image_base"])

    generic = corpus.normalized_evidence_path(version, tmp_path)
    packed_payload = corpus._normalize_records(
        [_raw(base + 0x1100, "Packed", 1)], version, packed,
        _locked_source())
    corpus._atomic_json(generic, packed_payload)
    corpus.bind_for_hash(
        str(generic), corpus.KIND, packed["sha256"],
        program_name="Fallout4.exe", image_base=base, pointer_size=8,
        address_coordinate="RVA")

    qualified = corpus.normalized_evidence_path(
        version, tmp_path, target_sha256=unpacked["sha256"])
    unpacked_payload = corpus._normalize_records(
        [_raw(base + 0x1200, "Unpacked", 1)], version, unpacked,
        _locked_source())
    corpus._atomic_json(qualified, unpacked_payload)
    corpus.bind_for_hash(
        str(qualified), corpus.KIND, unpacked["sha256"],
        program_name="Fallout4.exe.unpacked.exe", image_base=base,
        pointer_size=8, address_coordinate="RVA")

    assert corpus.select_normalized_evidence_path(
        version, packed["sha256"], tmp_path) == generic
    assert corpus.select_normalized_evidence_path(
        version, unpacked["sha256"], tmp_path) == qualified
    corpus._validate_output_destination(generic, version, packed["sha256"])
    with pytest.raises(corpus.IDANameArchiveError, match="another PE"):
        corpus._validate_output_destination(
            generic, version, unpacked["sha256"])
    with pytest.raises(corpus.IDANameArchiveError, match="SHA-qualified"):
        corpus._validate_output_destination(
            corpus.normalized_evidence_path(version, tmp_path / "new"),
            version, packed["sha256"])
    qualified.unlink()
    Path(str(qualified) + ".identity.json").unlink()
    # A valid generic artifact for the packed sibling is not an error and is
    # never selected for the unpacked target.
    assert corpus.select_normalized_evidence_path(
        version, unpacked["sha256"], tmp_path) is None


def test_bytesig_consumer_prefers_normalized_bound_functions(
        tmp_path, monkeypatch):
    import run_bytesig_port as consumer

    manifest = _manifest()
    manifest["sha256"] = (
        "81694b37816c8045855905a52c5fb13583c5803121fabb5024760892014e9bc6")
    manifest["file_version"] = [1, 11, 191, 0]
    manifest["version_string"] = "1.11.191.0"
    base = int(manifest["image_base"])
    payload = corpus._normalize_records(
        [_raw(base + 0x1100, "Function", 1),
         _raw(base + 0x4100, "Global", 2)],
        "1.11.191.0", manifest, _locked_source("1.11.191.0"))
    path = tmp_path / "f4_ida_names_1.11.191.0.json"
    corpus._atomic_json(path, payload)
    corpus.bind_for_hash(
        str(path), corpus.KIND, manifest["sha256"],
        program_name="Fallout4.exe", image_base=base, pointer_size=8,
        address_coordinate="RVA")
    monkeypatch.setattr(consumer, "IDA_NORMALIZED_DIR", tmp_path)

    assert consumer._load_ida_names(manifest) == {"Function": 0x1100}
