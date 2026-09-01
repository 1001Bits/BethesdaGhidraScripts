import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from binary_identity import inspect_pe
from symbol_export import (
    _public_target_manifest,
    _write_text_atomic,
    build_fakepdb_root,
    collect_segments,
    generate_shareable_pdb,
    package_symbol_bundle,
    select_shareable_symbols,
    write_outputs,
)


def test_symbol_exports_are_atomic_and_target_bound(tmp_path):
    target = {
        "sha256": "a" * 64,
        "file_size": 123,
        "image_base": 0x140000000,
        "image_size": 0x5000,
    }
    paths = write_outputs(
        tmp_path, "Game.exe", target["image_base"],
        [{"rva": 0x1000, "name": "RE::Start"}],
        [{"rva": 0x3000, "name": "VTABLE_RE::Actor", "kind": "vtable"}],
        target)

    symbols = json.loads(Path(paths[0]).read_text(encoding="utf-8"))
    assert symbols["target"]["sha256"] == "a" * 64
    assert "target_sha256=" + "a" * 64 in Path(paths[1]).read_text(
        encoding="utf-8")
    assert set(json.loads(Path(paths[2]).read_text(encoding="utf-8"))) == {
        "labels"}

    identity = json.loads(
        (tmp_path / "Game.export.identity.json").read_text(encoding="utf-8"))
    assert identity["target"]["sha256"] == "a" * 64
    for path in paths:
        assert identity["outputs"][Path(path).name] == hashlib.sha256(
            Path(path).read_bytes()).hexdigest()


def test_fakepdb_segments_come_only_from_verified_manifest():
    manifest = {
        "pointer_size": 8, "image_size": 0x3000,
        "sections": [
            {"name": ".text", "rva": 0x1000, "virtual_size": 0x1000,
             "raw_size": 0x800, "readable": True, "writable": False,
             "executable": True},
            {"name": ".rdata", "rva": 0x2000, "virtual_size": 0x1800,
             "raw_size": 0x400, "readable": True, "writable": False,
             "executable": False},
        ],
    }
    segments = collect_segments(manifest)
    assert [segment["name"] for segment in segments] == [".text", ".rdata"]
    assert [segment["selector"] for segment in segments] == [1, 2]
    assert [segment["start_rva"] for segment in segments] == [0x1000, 0x2000]
    assert all("permission" not in segment and "rva_end" not in segment
               for segment in segments)
    root = build_fakepdb_root("Game.exe", 64, segments, [], [])
    assert set(root) == {"general", "segments", "exports", "functions", "names"}
    assert "pe" not in root


def test_symbol_export_module_cannot_escape_output_directory(tmp_path):
    paths = write_outputs(
        tmp_path, "../outside.exe", 0x140000000, [], [],
        {"sha256": "b" * 64, "image_size": 0x1000})
    assert all(Path(path).parent == tmp_path for path in paths)
    assert (tmp_path / "outside.symbols.json").is_file()


def test_shareable_symbol_selection_is_safe_and_order_independent():
    manifest = {
        "sections": [
            {"name": ".text", "rva": 0x1000, "virtual_size": 0x1000,
             "raw_size": 0x1000, "executable": True},
            {"name": ".data", "rva": 0x3000, "virtual_size": 0x1000,
             "raw_size": 0x1000, "executable": False},
        ]}
    functions = [
        {"rva": 0x1000, "name": "Safe", "source": "IMPORTED"},
        {"rva": 0x1100, "name": "SameRvaA", "source": "USER_DEFINED"},
        {"rva": 0x1100, "name": "SameRvaB", "source": "IMPORTED"},
        {"rva": 0x1200, "name": "Repeated", "source": "IMPORTED"},
        {"rva": 0x1300, "name": "Repeated", "source": "IMPORTED"},
        {"rva": 0x1400, "name": "Heuristic", "source": "ANALYSIS"},
        {"rva": 0x3000, "name": "NotCode", "source": "IMPORTED"},
    ]
    labels = [{"rva": 0x3000, "name": "Global", "source": "USER_DEFINED",
               "kind": "data"}]
    selected_f, selected_l, report = select_shareable_symbols(
        functions, labels, manifest)
    reverse_f, reverse_l, reverse_report = select_shareable_symbols(
        list(reversed(functions)), list(reversed(labels)), manifest)
    assert selected_f == reverse_f == [
        {"rva": 0x1000, "name": "Safe", "source": "IMPORTED"}]
    assert selected_l == reverse_l == [
        {"rva": 0x3000, "name": "Global", "source": "USER_DEFINED",
         "kind": "data"}]
    assert report == reverse_report
    assert report["same_rva_alias_groups"] == 1
    assert report["same_name_multi_rva_groups"] == 1
    assert report["source_filtered"] == 1
    assert report["location_filtered"] == 1


def test_public_target_manifest_omits_executable_evidence_bytes():
    target = {"sha256": "c" * 64, "image_size": 0x2000,
              "anchors": [{"rva": 1, "bytes": "deadbeef"}],
              "function_starts": [0x1000], "data_directories": [{"rva": 1}]}
    public = _public_target_manifest(target)
    assert public["sha256"] == "c" * 64
    assert "anchors" not in public
    assert "function_starts" not in public
    assert "data_directories" not in public


def test_symbol_bundle_revision_is_explicit_and_checksummed(tmp_path):
    pdb = tmp_path / "Game.pdb"
    identity = tmp_path / "Game.pdb.identity.json"
    symbols = tmp_path / "Game.symbols.json"
    pdb.write_bytes(b"pdb")
    identity.write_text("{}\n", encoding="utf-8")
    symbols.write_text("{}\n", encoding="utf-8")
    target = {
        "sha256": "d" * 64,
        "version_string": "1.2.3.4",
    }
    bundle = package_symbol_bundle(
        tmp_path, "Game.exe", pdb, identity, symbols, target, revision=2)
    assert bundle.name == (
        "Game-1.2.3.4-dddddddddddd-community-symbols-r2.zip")
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == {
            "Game.pdb", "Game.pdb.identity.json", "Game.symbols.json",
            "README.txt"}
        assert "Symbol bundle revision: r2" in archive.read(
            "README.txt").decode("utf-8")
    checksum = Path(str(bundle) + ".sha256").read_text(
        encoding="utf-8").split()[0]
    assert checksum == hashlib.sha256(bundle.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="revision"):
        package_symbol_bundle(
            tmp_path, "Game.exe", pdb, identity, symbols, target,
            revision=0)


def test_pinned_fakepdb_real_round_trip_when_local_tool_and_target_exist(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    executable = repo / "exes" / "f4" / "221" / "Fallout4.exe"
    tool = repo / "tools" / "fakepdb" / "fakepdb.exe"
    if not executable.is_file() or not tool.is_file():
        pytest.skip("local exact F4 target/FakePDB installation unavailable")
    manifest = inspect_pe(str(executable))
    functions = [{"rva": 0x1000, "name": "RoundTrip::Function",
                  "source": "IMPORTED"}]
    labels = [{"rva": 0x2438000, "name": "RoundTripData",
               "source": "USER_DEFINED", "kind": "data"}]
    segments = collect_segments(manifest)
    root = build_fakepdb_root("Fallout4.exe", 64, segments,
                              functions, labels)
    input_json = tmp_path / "Fallout4.fakepdb.json"
    _write_text_atomic(input_json, json.dumps(root) + "\n")
    output, identity = generate_shareable_pdb(
        executable, input_json, tmp_path / "Fallout4.pdb",
        functions, labels, manifest,
        {"selected_functions": 1, "selected_labels": 1})
    assert output.is_file() and identity.is_file()
    document = json.loads(identity.read_text(encoding="utf-8"))
    assert document["pdb"]["publics"] == 2
    assert document["codeview"]["expected_pdb"] == "Fallout4.pdb"
