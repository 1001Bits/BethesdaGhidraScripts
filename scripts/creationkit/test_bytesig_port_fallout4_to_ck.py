from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytesig_port_fallout4_to_ck as f4ck
import reciprocal_bytesig_port as shared


def _proposal(source: str, source_rva: int, target_rva: int, name: str):
    parts = tuple(name.split("::"))
    return shared.Proposal(
        source_tag=source,
        source_sha256=("a" if source == "221" else "b") * 64,
        source_program_path="/{}.exe".format(source),
        source_name_type="IMPORTED",
        source_rva=source_rva,
        target_rva=target_rva,
        qualified_name=name,
        local_name=parts[-1],
        namespace=parts[:-1],
        match_kind="exact",
        signature_bytes=32,
    )


def test_fallout4_creation_kit_target_and_sources_are_exactly_pinned():
    assert f4ck.TARGET_SHA256 == (
        "222fd0aad949e76721d85c922ae508ad"
        "a6816ba2f3e1fc11647c7239c24c2e13")
    assert f4ck.TARGET_PRODUCT_VERSION == "1.11.137.0"
    assert f4ck.DEFAULT_TARGET_PATH == (
        "/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe")
    assert f4ck.DEFAULT_SOURCES == (
        ("Fallout4-1.11.221", "/Fallout4/Fallout4_1_11_221.exe"),
        ("Fallout4-1.10.163", "/Fallout4/Fallout4_OG_1_10_163.exe"),
    )
    assert f4ck.CONFIG.default_sources == f4ck.DEFAULT_SOURCES
    assert dict(f4ck.CONFIG.allowed_source_sha256) == {
        "/Fallout4/Fallout4_1_11_221.exe":
            "488015e2010308bfa164d3720cb618deea7e1c098b1d61af530d258a6f17d27b",
        "/Fallout4/Fallout4_OG_1_10_163.exe":
            "5b2a58004f1856e51235132ab304b20c1434017067703e4282e8b0d5bc539623",
    }


def test_target_identity_uses_fallout4_configuration(monkeypatch):
    manifest = {
        "sha256": f4ck.TARGET_SHA256,
        "program_path": f4ck.DEFAULT_TARGET_PATH,
    }
    monkeypatch.setattr(shared, "_program_manifest", lambda *_: manifest)
    assert shared._assert_target_identity(
        object(), f4ck.DEFAULT_TARGET_PATH, config=f4ck.CONFIG) is manifest

    wrong = dict(manifest, sha256=shared.TARGET_SHA256)
    monkeypatch.setattr(shared, "_program_manifest", lambda *_: wrong)
    with pytest.raises(RuntimeError, match="Fallout 4 Creation Kit 1.11.137.0"):
        shared._assert_target_identity(
            object(), f4ck.DEFAULT_TARGET_PATH, config=f4ck.CONFIG)

    monkeypatch.setattr(shared, "_program_manifest", lambda *_: manifest)
    with pytest.raises(RuntimeError, match="expected exact project path"):
        shared._assert_target_identity(
            object(), "/Scratch/CreationKit.exe", config=f4ck.CONFIG)


def test_source_signature_must_be_unique_in_source_text():
    signature = bytes(range(32))
    source_text = signature + b"gap!" + signature
    pairs, rejected = shared._source_unique_exact_pairs(
        [("RE::NamedTwin", 0x1000)], 0x1000, source_text, 32)
    assert pairs == []
    assert rejected == 1

    unique_text = signature + b"different trailing data"
    pairs, rejected = shared._source_unique_exact_pairs(
        [("RE::Unique", 0x1000)], 0x1000, unique_text, 32)
    assert pairs == [("RE::Unique", 0x1000)]
    assert rejected == 0


def test_configured_target_cannot_be_used_as_a_source(monkeypatch):
    monkeypatch.setattr(
        shared, "_program_manifest",
        lambda *_: {"sha256": f4ck.TARGET_SHA256, "program_path": "/source"})
    with pytest.raises(RuntimeError, match="configured target"):
        shared._match_source(
            object(), "bad", "/source", 0x1000, b"A" * 64,
            {0x1000: 64}, {0x1000}, config=f4ck.CONFIG)


def test_wrong_or_unconfigured_source_identity_is_rejected(monkeypatch):
    source_path = f4ck.DEFAULT_SOURCES[0][1]
    monkeypatch.setattr(
        shared, "_program_manifest",
        lambda *_: {"sha256": "f" * 64, "program_path": source_path})
    with pytest.raises(RuntimeError, match="!= pinned"):
        shared._match_source(
            object(), "wrong", source_path, 0x1000, b"A" * 64,
            {0x1000: 64}, {0x1000}, config=f4ck.CONFIG)

    with pytest.raises(ValueError, match="not identity-pinned"):
        shared._parse_source_specs(
            ["unknown=/Fallout4/RenamedWrong.exe"], config=f4ck.CONFIG)


def test_cross_build_name_conflict_is_quarantined():
    rows, decisions, accepted = f4ck.resolve_proposals([
        _proposal("221", 0x100, 0x900, "RE::TESForm::Lookup"),
        _proposal("og", 0x200, 0xA00, "RE::TESForm::Lookup"),
    ])
    assert accepted == []
    assert {decisions[row] for row in rows} == {"rejected_name_conflict"}


def test_fallout4_evidence_is_content_and_target_bound(tmp_path):
    row = _proposal("221", 0x100, 0x900, "RE::TESForm::Lookup")
    rows, decisions, accepted = shared.resolve_proposals([row])
    mapping = {accepted[0]: "would_apply"}
    target = {
        "sha256": f4ck.TARGET_SHA256,
        "program_path": f4ck.DEFAULT_TARGET_PATH,
        "program_name": "CreationKit.exe",
        "identity_kind": "ghidra_program_executable_sha256",
        "image_base": 0x140000000,
        "sections": [],
    }
    source = {
        "sha256": "a" * 64,
        "program_path": f4ck.DEFAULT_SOURCES[0][1],
        "program_name": "Fallout4.exe",
        "identity_kind": "ghidra_program_executable_sha256",
        "image_base": 0x140000000,
        "sections": [],
    }
    artifact = tmp_path / "f4ck.csv"
    shared._write_evidence(
        artifact, rows, decisions, mapping,
        {accepted[0]: "FUN_140000900"}, target, [source], [], "dry_run",
        config=f4ck.CONFIG)

    with artifact.open("r", encoding="utf-8", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    assert csv_rows[0]["target_sha256"] == f4ck.TARGET_SHA256
    sidecar_path = Path(str(artifact) + ".identity.json")
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert sidecar["artifact_sha256"] == hashlib.sha256(
        artifact.read_bytes()).hexdigest()
    assert sidecar["expected_target"] == {
        "product_version": "1.11.137.0",
        "sha256": f4ck.TARGET_SHA256,
    }


def test_live_wrapper_delegates_dry_run_with_fallout4_config(monkeypatch):
    captured = {}

    def fake_run_live(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(shared, "run_live", fake_run_live)
    assert f4ck.run_live("program", "state") == {"ok": True}
    assert captured["config"] is f4ck.CONFIG
    assert captured["apply"] is False
    assert captured["save"] is False
    assert captured["source_specs"] is None


def test_cli_wrapper_delegates_fallout4_description_and_config(monkeypatch):
    captured = {}

    def fake_main(**kwargs):
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(shared, "main", fake_main)
    assert f4ck.main(["--help"]) == 7
    assert captured["argv"] == ["--help"]
    assert captured["config"] is f4ck.CONFIG
    assert "Fallout 4 Creation Kit" in captured["description"]
