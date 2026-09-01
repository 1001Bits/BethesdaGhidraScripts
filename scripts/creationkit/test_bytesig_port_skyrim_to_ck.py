from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytesig_port_skyrim_to_ck as port


def proposal(source, source_rva, target_rva, name, kind="exact"):
    parts = tuple(name.split("::"))
    return port.Proposal(
        source_tag=source,
        source_sha256=("a" if source == "a" else "b") * 64,
        source_program_path="/{}.exe".format(source),
        source_rva=source_rva,
        target_rva=target_rva,
        qualified_name=name,
        local_name=parts[-1],
        namespace=parts[:-1],
        source_name_type="IMPORTED",
        match_kind=kind,
        signature_bytes=32 if kind == "exact" else 48,
    )


def test_target_identity_is_pinned_to_downloaded_creation_kit():
    assert port.TARGET_SHA256 == (
        "3e8f7215303a82d8991f87fbc42eb84e"
        "f2672d5d8ab038212447faecfdf37b23")


def test_filtered_prefix_index_has_only_requested_prefixes():
    text = b"abcdef--abcdef--uvwxyz"
    index = port._build_filtered_prefix_index(text, {b"abcdef", b"not-in"})
    assert index == {b"abcdef": [0, 8]}


def test_cross_source_corroboration_is_accepted():
    rows, decisions, accepted = port.resolve_proposals([
        proposal("a", 0x100, 0x900, "RE::TESForm::Lookup"),
        proposal("b", 0x200, 0x900, "RE::TESForm::Lookup", "masked"),
    ])
    assert len(rows) == 2
    assert set(decisions.values()) == {"accepted"}
    assert accepted == [("RE::TESForm::Lookup", 0x900)]


def test_target_conflict_rejects_every_claim_without_source_order_tiebreak():
    rows, decisions, accepted = port.resolve_proposals([
        proposal("a", 0x100, 0x900, "RE::TESForm::Lookup"),
        proposal("b", 0x200, 0x900, "RE::TESObject::Lookup"),
    ])
    assert accepted == []
    assert {decisions[row] for row in rows} == {"rejected_target_conflict"}


def test_name_conflict_rejects_every_claim_without_source_order_tiebreak():
    rows, decisions, accepted = port.resolve_proposals([
        proposal("a", 0x100, 0x900, "RE::TESForm::Lookup"),
        proposal("b", 0x200, 0xA00, "RE::TESForm::Lookup"),
    ])
    assert accepted == []
    assert {decisions[row] for row in rows} == {"rejected_name_conflict"}


def test_exact_duplicate_supersedes_masked_duplicate():
    rows, decisions, accepted = port.resolve_proposals([
        proposal("a", 0x100, 0x900, "RE::TESForm::Lookup", "masked"),
        proposal("a", 0x100, 0x900, "RE::TESForm::Lookup", "exact"),
    ])
    assert len(rows) == 1
    assert rows[0].match_kind == "exact"
    assert decisions[rows[0]] == "accepted"
    assert accepted == [("RE::TESForm::Lookup", 0x900)]


def test_match_source_passes_function_boundary_guards_to_shared_matcher(monkeypatch):
    name = port.SourceName(
        qualified_name="RE::TESForm::Lookup",
        local_name="Lookup",
        namespace=("RE", "TESForm"),
        source_name_type="IMPORTED",
        rva=0x100,
    )
    source_manifest = {
        "sha256": port.SKYRIM_CONFIG.allowed_source_sha256[0][1],
        "program_path": port.DEFAULT_SOURCES[0][1],
    }
    monkeypatch.setattr(port, "_program_manifest", lambda *_: source_manifest)
    monkeypatch.setattr(
        port, "_extract_source_names",
        lambda _program: ({name.qualified_name: name}, {"accepted_names": 1}))
    monkeypatch.setattr(
        port, "_function_boundaries", lambda _program: ({0x100: 32}, {0x100}))
    monkeypatch.setattr(
        port, "_load_text_block", lambda _program: (0x140000000, 0x100, b"A" * 32))

    calls = []

    def fake_port_symbols(*args, **kwargs):
        calls.append((args, kwargs))
        assert kwargs["src_function_sizes"] == {0x100: 32}
        assert kwargs["target_function_starts"] == {0x900}
        return [(name.qualified_name, 0x900)], {"ok": 1}

    monkeypatch.setattr(port, "port_symbols", fake_port_symbols)
    proposals, _stats, _manifest = port._match_source(
        object(), "source", port.DEFAULT_SOURCES[0][1], 0x900, b"A" * 32,
        {0x900: 32}, {0x900})
    assert len(calls) == 1
    assert [(item.qualified_name, item.target_rva) for item in proposals] == [
        (name.qualified_name, 0x900)]


def test_evidence_csv_and_sidecar_are_content_bound(tmp_path):
    row = proposal("a", 0x100, 0x900, "RE::TESForm::Lookup")
    rows, decisions, accepted = port.resolve_proposals([row])
    mapping = {accepted[0]: "would_apply"}
    target = {
        "sha256": port.TARGET_SHA256,
        "program_path": "/CreationKit.exe",
        "program_name": "CreationKit.exe",
        "identity_kind": "ghidra_program_executable_sha256",
        "image_base": 0x140000000,
        "sections": [],
    }
    source = {
        "sha256": "a" * 64,
        "program_path": "/a.exe",
        "program_name": "a.exe",
        "identity_kind": "ghidra_program_executable_sha256",
        "image_base": 0x140000000,
        "sections": [],
    }
    artifact = tmp_path / "evidence.csv"
    port._write_evidence(
        artifact, rows, decisions, mapping, {accepted[0]: "FUN_140000900"},
        target, [source], [], "dry_run")

    with artifact.open("r", encoding="utf-8", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    assert csv_rows[0]["decision"] == "would_apply"
    assert csv_rows[0]["target_sha256"] == port.TARGET_SHA256

    sidecar = json.loads(
        Path(str(artifact) + ".identity.json").read_text(encoding="utf-8"))
    assert sidecar["artifact_sha256"] == hashlib.sha256(
        artifact.read_bytes()).hexdigest()
    assert sidecar["target"]["sha256"] == port.TARGET_SHA256
    assert sidecar["sources"][0]["sha256"] == "a" * 64
