import json
from pathlib import Path
import zipfile

import pytest

from provenance import (
    CANARY_PREFIX,
    build_manifest,
    canonical_json,
    generate_keypair,
    pdb_canary_name,
    sign_manifest,
    validate_manifest,
)
from provenance_scan import scan_bytes, scan_path
from stamp_provenance import stamp
from symbol_export import (
    add_pdb_provenance_canary,
    package_symbol_bundle,
    write_outputs,
)


def _fixture(tmp_path, release_id="test-release"):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "VERSION").write_text(release_id + "\n", encoding="ascii")
    (repo / "toolchain.lock.json").write_text(
        '{"toolchain":"test"}\n', encoding="ascii")
    generator = repo / "generator.py"
    generator.write_text("# deterministic generator\n", encoding="ascii")
    targets = [{"sha256": "b" * 64}, {"sha256": "a" * 64},
               {"sha256": "b" * 64}]
    return repo, generator, targets


def test_manifest_is_deterministic_target_bound_and_tamper_evident(tmp_path):
    repo, generator, targets = _fixture(tmp_path)
    first = build_manifest(repo, generator, targets)
    second = build_manifest(repo, generator, list(reversed(targets)))
    assert first == second
    assert first["release_id"] == "test-release"
    assert first["target_sha256"] == ["a" * 64, "b" * 64]
    assert first["canary"] == CANARY_PREFIX + first["provenance_id"]
    assert validate_manifest(first) is first

    tampered = dict(first, release_id="different")
    with pytest.raises(ValueError, match="ID does not match"):
        validate_manifest(tampered)
    with pytest.raises(ValueError, match="valid SHA-256"):
        build_manifest(repo, generator, [{"sha256": "not-a-hash"}])
    with pytest.raises(ValueError, match="at least one"):
        build_manifest(repo, generator, [])


def test_ed25519_signature_is_verified_and_tamper_rejected(tmp_path):
    repo, generator, targets = _fixture(tmp_path)
    private_key = tmp_path / "release.bgs-ed25519-private.pem"
    public_key = tmp_path / "release-public.pem"
    key_id = generate_keypair(private_key, public_key)
    signed = sign_manifest(build_manifest(repo, generator, targets), private_key)
    assert signed["signature"]["key_id"] == key_id
    assert validate_manifest(signed, public_key=public_key) is signed

    tampered = dict(signed)
    tampered["canary_comment"] += " modified"
    with pytest.raises(ValueError):
        validate_manifest(tampered, public_key=public_key)
    malformed = dict(signed)
    malformed["signature"] = dict(signed["signature"], value="AA==")
    with pytest.raises(ValueError, match="signature length"):
        validate_manifest(malformed)


def test_scanner_finds_importer_json_zip_pdb_and_comment(tmp_path):
    repo, generator, targets = _fixture(tmp_path)
    private_key = tmp_path / "release.bgs-ed25519-private.pem"
    public_key = tmp_path / "release-public.pem"
    generate_keypair(private_key, public_key)
    manifest = build_manifest(repo, generator, targets,
                              signing_key=private_key)
    encoded = canonical_json(manifest)

    importer = tmp_path / "CommonLibImport_Test.py"
    importer.write_text(
        "import json as _json_target\nBGS_PROVENANCE = "
        "_json_target.loads(" + repr(encoded) + ")\n", encoding="ascii")
    importer_findings = scan_path(importer, public_key=public_key)
    assert [(item["kind"], item["signature_state"])
            for item in importer_findings] == [("manifest", "signed-trusted")]
    assert scan_path(importer)[0]["signature_state"] == "signed-unverified"

    exported = tmp_path / "symbols.json"
    exported.write_text(json.dumps({"bgs_provenance": manifest}),
                        encoding="ascii")
    assert scan_path(exported, public_key=public_key)[0]["kind"] == "manifest"

    standalone = tmp_path / "signed-manifest.json"
    standalone.write_text(json.dumps(manifest), encoding="ascii")
    standalone_findings = scan_path(standalone, public_key=public_key)
    assert [(item["kind"], item["signature_state"])
            for item in standalone_findings] == [
                ("manifest", "signed-trusted")]

    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("BGS_PROVENANCE.json",
                        json.dumps({"BGS_PROVENANCE": manifest}))
    assert scan_path(archive, public_key=public_key)[0]["path"].endswith(
        "bundle.zip!BGS_PROVENANCE.json")

    provenance_id = manifest["provenance_id"]
    assert scan_bytes("symbols.pdb", (
        "binary\0" + pdb_canary_name(manifest) + "\0").encode("ascii")) == [{
            "path": "symbols.pdb", "kind": "pdb-canary",
            "provenance_id": provenance_id, "signature_state": "marker-only"}]
    assert scan_bytes("copied.log", manifest["canary_comment"].encode(
        "ascii"))[0]["kind"] == "comment-canary"


def test_existing_importer_stamping_is_idempotent(tmp_path):
    importer = tmp_path / "CommonLibImport_Test.py"
    target = {
        "sha256": "c" * 64,
        "file_size": 0x4000,
        "pointer_size": 8,
        "image_base": 0x140000000,
        "image_size": 0x5000,
        "sections": [{"name": ".text", "rva": 0x1000}],
        "anchors": [{"rva": 0x1000, "bytes": "90"}],
        "function_starts": [0x1000],
    }
    importer.write_text(
        "import json as _json_target\n"
        "TARGET_MANIFESTS = _json_target.loads("
        + repr(json.dumps([target], separators=(",", ":"))) + ")\n"
        "TARGET_LINEAGE = _json_target.loads('{}')\n"
        "def _merge_plate_comment(address, comments):\n"
        "    pass\n"
        "def run():\n"
        "    pass\n"
        "run()\n",
        encoding="ascii")
    manifest = stamp(importer)
    first = importer.read_text(encoding="utf-8")
    assert "BGS_PROVENANCE = _json_target.loads(" in first
    assert "def _apply_bgs_provenance():" in first
    assert first.rstrip().endswith("_apply_bgs_provenance()")
    assert manifest["target_sha256"] == ["c" * 64]
    assert scan_path(importer)[0]["provenance_id"] == manifest["provenance_id"]
    stamp(importer)
    assert importer.read_text(encoding="utf-8") == first


def test_symbol_outputs_and_bundle_propagate_provenance(tmp_path):
    repo, generator, targets = _fixture(tmp_path)
    manifest = build_manifest(repo, generator, targets)
    target = {
        "sha256": "a" * 64,
        "version_string": "1.2.3.4",
        "image_size": 0x5000,
    }
    functions = [{"rva": 0x1000, "name": "RE::Start"}]
    labels = [{"rva": 0x3000, "name": "Global", "kind": "data"}]
    symbols_json, _, _ = write_outputs(
        tmp_path, "Game.exe", 0x140000000, functions, labels, target,
        bgs_provenance=manifest)
    symbols = json.loads(Path(symbols_json).read_text(encoding="utf-8"))
    identity = json.loads((tmp_path / "Game.export.identity.json").read_text(
        encoding="utf-8"))
    assert symbols["bgs_provenance"] == manifest
    assert identity["bgs_provenance"] == manifest

    pdb_labels = add_pdb_provenance_canary(functions, labels, manifest)
    assert pdb_labels[-1]["name"] == pdb_canary_name(manifest)
    assert pdb_labels[-1]["rva"] == functions[0]["rva"]

    pdb = tmp_path / "Game.pdb"
    pdb_identity = tmp_path / "Game.pdb.identity.json"
    pdb.write_bytes(("PDB\0" + pdb_labels[-1]["name"]).encode("ascii"))
    pdb_identity.write_text(json.dumps({"bgs_provenance": manifest}),
                            encoding="ascii")
    bundle = package_symbol_bundle(
        tmp_path, "Game.exe", pdb, pdb_identity, symbols_json, target,
        bgs_provenance=manifest)
    with zipfile.ZipFile(bundle) as archive:
        bundled = json.loads(archive.read("BGS_PROVENANCE.json"))
    assert bundled == manifest
    assert {item["kind"] for item in scan_path(bundle)} >= {
        "manifest", "pdb-canary"}
