import json

import pytest

import importer_binding


def _manifest(sha="a" * 64):
    return {
        "sha256": sha,
        "file_size": 100,
        "pointer_size": 8,
        "image_base": 0x140000000,
        "image_size": 0x3000,
        "sections": [{"name": ".text"}],
        "anchors": [{"rva": 0x1000, "bytes": "90"}],
        "function_starts": [],
    }


def test_extracts_generated_json_assignment(tmp_path):
    path = tmp_path / "importer.py"
    payload = json.dumps([_manifest()], separators=(",", ":"))
    path.write_text(
        "import json as _json_target\nTARGET_MANIFESTS = "
        "_json_target.loads({!r})\n".format(payload), encoding="utf-8")
    assert importer_binding.extract_target_manifests(path)[0]["sha256"] == "a" * 64


def test_rejects_legacy_unbound_importer(tmp_path):
    path = tmp_path / "legacy.py"
    path.write_text("print('mutating old importer')\n", encoding="utf-8")
    with pytest.raises(importer_binding.ImporterBindingError,
                       match="does not record which game build"):
        importer_binding.extract_target_manifests(path)


def test_unbound_importer_names_its_staging_directory(tmp_path):
    """A known importer's error must name the exact .exe folder, not <game>."""
    path = tmp_path / "CommonLibImport_VR.py"
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(importer_binding.ImporterBindingError) as exc:
        importer_binding.extract_target_manifests(path)
    assert "exes/skyrim/vr/" in str(exc.value)
    assert "Skyrim VR 1.4.15" in str(exc.value)


def test_unknown_importer_falls_back_to_generic_staging_hint(tmp_path):
    path = tmp_path / "CommonLibImport_Nonesuch.py"
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(importer_binding.ImporterBindingError,
                       match=r"exes/<game>/<version>/"):
        importer_binding.extract_target_manifests(path)


def test_rejects_ambiguous_duplicate_assignment(tmp_path):
    path = tmp_path / "importer.py"
    payload = "{!r}".format([_manifest()])
    path.write_text("TARGET_MANIFESTS = {0}\nTARGET_MANIFESTS = {0}\n".format(payload),
                    encoding="utf-8")
    with pytest.raises(importer_binding.ImporterBindingError, match="ambiguous"):
        importer_binding.extract_target_manifests(path)


def test_rejects_dynamic_assignment(tmp_path):
    path = tmp_path / "dynamic.py"
    path.write_text("TARGET_MANIFESTS = discover_targets()\n", encoding="utf-8")
    with pytest.raises(importer_binding.ImporterBindingError, match="static"):
        importer_binding.extract_target_manifests(path)


def test_accepts_only_matching_identity(tmp_path):
    path = tmp_path / "importer.py"
    path.write_text("TARGET_MANIFESTS = {!r}\n".format([_manifest()]),
                    encoding="utf-8")
    assert importer_binding.accepts_manifest(path, _manifest())
    with pytest.raises(importer_binding.ImporterBindingError, match="mismatch"):
        importer_binding.accepts_manifest(path, _manifest("b" * 64))
