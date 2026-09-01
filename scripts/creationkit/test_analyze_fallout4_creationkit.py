import importlib.util
import json
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent


def _load_driver():
    path = HERE / "analyze_fallout4_creationkit.py"
    spec = importlib.util.spec_from_file_location("f4ck_analysis_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_analysis_driver_identity_matches_ckpe_lock():
    driver = _load_driver()
    lock = json.loads(
        (HERE / "refs" / "ckpe_fo4_1_11_137_0.lock.json").read_text(
            encoding="utf-8"))
    expected = driver._expected_identity()
    target = lock["target"]
    for key in (
            "sha256", "file_size", "machine", "pointer_size", "image_base",
            "image_size", "timestamp"):
        assert expected[key] == target[key]
    assert expected["file_version"] == [1, 11, 137, 0]
    assert target["version_string"] == "1.11.137.0"


def test_analysis_driver_uses_unique_combined_path():
    driver = _load_driver()
    assert driver.PROGRAM_PATH == (
        "/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe")
    assert "Skyrim" not in driver.PROGRAM_PATH


def test_ckpe_root_prefers_explicit_then_environment(tmp_path, monkeypatch):
    driver = _load_driver()
    explicit = tmp_path / "explicit"
    configured = tmp_path / "configured"
    explicit.mkdir()
    configured.mkdir()
    monkeypatch.setenv("BGS_CKPE_ROOT", os.fspath(configured))
    assert driver._resolve_ckpe_root(explicit) == explicit.resolve()
    assert driver._resolve_ckpe_root(None) == configured.resolve()


def test_java_finalizer_live_anchors_match_exact_lock():
    lock = json.loads(
        (HERE / "refs" / "ckpe_fo4_1_11_137_0.lock.json").read_text(
            encoding="utf-8"))
    source = (HERE / "VerifyAndFinalizeFallout4CreationKit.java").read_text(
        encoding="utf-8")
    for anchor in lock["target"]["anchors"]:
        assert "0x{:X}L".format(anchor["rva"]) in source
        assert '"{}"'.format(anchor["bytes"].lower()) in source.lower()
