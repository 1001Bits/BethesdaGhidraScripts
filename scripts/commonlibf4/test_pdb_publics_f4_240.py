import json
from pathlib import Path

import pytest

import pdb_publics_f4_240 as corpus  # puts scripts/core on sys.path
import binary_identity
import pdb_identity

PACKED_SHA = "fdcef37ac1230af6d0b0050eb2142b139ef3a867b37b9211fb6edfcc646072f8"
# Pinned Steamless 3.1.0.5 (--quiet --keepbind) output of the packed exe.
UNPACKED_SHA = "44bad7d287d5ec95d2b0bef11db4e51aaea087d64e24248e29ca0f013ad4aaca"


def _identity():
    return json.loads(Path(corpus.IDENTITY_JSON).read_text(encoding="utf-8"))


def test_corpus_binds_packed_exe_and_its_steamless_artifact():
    targets = {target["sha256"]: target for target in _identity()["targets"]}
    assert set(targets) == {PACKED_SHA, UNPACKED_SHA}
    assert targets[UNPACKED_SHA]["file"] == "Fallout4.exe.unpacked.exe"
    for key in ("file_version", "image_size", "machine"):
        assert targets[UNPACKED_SHA][key] == targets[PACKED_SHA][key]


@pytest.fixture
def fake_target(monkeypatch, tmp_path):
    identity = _identity()
    real_sha256 = corpus._sha256
    target = tmp_path / "Fallout4.exe.unpacked.exe"
    target.write_bytes(b"MZ")
    hashes = {}

    def fake_sha256(path):
        if Path(path) == target:
            return hashes["target"]
        return real_sha256(path)

    monkeypatch.setattr(corpus, "_sha256", fake_sha256)
    monkeypatch.setattr(
        binary_identity, "inspect_pe",
        lambda path, include_sha256=True: {
            "image_size": identity["targets"][0]["image_size"],
            "machine": identity["targets"][0]["machine"]})
    monkeypatch.setattr(
        pdb_identity, "read_pe_codeview",
        lambda path: {"guid": identity["pdb"]["guid"],
                      "age": identity["pdb"]["age"]})

    def bind(sha):
        hashes["target"] = sha
        return str(target)
    return bind


def test_steamless_artifact_passes_identity_validation(fake_target):
    # run.py's ensure_unpacked makes _target_binding hand the unpacked exe to
    # load_publics; refusing it aborted every Steam 1.11.240 generation.
    for sha in (PACKED_SHA, UNPACKED_SHA):
        assert corpus._validate_identity(fake_target(sha), sha)["targets"]


def test_other_executables_are_still_rejected(fake_target):
    other = "0" * 64
    with pytest.raises(ValueError, match="targets another executable"):
        corpus._validate_identity(fake_target(other), other)
