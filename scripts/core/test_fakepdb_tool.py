import hashlib
import json

import pytest

from fakepdb_tool import (
    FakePDBToolError,
    validate_fakepdb_install,
    write_fakepdb_receipt,
)


def _repo(tmp_path):
    executable = tmp_path / "tools" / "fakepdb" / "fakepdb.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"pinned fakepdb")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    archive = "a" * 64
    (tmp_path / "toolchain.lock.json").write_text(json.dumps({
        "schema": 1,
        "fakepdb": {
            "version": "0.3", "release_tag": "v0.3",
            "source_commit": "commit", "asset": "fakepdb_v0.3.zip",
            "sha256": archive, "executable": "fakepdb.exe",
            "executable_sha256": digest, "license": "Apache-2.0",
        }}), encoding="utf-8")
    return executable, archive


def test_fakepdb_install_requires_matching_receipt_and_binary(tmp_path):
    executable, archive = _repo(tmp_path)
    write_fakepdb_receipt(tmp_path, archive)
    assert validate_fakepdb_install(tmp_path) == executable
    executable.write_bytes(b"tampered")
    with pytest.raises(FakePDBToolError, match="differs"):
        validate_fakepdb_install(tmp_path)


def test_fakepdb_receipt_rejects_wrong_archive(tmp_path):
    _repo(tmp_path)
    with pytest.raises(FakePDBToolError, match="archive identity"):
        write_fakepdb_receipt(tmp_path, "b" * 64)
