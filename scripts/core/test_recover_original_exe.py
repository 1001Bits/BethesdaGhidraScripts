import hashlib

import pytest

import recover_original_exe as recover


class _Memory:
    def __init__(self, file_bytes):
        self._file_bytes = file_bytes

    def getAllFileBytes(self):
        return self._file_bytes


class _Program:
    """Duck-typed Program -- the guards must hold without a Ghidra JVM."""

    def __init__(self, sha, file_bytes=("stored",)):
        self._sha = sha
        self._memory = _Memory(list(file_bytes))

    def getExecutableSHA256(self):
        return self._sha

    def getMemory(self):
        return self._memory


def test_refuses_program_without_import_hash(tmp_path):
    out = tmp_path / "recovered.exe"
    with pytest.raises(recover.RecoveryError, match="no import-time SHA-256"):
        recover.recover_original_exe(_Program(None), out)
    assert not out.exists()


def test_refuses_program_without_stored_file_bytes(tmp_path):
    out = tmp_path / "recovered.exe"
    with pytest.raises(recover.RecoveryError, match="no original file bytes"):
        recover.recover_original_exe(_Program("a" * 64, file_bytes=()), out)
    assert not out.exists()


def test_sha256_reads_in_chunks(tmp_path):
    blob = b"\x90" * (1 << 20) + b"payload"
    path = tmp_path / "blob.bin"
    path.write_bytes(blob)
    assert recover._sha256(path) == hashlib.sha256(blob).hexdigest()
