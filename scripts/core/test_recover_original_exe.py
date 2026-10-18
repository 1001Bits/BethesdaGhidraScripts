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


def _exporter(payload):
    def export(_program, destination, _monitor=None):
        destination.write_bytes(payload)
        return True
    return export


def test_never_truncates_or_deletes_a_pre_existing_target(tmp_path, monkeypatch):
    """A user-staged exe at --out used to be truncated, then unlinked."""
    staged = tmp_path / "Game.exe"
    staged.write_bytes(b"the user's own file")
    monkeypatch.setattr(recover, "_export_original", _exporter(b"other"))
    with pytest.raises(recover.RecoveryError, match="refusing to overwrite"):
        recover.recover_original_exe(
            _Program(hashlib.sha256(b"other").hexdigest()), staged)
    assert staged.read_bytes() == b"the user's own file"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Game.exe"]


def test_hash_mismatch_leaves_nothing_behind(tmp_path, monkeypatch):
    out = tmp_path / "sub" / "recovered.exe"
    monkeypatch.setattr(recover, "_export_original", _exporter(b"wrong bytes"))
    with pytest.raises(recover.RecoveryError, match="discarded"):
        recover.recover_original_exe(_Program("a" * 64), out)
    assert list((tmp_path / "sub").iterdir()) == []


def test_verified_export_lands_on_the_target(tmp_path, monkeypatch):
    out = tmp_path / "recovered.exe"
    monkeypatch.setattr(recover, "_export_original", _exporter(b"exact"))
    result = recover.recover_original_exe(
        _Program(hashlib.sha256(b"exact").hexdigest()), out)
    assert result == out and out.read_bytes() == b"exact"
    assert [p.name for p in tmp_path.iterdir()] == ["recovered.exe"]


def test_target_appearing_during_export_is_not_clobbered(tmp_path, monkeypatch):
    out = tmp_path / "recovered.exe"

    def export(_program, destination, _monitor=None):
        destination.write_bytes(b"exact")
        out.write_bytes(b"raced in")
        return True

    monkeypatch.setattr(recover, "_export_original", export)
    with pytest.raises(recover.RecoveryError, match="refusing to overwrite"):
        recover.recover_original_exe(
            _Program(hashlib.sha256(b"exact").hexdigest()), out)
    assert out.read_bytes() == b"raced in"
    assert [p.name for p in tmp_path.iterdir()] == ["recovered.exe"]
