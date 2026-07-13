"""Receipt validation for the pinned FakePDB public-symbol generator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


RECEIPT_SCHEMA = "bgs-fakepdb-install-receipt-v1"
RECEIPT_NAME = ".bgs-install-receipt.json"


class FakePDBToolError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _lock(repo_root: Path) -> dict:
    try:
        document = json.loads(
            (repo_root / "toolchain.lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FakePDBToolError("invalid or missing toolchain.lock.json") from exc
    record = document.get("fakepdb")
    if document.get("schema") != 1 or not isinstance(record, dict):
        raise FakePDBToolError("toolchain lock has no FakePDB identity")
    return record


def _write_atomic(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".fakepdb-receipt-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_fakepdb_receipt(repo_root: str | Path,
                          archive_sha256: str) -> dict:
    root = Path(repo_root)
    lock = _lock(root)
    digest = str(archive_sha256).lower()
    if (digest != str(lock.get("sha256") or "").lower() or
            not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise FakePDBToolError(
            "FakePDB archive identity does not match toolchain lock")
    tool_dir = root / "tools" / "fakepdb"
    executable_name = str(lock.get("executable") or "")
    executable = tool_dir / executable_name
    expected_hash = str(lock.get("executable_sha256") or "").lower()
    if (not executable_name or not executable.is_file() or
            not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or
            _sha256(executable) != expected_hash):
        raise FakePDBToolError(
            "installed FakePDB executable does not match toolchain lock")
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "version": lock.get("version"),
        "release_tag": lock.get("release_tag"),
        "source_commit": lock.get("source_commit"),
        "asset": lock.get("asset"),
        "archive_sha256": digest,
        "executable": executable_name,
        "executable_size": executable.stat().st_size,
        "executable_sha256": expected_hash,
        "license": lock.get("license"),
    }
    _write_atomic(tool_dir / RECEIPT_NAME, receipt)
    return receipt


def validate_fakepdb_install(repo_root: str | Path) -> Path:
    """Return the exact repo-local executable or fail closed."""
    root = Path(repo_root)
    lock = _lock(root)
    tool_dir = root / "tools" / "fakepdb"
    receipt_path = tool_dir / RECEIPT_NAME
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FakePDBToolError(
            "FakePDB has no valid installation receipt; run `python run.py setup`") from exc
    locked_hash = str(lock.get("executable_sha256") or "").lower()
    archive_hash = str(lock.get("sha256") or "").lower()
    executable_name = str(lock.get("executable") or "")
    if (receipt.get("schema") != RECEIPT_SCHEMA or
            receipt.get("version") != lock.get("version") or
            receipt.get("release_tag") != lock.get("release_tag") or
            receipt.get("source_commit") != lock.get("source_commit") or
            receipt.get("asset") != lock.get("asset") or
            str(receipt.get("archive_sha256") or "").lower() != archive_hash or
            receipt.get("executable") != executable_name or
            str(receipt.get("executable_sha256") or "").lower() != locked_hash):
        raise FakePDBToolError(
            "FakePDB receipt does not match toolchain.lock.json")
    executable = tool_dir / executable_name
    try:
        executable.resolve().relative_to(tool_dir.resolve())
    except ValueError as exc:
        raise FakePDBToolError("FakePDB executable path escapes installation") from exc
    if (not executable.is_file() or
            int(receipt.get("executable_size") or -1) != executable.stat().st_size or
            not re.fullmatch(r"[0-9a-f]{64}", locked_hash) or
            _sha256(executable) != locked_hash):
        raise FakePDBToolError(
            "FakePDB executable differs from its verified receipt")
    return executable
