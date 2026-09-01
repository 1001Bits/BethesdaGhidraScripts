"""Bind Microsoft PDB inputs to their PE and support OMAP translation."""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import uuid
import warnings
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from binary_identity import inspect_pe


class PDBIdentityError(ValueError):
    pass


LLVM_RECEIPT_SCHEMA = "bgs-llvm-install-receipt-v1"
LLVM_RECEIPT_NAME = ".bgs-install-receipt.json"
UNPINNED_PDBUTIL_RESEARCH_OPT_IN = (
    "BGS_RESEARCH_ALLOW_UNPINNED_PDBUTIL")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _llvm_binary_relpaths() -> Dict[str, str]:
    suffix = ".exe" if os.name == "nt" else ""
    return {
        "clang": "bin/clang{}".format(suffix),
        "llvm-pdbutil": "bin/llvm-pdbutil{}".format(suffix),
    }


def _read_toolchain_lock(lock_path: Path) -> Dict[str, object]:
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PDBIdentityError("invalid or missing toolchain.lock.json") from exc
    if lock.get("schema") != 1 or not isinstance(lock.get("llvm"), dict):
        raise PDBIdentityError("toolchain lock has no LLVM identity")
    return lock


def _atomic_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".llvm-receipt-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_llvm_install_receipt(llvm_dir: Path, lock_path: Path,
                               platform_key: str, asset_name: str,
                               archive_sha256: str) -> Dict[str, object]:
    """Record hashes for binaries extracted from a verified locked archive."""
    llvm_dir = Path(llvm_dir)
    lock = _read_toolchain_lock(Path(lock_path))
    llvm_lock = lock["llvm"]
    asset_key = platform_key + "_asset"
    digest_key = platform_key + "_sha256"
    digest = str(archive_sha256).lower()
    if (llvm_lock.get(asset_key) != asset_name or
            str(llvm_lock.get(digest_key) or "").lower() != digest or
            not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise PDBIdentityError(
            "installed LLVM archive identity does not match toolchain lock")
    binaries = {}
    for label, relative in _llvm_binary_relpaths().items():
        path = llvm_dir / Path(relative)
        if not path.is_file():
            raise PDBIdentityError(
                "verified LLVM archive lacks {}".format(relative))
        binaries[label] = {
            "path": relative,
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
    receipt = {
        "schema": LLVM_RECEIPT_SCHEMA,
        "llvm_version": llvm_lock.get("version"),
        "release_tag": llvm_lock.get("release_tag"),
        "platform_key": platform_key,
        "asset": asset_name,
        "archive_sha256": digest,
        "binaries": binaries,
    }
    _atomic_json(llvm_dir / LLVM_RECEIPT_NAME, receipt)
    return receipt


def validate_repo_llvm_install(repo_root: Optional[Path] = None) -> Dict[str, Path]:
    """Validate the repo-local LLVM receipt and every attested binary."""
    root = Path(repo_root) if repo_root is not None else _repo_root()
    llvm_dir = root / "tools" / "llvm"
    lock = _read_toolchain_lock(root / "toolchain.lock.json")
    receipt_path = llvm_dir / LLVM_RECEIPT_NAME
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PDBIdentityError(
            "repo LLVM has no valid installation receipt; run `python run.py setup`") from exc
    llvm_lock = lock["llvm"]
    platform_key = str(receipt.get("platform_key") or "")
    locked_asset = llvm_lock.get(platform_key + "_asset")
    locked_digest = str(
        llvm_lock.get(platform_key + "_sha256") or "").lower()
    if (receipt.get("schema") != LLVM_RECEIPT_SCHEMA or
            not re.fullmatch(r"[a-z0-9_]+", platform_key) or
            not isinstance(locked_asset, str) or not locked_asset or
            not re.fullmatch(r"[0-9a-f]{64}", locked_digest) or
            receipt.get("llvm_version") != llvm_lock.get("version") or
            receipt.get("release_tag") != llvm_lock.get("release_tag") or
            receipt.get("asset") != locked_asset or
            str(receipt.get("archive_sha256") or "").lower() !=
            locked_digest):
        raise PDBIdentityError(
            "repo LLVM receipt does not match toolchain.lock.json")
    records = receipt.get("binaries")
    if not isinstance(records, dict):
        raise PDBIdentityError("repo LLVM receipt has no binary hashes")
    resolved = {}
    for label, expected_relative in _llvm_binary_relpaths().items():
        record = records.get(label)
        if not isinstance(record, dict) or record.get("path") != expected_relative:
            raise PDBIdentityError(
                "repo LLVM receipt does not attest {}".format(label))
        path = llvm_dir / Path(expected_relative)
        try:
            path.resolve().relative_to(llvm_dir.resolve())
        except ValueError as exc:
            raise PDBIdentityError("LLVM receipt path escapes installation") from exc
        expected_hash = str(record.get("sha256") or "").lower()
        if (not path.is_file() or
                int(record.get("size") or -1) != path.stat().st_size or
                not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or
                _sha256_file(path) != expected_hash):
            raise PDBIdentityError(
                "repo LLVM binary {} differs from its verified receipt".format(
                    label))
        resolved[label] = path
    return resolved


def _rva_to_offset(manifest: Dict, rva: int, size: int) -> int:
    for section in manifest["sections"]:
        start = int(section["rva"])
        delta = rva - start
        if 0 <= delta and delta + size <= int(section["raw_size"]):
            return int(section["raw_offset"]) + delta
    raise PDBIdentityError("debug directory RVA is not physically backed")


def read_pe_codeview(pe_path: str) -> Dict[str, object]:
    """Read the PE's RSDS CodeView GUID, age and recorded PDB name."""
    blob = Path(pe_path).read_bytes()
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise PDBIdentityError("not a PE image")
    peoff = struct.unpack_from("<I", blob, 0x3C)[0]
    if peoff + 24 > len(blob) or blob[peoff:peoff + 4] != b"PE\0\0":
        raise PDBIdentityError("invalid PE header")
    opt_size = struct.unpack_from("<H", blob, peoff + 20)[0]
    opt = peoff + 24
    if opt + opt_size > len(blob):
        raise PDBIdentityError("truncated optional header")
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic == 0x20B:
        number_offset, directory_offset = 108, 112
    elif magic == 0x10B:
        number_offset, directory_offset = 92, 96
    else:
        raise PDBIdentityError("unsupported optional-header magic")
    if opt_size < directory_offset + 8 * 7:
        raise PDBIdentityError("PE has no debug data-directory slot")
    count = struct.unpack_from("<I", blob, opt + number_offset)[0]
    if count <= 6:
        raise PDBIdentityError("PE has no debug directory")
    debug_rva, debug_size = struct.unpack_from("<II", blob,
                                                opt + directory_offset + 6 * 8)
    if not debug_rva or debug_size < 28:
        raise PDBIdentityError("PE has no CodeView debug record")
    manifest = inspect_pe(pe_path, include_sha256=False)
    table = _rva_to_offset(manifest, debug_rva, debug_size)
    for offset in range(table, table + debug_size - 27, 28):
        (_chars, _stamp, _major, _minor, record_type, data_size,
         data_rva, data_offset) = struct.unpack_from("<IIHHIIII", blob, offset)
        if record_type != 2 or data_size < 24:
            continue
        if not data_offset and data_rva:
            data_offset = _rva_to_offset(manifest, data_rva, data_size)
        if data_offset + data_size > len(blob):
            raise PDBIdentityError("truncated CodeView record")
        record = blob[data_offset:data_offset + data_size]
        if record[:4] != b"RSDS":
            continue
        guid = str(uuid.UUID(bytes_le=record[4:20])).upper()
        age = struct.unpack_from("<I", record, 20)[0]
        name = record[24:].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace")
        return {"guid": guid, "age": age, "pdb_path": name}
    raise PDBIdentityError("PE debug directory has no RSDS CodeView record")


def _find_pdbutil(explicit: Optional[str] = None) -> str:
    expected_path = (_repo_root() / "tools" / "llvm" /
                     Path(_llvm_binary_relpaths()["llvm-pdbutil"]))
    if explicit is None or Path(explicit).resolve() == expected_path.resolve():
        return str(validate_repo_llvm_install()["llvm-pdbutil"])
    if os.environ.get(UNPINNED_PDBUTIL_RESEARCH_OPT_IN) != "1":
        raise PDBIdentityError(
            "an explicit unpinned llvm-pdbutil is forbidden; set {}=1 only "
            "for a non-reproducible research run".format(
                UNPINNED_PDBUTIL_RESEARCH_OPT_IN))
    override = Path(explicit)
    if not override.is_file():
        raise PDBIdentityError("explicit research llvm-pdbutil does not exist")
    warnings.warn(
        "using explicitly unpinned llvm-pdbutil for research",
        RuntimeWarning, stacklevel=2)
    return str(override)


def _parse_pdbutil_summary(text: str) -> Dict[str, object]:
    """Parse identity fields across llvm-pdbutil summary spellings.

    LLVM 22 prints ``GUID`` in all capitals, while older releases used
    ``Guid``.  Treat field labels case-insensitively; the identity value is
    still normalized through :class:`uuid.UUID` below.
    """
    guid_match = re.search(
        r"\bguid:\s*['{]?([0-9A-Fa-f-]{36})", text,
        flags=re.IGNORECASE)
    age_match = re.search(r"\bage:\s*(\d+)", text, flags=re.IGNORECASE)
    if not guid_match or not age_match:
        raise PDBIdentityError("could not parse PDB GUID/age from llvm-pdbutil")
    return {"guid": str(uuid.UUID(guid_match.group(1))).upper(),
            "age": int(age_match.group(1))}


def read_pdb_identity(pdb_path: str, llvm_pdbutil: Optional[str] = None) -> Dict[str, object]:
    tool = _find_pdbutil(llvm_pdbutil)
    result = subprocess.run([tool, "dump", "-summary", pdb_path],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise PDBIdentityError("llvm-pdbutil failed: {}".format(
            (result.stderr or result.stdout).strip()))
    return _parse_pdbutil_summary(result.stdout + "\n" + result.stderr)


def validate_pdb_for_pe(pe_path: str, pdb_path: str,
                        llvm_pdbutil: Optional[str] = None) -> Dict[str, object]:
    pe = read_pe_codeview(pe_path)
    pdb = read_pdb_identity(pdb_path, llvm_pdbutil)
    if pe["guid"] != pdb["guid"] or pe["age"] != pdb["age"]:
        raise PDBIdentityError(
            "PDB mismatch: PE expects {}/age {}, PDB is {}/age {}".format(
                pe["guid"], pe["age"], pdb["guid"], pdb["age"]))
    return {"guid": pe["guid"], "age": pe["age"],
            "pdb_path": pe["pdb_path"]}


def parse_omap(data: bytes) -> List[Tuple[int, int]]:
    if len(data) % 8:
        raise PDBIdentityError("OMAP stream length is not a multiple of 8")
    rows = [struct.unpack_from("<II", data, offset)
            for offset in range(0, len(data), 8)]
    if any(rows[index][0] >= rows[index + 1][0]
           for index in range(len(rows) - 1)):
        raise PDBIdentityError("OMAP source RVAs are not strictly increasing")
    return rows


def map_from_source(rva: int, omap: Sequence[Tuple[int, int]]) -> Optional[int]:
    """Translate a source/PDB RVA to the optimized image using OMAP_FROM_SRC."""
    if not omap:
        return rva
    starts = [row[0] for row in omap]
    index = bisect.bisect_right(starts, rva) - 1
    if index < 0:
        return None
    source, target = omap[index]
    if target == 0:
        return None
    return target + (rva - source)
