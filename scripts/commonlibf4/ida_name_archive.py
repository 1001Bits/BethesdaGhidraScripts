#!/usr/bin/env python3
"""Validate and normalize the external Fallout 4 IDA-name archive.

The third-party archive is *input*, not a script dependency: it is never
imported or executed.  This module accepts only the byte-for-byte archive
described by ``refs/ida_import_fallout4.lock.json``, parses a very small
allowlisted Python AST, and converts addresses to identity-bound RVA evidence.

Normalization is deliberately conservative:

* the archive entry must match the exact target version and an independently
  approved target PE SHA-256 from the source lock;
* both full VAs and the archive's accidentally bare RVAs are accepted only
  when their name suffix agrees and the resulting RVA is mapped;
* executable names must be linker-attested AMD64 runtime-function starts;
* data-section names remain labels; and
* same-address aliases and same-name/multiple-address records are quarantined.

The raw archive and generated evidence have unknown redistribution rights.
Keep both in the local ``extras`` area; do not add them to release packages
without permission from the source author.

Examples::

    python scripts/commonlibf4/ida_name_archive.py audit path/to/archive.zip
    python scripts/commonlibf4/ida_name_archive.py normalize path/to/archive.zip \
        --version 1.11.221.0 --target path/to/Fallout4.exe \
        --output extras/normalized/f4_ida_names_1.11.221.0.<target-sha256>.json
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from typing import Any, Iterable
import zipfile


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parents[1]
CORE_DIR = REPO_DIR / "scripts" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from binary_identity import (  # noqa: E402
    canonical_identity,
    inspect_pe,
    manifest_matches,
)
from evidence_identity import (  # noqa: E402
    bind_for_hash,
    read_binding,
)


SCHEMA = "bgs-f4-ida-name-evidence-v1"
KIND = "f4_ida_names_normalized"
LOCK_SCHEMA = "bgs-external-input-lock-v1"
LOCK_PATH = SCRIPT_DIR / "refs" / "ida_import_fallout4.lock.json"
DEFAULT_NORMALIZED_DIR = REPO_DIR / "extras" / "normalized"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_ENTRY_RE = re.compile(r"^ida-import-fallout4-(\d+\.\d+\.\d+\.\d+)\.py$")
_ADDR_SUFFIX_RE = re.compile(r"_([0-9A-Fa-f]{6,16})$")
_PLACEHOLDER_RE = re.compile(
    r"^(?:FUN|sub|loc|byte|word|dword|qword|unk|off|stru|asc|jpt|nullsub|j_)"
    r"_[0-9A-Fa-f]+$"
)


class IDANameArchiveError(ValueError):
    """Raised when external IDA-name evidence fails a safety invariant."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: os.PathLike[str] | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: os.PathLike[str] | str, value: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def normalized_evidence_path(version: str,
                             directory: os.PathLike[str] | str | None = None,
                             target_sha256: str | None = None,
                             ) -> Path:
    """Return a conventional local-only normalized-evidence path.

    New evidence should pass ``target_sha256``.  A full-hash filename makes
    packed and unpacked images with identical RVAs coexist without allowing a
    consumer to guess which binding applies.  The unqualified filename is
    retained as a compatibility location for already-generated evidence.
    """
    if not _VERSION_RE.fullmatch(version):
        raise IDANameArchiveError("invalid Fallout 4 version: " + version)
    root = Path(directory) if directory is not None else DEFAULT_NORMALIZED_DIR
    stem = "f4_ida_names_{}".format(version)
    if target_sha256 is not None:
        target_sha256 = str(target_sha256).lower()
        if not _SHA256_RE.fullmatch(target_sha256):
            raise IDANameArchiveError("invalid normalized-evidence target hash")
        stem += "." + target_sha256
    return root / (stem + ".json")


def select_normalized_evidence_path(
        version: str, target_sha256: str,
        directory: os.PathLike[str] | str | None = None,
        ) -> Path | None:
    """Select evidence deterministically for one exact target SHA-256.

    The full-hash-qualified artifact always wins.  The historical generic
    artifact is considered only when its sidecar binds it to this same target;
    a valid generic artifact for the packed/unpacked sibling is simply not a
    candidate.  Missing or malformed sidecars still fail closed.
    """
    target_sha256 = str(target_sha256).lower()
    qualified = normalized_evidence_path(
        version, directory, target_sha256=target_sha256)
    generic = normalized_evidence_path(version, directory)
    for path in (qualified, generic):
        if not path.is_file():
            continue
        binding = read_binding(str(path), KIND, require_content=True)
        bound_hash = str(binding.get("target_sha256") or "").lower()
        if path == qualified and bound_hash != target_sha256:
            raise IDANameArchiveError(
                "hash-qualified IDA evidence is bound to another PE")
        if bound_hash == target_sha256:
            return path
    return None


def _validate_output_destination(path: Path, version: str,
                                 target_sha256: str) -> None:
    """Prevent cross-target overwrite and ambiguous new output names."""
    qualified = normalized_evidence_path(
        version, path.parent, target_sha256=target_sha256)
    generic = normalized_evidence_path(version, path.parent)
    if path.name == generic.name:
        if not path.is_file():
            raise IDANameArchiveError(
                "new normalized evidence requires a full target-SHA-qualified "
                "filename")
    elif path.name != qualified.name:
        raise IDANameArchiveError(
            "normalized evidence filename must contain the full target SHA-256")
    if path.is_file():
        binding = read_binding(str(path), KIND, require_content=False)
        if str(binding.get("target_sha256") or "").lower() != target_sha256:
            raise IDANameArchiveError(
                "refusing to overwrite normalized evidence for another PE")


def load_source_lock(path: os.PathLike[str] | str = LOCK_PATH) -> dict[str, Any]:
    """Load and structurally validate the committed external-input lock."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IDANameArchiveError("missing/invalid IDA archive source lock") from exc
    if value.get("schema") != LOCK_SCHEMA:
        raise IDANameArchiveError("unsupported IDA archive source-lock schema")
    artifact = value.get("artifact")
    provenance = value.get("provenance")
    entries = value.get("entries")
    if not isinstance(artifact, dict) or not isinstance(provenance, dict) \
            or not isinstance(entries, list) or not entries:
        raise IDANameArchiveError("incomplete IDA archive source lock")
    if not _SHA256_RE.fullmatch(str(artifact.get("sha256") or "")):
        raise IDANameArchiveError("source lock has no archive SHA-256")
    if int(artifact.get("size", 0)) <= 0:
        raise IDANameArchiveError("source lock has no archive size")
    if (provenance.get("license") != "unknown" or
            provenance.get("redistribution_allowed") is not False or
            provenance.get("raw_input_policy") != "local-only"):
        raise IDANameArchiveError(
            "external input must remain explicitly unlicensed/local-only")
    seen_versions: set[str] = set()
    seen_names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise IDANameArchiveError("invalid entry in IDA archive source lock")
        name = str(entry.get("name") or "")
        version = str(entry.get("version") or "")
        match = _ENTRY_RE.fullmatch(name)
        if match is None or match.group(1) != version:
            raise IDANameArchiveError("source-lock entry name/version mismatch")
        if name in seen_names or version in seen_versions:
            raise IDANameArchiveError("duplicate source-lock entry/version")
        seen_names.add(name)
        seen_versions.add(version)
        if not _SHA256_RE.fullmatch(str(entry.get("sha256") or "")):
            raise IDANameArchiveError("source-lock entry has no SHA-256")
        for key in ("size", "records", "bare_rva_records", "unique_names",
                    "duplicate_name_groups", "records_in_duplicate_name_groups"):
            if int(entry.get(key, -1)) < 0:
                raise IDANameArchiveError(
                    "source-lock entry has invalid {}".format(key))
        targets = entry.get("approved_target_sha256")
        if not isinstance(targets, list) or any(
                not _SHA256_RE.fullmatch(str(item or "")) for item in targets):
            raise IDANameArchiveError(
                "source-lock entry has invalid approved-target list")
    return value


def _is_name_wrapper(node: ast.AST) -> bool:
    if not isinstance(node, ast.FunctionDef) or node.name != "NAME":
        return False
    args = node.args
    if (len(args.args) != 2 or [arg.arg for arg in args.args] != ["ea", "name"]
            or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or args.defaults or args.kw_defaults or node.decorator_list
            or node.returns is not None or len(node.body) != 1):
        return False
    statement = node.body[0]
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "idc"
        and call.func.attr == "set_name"
        and not call.keywords
        and len(call.args) == 3
        and isinstance(call.args[0], ast.Name) and call.args[0].id == "ea"
        and isinstance(call.args[1], ast.Name) and call.args[1].id == "name"
        and isinstance(call.args[2], ast.Name) and call.args[2].id == "SN_CHECK"
    )


def _constant_call(node: ast.AST, function: str) -> ast.Call | None:
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
        return None
    call = node.value
    if not isinstance(call.func, ast.Name) or call.func.id != function \
            or call.keywords:
        return None
    return call


def _parse_ida_script(source: bytes, filename: str) -> list[dict[str, Any]]:
    """Parse the one permitted generated-script grammar without executing it."""
    try:
        text = source.decode("utf-8", errors="strict")
        tree = ast.parse(text, filename=filename)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise IDANameArchiveError(
            "{} is not strict UTF-8/Python".format(filename)) from exc
    if not tree.body or not _is_name_wrapper(tree.body[0]):
        raise IDANameArchiveError(
            "{} has an unexpected NAME wrapper".format(filename))
    if len(tree.body) < 3:
        raise IDANameArchiveError("{} has no name records".format(filename))

    records: list[dict[str, Any]] = []
    prints: list[str] = []
    for node in tree.body[1:]:
        print_call = _constant_call(node, "print")
        if print_call is not None:
            if (len(print_call.args) != 1 or
                    not isinstance(print_call.args[0], ast.Constant) or
                    not isinstance(print_call.args[0].value, str)):
                raise IDANameArchiveError(
                    "{} has a non-constant print call".format(filename))
            prints.append(print_call.args[0].value)
            continue
        name_call = _constant_call(node, "NAME")
        if name_call is None or len(name_call.args) != 2:
            raise IDANameArchiveError(
                "{} contains non-allowlisted Python at line {}".format(
                    filename, getattr(node, "lineno", 0)))
        address_node, name_node = name_call.args
        if (not isinstance(address_node, ast.Constant)
                or not isinstance(address_node.value, int)
                or isinstance(address_node.value, bool)
                or not isinstance(name_node, ast.Constant)
                or not isinstance(name_node.value, str)):
            raise IDANameArchiveError(
                "{} has a non-constant NAME call at line {}".format(
                    filename, getattr(node, "lineno", 0)))
        records.append({
            "source_address": int(address_node.value),
            "raw_name": name_node.value,
            "line": int(getattr(node, "lineno", 0)),
        })
    if prints != ["Importing names...", "Done with name import"]:
        raise IDANameArchiveError(
            "{} has unexpected progress calls".format(filename))
    return records


def _entry_metrics(records: list[dict[str, Any]], image_base: int) -> dict[str, int]:
    names = []
    suffix_mismatches = 0
    addresses = Counter()
    for record in records:
        address = int(record["source_address"])
        addresses[address] += 1
        match = _ADDR_SUFFIX_RE.search(str(record["raw_name"]))
        if match is None or int(match.group(1), 16) != address:
            suffix_mismatches += 1
            clean = str(record["raw_name"])
        else:
            clean = str(record["raw_name"])[:match.start()]
        names.append(clean)
    name_counts = Counter(names)
    return {
        "records": len(records),
        "bare_rva_records": sum(
            int(record["source_address"]) < image_base for record in records),
        "unique_names": len(name_counts),
        "duplicate_name_groups": sum(
            count > 1 for count in name_counts.values()),
        "records_in_duplicate_name_groups": sum(
            count for count in name_counts.values() if count > 1),
        "duplicate_address_groups": sum(
            count > 1 for count in addresses.values()),
        "suffix_mismatches": suffix_mismatches,
    }


def _read_locked_archive(
        archive_path: os.PathLike[str] | str,
        lock_path: os.PathLike[str] | str = LOCK_PATH,
        ) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, Any]]:
    lock = load_source_lock(lock_path)
    archive_path = Path(archive_path)
    if not archive_path.is_file():
        raise IDANameArchiveError("IDA name archive does not exist")
    artifact = lock["artifact"]
    if archive_path.stat().st_size != int(artifact["size"]):
        raise IDANameArchiveError("IDA name archive size differs from source lock")
    archive_hash = _sha256_file(archive_path)
    if archive_hash != artifact["sha256"]:
        raise IDANameArchiveError("IDA name archive SHA-256 differs from source lock")

    expected = {entry["name"]: entry for entry in lock["entries"]}
    parsed: dict[str, list[dict[str, Any]]] = {}
    report_entries = []
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise IDANameArchiveError("IDA name archive has duplicate entries")
            if set(names) != set(expected):
                missing = sorted(set(expected) - set(names))
                extra = sorted(set(names) - set(expected))
                raise IDANameArchiveError(
                    "IDA name archive entry set differs from source lock "
                    "(missing={!r}, extra={!r})".format(missing, extra))
            for info in infos:
                path = PurePosixPath(info.filename)
                unix_mode = (int(info.external_attr) >> 16) & 0o170000
                if (info.is_dir() or len(path.parts) != 1 or
                        path.name != info.filename or unix_mode == 0o120000 or
                        (int(info.flag_bits) & 1)):
                    raise IDANameArchiveError(
                        "unsafe ZIP entry: {}".format(info.filename))
                locked = expected[info.filename]
                if info.file_size != int(locked["size"]):
                    raise IDANameArchiveError(
                        "{} size differs from source lock".format(info.filename))
                source = archive.read(info)
                if _sha256_bytes(source) != locked["sha256"]:
                    raise IDANameArchiveError(
                        "{} SHA-256 differs from source lock".format(info.filename))
                records = _parse_ida_script(source, info.filename)
                metrics = _entry_metrics(records, int(artifact["image_base"]))
                for key in ("records", "bare_rva_records", "unique_names",
                            "duplicate_name_groups",
                            "records_in_duplicate_name_groups"):
                    if metrics[key] != int(locked[key]):
                        raise IDANameArchiveError(
                            "{} {} differs from source lock".format(
                                info.filename, key))
                if metrics["duplicate_address_groups"] or metrics["suffix_mismatches"]:
                    raise IDANameArchiveError(
                        "{} has duplicate addresses or broken suffixes".format(
                            info.filename))
                parsed[locked["version"]] = records
                report_entries.append({
                    "name": info.filename,
                    "version": locked["version"],
                    "sha256": locked["sha256"],
                    **metrics,
                    "approved_target_count": len(
                        locked["approved_target_sha256"]),
                })
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise IDANameArchiveError("invalid IDA name ZIP archive") from exc

    report = {
        "schema": "bgs-f4-ida-name-audit-v1",
        "archive": {
            "name": artifact["name"],
            "size": int(artifact["size"]),
            "sha256": archive_hash,
        },
        "provenance": lock["provenance"],
        "entries": sorted(report_entries, key=lambda row: row["version"]),
    }
    return lock, parsed, report


def audit_archive(archive_path: os.PathLike[str] | str) -> dict[str, Any]:
    """Validate the locked ZIP and return a non-symbol audit report."""
    _lock, _parsed, report = _read_locked_archive(archive_path)
    return report


def _section_for_rva(manifest: dict[str, Any], rva: int) -> dict[str, Any] | None:
    for section in manifest.get("sections", []):
        start = int(section.get("rva", 0))
        span = max(int(section.get("virtual_size", 0)),
                   int(section.get("raw_size", 0)))
        if start <= rva < start + span:
            return section
    return None


def _target_for_evidence(manifest: dict[str, Any]) -> dict[str, Any]:
    target = canonical_identity(manifest)
    target["version_string"] = manifest.get("version_string")
    target["sections"] = manifest.get("sections", [])
    target["anchors"] = manifest.get("anchors", [])
    return target


def _normalize_records(
        records: Iterable[dict[str, Any]], version: str,
        manifest: dict[str, Any], source: dict[str, Any],
        ) -> dict[str, Any]:
    """Pure normalizer used by the PE-bound CLI and unit tests."""
    expected_version = [int(part) for part in version.split(".")]
    if list(manifest.get("file_version") or []) != expected_version:
        raise IDANameArchiveError(
            "archive entry {} does not match target version {}".format(
                version, manifest.get("version_string")))
    if (int(manifest.get("machine", 0)) != 0x8664 or
            int(manifest.get("pointer_size", 0)) != 8):
        raise IDANameArchiveError("IDA name evidence requires an AMD64 target")
    image_base = int(manifest.get("image_base", 0))
    image_size = int(manifest.get("image_size", 0))
    if image_base <= 0 or image_size <= 0 or not manifest.get("sections"):
        raise IDANameArchiveError("target PE manifest has no mapped layout")
    runtime_starts = {int(value) for value in manifest.get("function_starts", [])}
    if not runtime_starts:
        raise IDANameArchiveError(
            "target PE has no validated AMD64 runtime-function starts")

    prepared: list[dict[str, Any]] = []
    for record in records:
        source_address = int(record["source_address"])
        raw_name = str(record["raw_name"])
        reasons: list[str] = []
        suffix = _ADDR_SUFFIX_RE.search(raw_name)
        if suffix is None or int(suffix.group(1), 16) != source_address:
            clean_name = raw_name
            reasons.append("address_suffix_mismatch")
        else:
            clean_name = raw_name[:suffix.start()].strip()
        if not clean_name or _PLACEHOLDER_RE.fullmatch(clean_name):
            reasons.append("empty_or_placeholder_name")

        if image_base <= source_address < image_base + image_size:
            rva = source_address - image_base
            source_coordinate = "VA"
        elif 0 < source_address < image_size:
            rva = source_address
            source_coordinate = "RVA"
        else:
            rva = -1
            source_coordinate = "INVALID"
            reasons.append("outside_target_image")
        section = _section_for_rva(manifest, rva) if rva > 0 else None
        if section is None:
            reasons.append("unmapped_rva")
        prepared.append({
            "rva": rva,
            "name": clean_name,
            "raw_name": raw_name,
            "source_address": source_address,
            "source_coordinate": source_coordinate,
            "section": str(section.get("name") or "") if section else "",
            "section_executable": bool(section and section.get("executable")),
            "line": int(record.get("line", 0)),
            "reasons": reasons,
        })

    by_rva: dict[int, set[str]] = defaultdict(set)
    by_name: dict[str, set[int]] = defaultdict(set)
    for row in prepared:
        if row["rva"] > 0 and row["name"]:
            by_rva[row["rva"]].add(row["name"])
            by_name[row["name"]].add(row["rva"])

    accepted = []
    quarantined = []
    for row in prepared:
        reasons = list(row.pop("reasons"))
        rva = int(row["rva"])
        name = str(row["name"])
        if rva > 0 and len(by_rva[rva]) > 1:
            reasons.append("same_rva_alias")
        if name and len(by_name[name]) > 1:
            reasons.append("same_name_multiple_rvas")
        if row["section_executable"]:
            kind = "func"
            verified_entry = rva in runtime_starts
            if not verified_entry:
                reasons.append("not_runtime_function_start")
        else:
            kind = "label"
            verified_entry = False
        normalized = {
            "rva": rva,
            "name": name,
            "kind": kind,
            "section": row["section"],
            "verified_entry": verified_entry,
            "source_coordinate": row["source_coordinate"],
            "source_address": int(row["source_address"]),
            "raw_name": row["raw_name"],
            "line": int(row["line"]),
        }
        if reasons:
            normalized["reasons"] = sorted(set(reasons))
            quarantined.append(normalized)
        else:
            accepted.append(normalized)

    accepted.sort(key=lambda row: (row["rva"], row["name"]))
    quarantined.sort(key=lambda row: (
        row["rva"] if row["rva"] >= 0 else 1 << 64, row["name"]))
    reason_counts = Counter(
        reason for row in quarantined for reason in row["reasons"])
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "version": version,
        "address_coordinate": "RVA",
        "source": source,
        "target": _target_for_evidence(manifest),
        "counts": {
            "raw_records": len(prepared),
            "accepted_records": len(accepted),
            "functions": sum(row["kind"] == "func" for row in accepted),
            "labels": sum(row["kind"] == "label" for row in accepted),
            "source_va_records": sum(
                row["source_coordinate"] == "VA" for row in prepared),
            "source_rva_records": sum(
                row["source_coordinate"] == "RVA" for row in prepared),
            "quarantined_records": len(quarantined),
            "quarantine_reasons": dict(sorted(reason_counts.items())),
        },
        "records": accepted,
        "quarantine": quarantined,
        "policy": {
            "merge_priority": (
                "primary/CommonLib and exact PDB > exact IDA map > "
                "cross-version ports"),
            "overwrite_conflicts": False,
            "redistribution_allowed": False,
        },
    }


def normalize_archive(
        archive_path: os.PathLike[str] | str, version: str,
        target_pe: os.PathLike[str] | str,
        output_path: os.PathLike[str] | str,
        ) -> dict[str, Any]:
    """Create content- and exact-PE-bound normalized evidence."""
    lock, parsed, _report = _read_locked_archive(archive_path)
    if version not in parsed:
        raise IDANameArchiveError("archive has no version " + version)
    locked_entry = next(
        entry for entry in lock["entries"] if entry["version"] == version)
    manifest = inspect_pe(str(target_pe))
    target_hash = str(manifest.get("sha256") or "").lower()
    approved = set(locked_entry["approved_target_sha256"])
    if not approved:
        raise IDANameArchiveError(
            "{} has no independently approved exact target; add a verified "
            "PE identity to the source lock before normalization".format(version))
    if target_hash not in approved:
        raise IDANameArchiveError(
            "target PE SHA-256 is not approved for archive version " + version)
    output_path = Path(output_path)
    _validate_output_destination(output_path, version, target_hash)
    source = {
        "archive_name": lock["artifact"]["name"],
        "archive_sha256": lock["artifact"]["sha256"],
        "entry_name": locked_entry["name"],
        "entry_sha256": locked_entry["sha256"],
        "license": lock["provenance"]["license"],
        "redistribution_allowed": False,
        "raw_input_policy": "local-only",
    }
    payload = _normalize_records(parsed[version], version, manifest, source)
    _atomic_json(output_path, payload)
    bind_for_hash(
        str(output_path), KIND, target_hash,
        program_name=str(manifest.get("file_name") or "Fallout4.exe"),
        image_base=int(manifest["image_base"]),
        pointer_size=int(manifest["pointer_size"]),
        address_coordinate="RVA")
    return payload


def load_normalized_evidence(
        evidence_path: os.PathLike[str] | str,
        target_manifest: dict[str, Any],
        expected_version: str | None = None,
        ) -> list[dict[str, Any]]:
    """Load normalized records only after content and target verification."""
    evidence_path = Path(evidence_path)
    binding = read_binding(str(evidence_path), KIND, require_content=True)
    target_hash = str(target_manifest.get("sha256") or "").lower()
    if binding["target_sha256"].lower() != target_hash:
        raise IDANameArchiveError("normalized IDA evidence targets another PE")
    if (binding.get("address_coordinate") != "RVA" or
            int(binding.get("image_base", 0)) !=
            int(target_manifest.get("image_base", -1)) or
            int(binding.get("pointer_size", 0)) !=
            int(target_manifest.get("pointer_size", -1))):
        raise IDANameArchiveError("normalized IDA evidence ABI binding differs")
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IDANameArchiveError("invalid normalized IDA evidence JSON") from exc
    if payload.get("schema") != SCHEMA or payload.get("kind") != KIND \
            or payload.get("address_coordinate") != "RVA":
        raise IDANameArchiveError("unsupported normalized IDA evidence schema")
    version = str(payload.get("version") or "")
    if expected_version is not None and version != expected_version:
        raise IDANameArchiveError("normalized IDA evidence version differs")
    matches, reasons = manifest_matches(payload.get("target") or {}, target_manifest)
    if not matches:
        raise IDANameArchiveError(
            "normalized IDA target manifest differs: " + "; ".join(reasons[:8]))

    lock = load_source_lock()
    locked_entry = next(
        (entry for entry in lock["entries"] if entry["version"] == version), None)
    source = payload.get("source")
    if locked_entry is None or not isinstance(source, dict):
        raise IDANameArchiveError("normalized IDA evidence has unknown provenance")
    expected_source = {
        "archive_name": lock["artifact"]["name"],
        "archive_sha256": lock["artifact"]["sha256"],
        "entry_name": locked_entry["name"],
        "entry_sha256": locked_entry["sha256"],
        "license": "unknown",
        "redistribution_allowed": False,
        "raw_input_policy": "local-only",
    }
    if source != expected_source or target_hash not in set(
            locked_entry["approved_target_sha256"]):
        raise IDANameArchiveError(
            "normalized IDA evidence source/target is not source-locked")

    records = payload.get("records")
    quarantine = payload.get("quarantine")
    counts = payload.get("counts")
    if not isinstance(records, list) or not isinstance(quarantine, list) \
            or not isinstance(counts, dict):
        raise IDANameArchiveError("normalized IDA evidence is incomplete")
    runtime_starts = {
        int(value) for value in target_manifest.get("function_starts", [])}
    seen_rvas: set[int] = set()
    seen_names: set[str] = set()
    previous = -1
    for record in records:
        if not isinstance(record, dict):
            raise IDANameArchiveError("normalized IDA record is not an object")
        rva = int(record.get("rva", -1))
        name = str(record.get("name") or "")
        kind = record.get("kind")
        section = _section_for_rva(target_manifest, rva)
        if (rva <= previous or rva in seen_rvas or name in seen_names or
                not name or section is None):
            raise IDANameArchiveError(
                "normalized IDA records are ambiguous, unmapped, or unsorted")
        executable = bool(section.get("executable"))
        if ((kind == "func" and
             (not executable or not record.get("verified_entry") or
              rva not in runtime_starts)) or
                (kind == "label" and executable) or
                kind not in ("func", "label")):
            raise IDANameArchiveError(
                "normalized IDA record has an unsafe kind classification")
        if str(record.get("section") or "") != str(section.get("name") or ""):
            raise IDANameArchiveError(
                "normalized IDA record section differs from target")
        seen_rvas.add(rva)
        seen_names.add(name)
        previous = rva
    if (int(counts.get("accepted_records", -1)) != len(records) or
            int(counts.get("functions", -1)) !=
            sum(record["kind"] == "func" for record in records) or
            int(counts.get("labels", -1)) !=
            sum(record["kind"] == "label" for record in records) or
            int(counts.get("quarantined_records", -1)) != len(quarantine)):
        raise IDANameArchiveError("normalized IDA evidence counts differ")
    return records


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "archive": report["archive"],
        "provenance": report["provenance"],
        "entries": [{
            "version": row["version"],
            "records": row["records"],
            "bare_rva_records": row["bare_rva_records"],
            "duplicate_name_groups": row["duplicate_name_groups"],
            "approved_target_count": row["approved_target_count"],
        } for row in report["entries"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="validate without extracting")
    audit.add_argument("archive", type=Path)
    normalize = subparsers.add_parser(
        "normalize", help="emit exact-PE-bound local evidence")
    normalize.add_argument("archive", type=Path)
    normalize.add_argument("--version", required=True)
    normalize.add_argument("--target", required=True, type=Path)
    normalize.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "audit":
        print(json.dumps(_summary(audit_archive(args.archive)), indent=2))
        return 0
    payload = normalize_archive(
        args.archive, args.version, args.target, args.output)
    print(json.dumps({
        "output": str(args.output),
        "identity": str(args.output) + ".identity.json",
        "version": payload["version"],
        "target_sha256": payload["target"]["sha256"],
        "counts": payload["counts"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
