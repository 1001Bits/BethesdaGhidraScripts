#!/usr/bin/env python3
"""Scan importers, exports, packages, PDBs, logs, or copied comments for BGS provenance."""
import argparse
import ast
import io
import json
from pathlib import Path
import re
import zipfile

from provenance import CANARY_PREFIX, PDB_CANARY_PREFIX, validate_manifest


_IMPORTER_RE = re.compile(
    r"^BGS_PROVENANCE\s*=\s*_json_target\.loads\((.+)\)\s*$", re.M)
_CANARY_RE = re.compile(
    rb"(?:BGS-CANARY-v1:|__BGS_PROVENANCE_)([0-9a-fA-F]{64})")


def _walk_json(value):
    if isinstance(value, dict):
        if {"schema_version", "provenance_id", "target_sha256", "canary"} \
                <= set(value):
            yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _importer_manifest(text):
    match = _IMPORTER_RE.search(text)
    if not match:
        return None
    encoded = ast.literal_eval(match.group(1))
    return json.loads(encoded)


def scan_bytes(name, data, public_key=None):
    findings = []
    suffix = Path(name).suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                findings.extend(scan_bytes(name + "!" + member.filename,
                                           archive.read(member), public_key))
        return findings
    if suffix == ".py":
        try:
            manifest = _importer_manifest(data.decode("utf-8"))
        except (UnicodeDecodeError, SyntaxError, ValueError, json.JSONDecodeError):
            manifest = None
        if manifest is not None:
            validate_manifest(manifest, public_key=public_key)
            findings.append({"path": name, "kind": "manifest",
                             "provenance_id": manifest["provenance_id"],
                             "signature_state": _signature_state(
                                 manifest, public_key)})
    if suffix == ".json":
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if document is not None:
            for manifest in _walk_json(document):
                validate_manifest(manifest, public_key=public_key)
                findings.append({"path": name, "kind": "manifest",
                                 "provenance_id": manifest["provenance_id"],
                                 "signature_state": _signature_state(
                                     manifest, public_key)})
    known_ids = {finding["provenance_id"] for finding in findings}
    for match in _CANARY_RE.finditer(data):
        provenance_id = match.group(1).decode("ascii").lower()
        if provenance_id in known_ids:
            continue
        kind = "pdb-canary" if match.group(0).startswith(
            PDB_CANARY_PREFIX.encode("ascii")) else "comment-canary"
        if provenance_id not in known_ids:
            findings.append({"path": name, "kind": kind,
                             "provenance_id": provenance_id,
                             "signature_state": "marker-only"})
            known_ids.add(provenance_id)
    return findings


def _signature_state(manifest, public_key):
    if not manifest.get("signature"):
        return "unsigned"
    return "signed-trusted" if public_key is not None else "signed-unverified"


def scan_path(path, public_key=None):
    path = Path(path)
    if path.is_dir():
        findings = []
        for child in sorted(item for item in path.rglob("*") if item.is_file()
                            and ".git" not in item.parts):
            findings.extend(scan_bytes(str(child), child.read_bytes(), public_key))
        return findings
    return scan_bytes(str(path), path.read_bytes(), public_key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--public-key",
                        help="trusted Ed25519 public key; requires signed manifests")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    findings = []
    try:
        for path in args.paths:
            findings.extend(scan_path(path, args.public_key))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print("INVALID: " + str(exc))
        return 2
    if args.json:
        print(json.dumps(findings, indent=2, sort_keys=True))
    else:
        for finding in findings:
            print("{}  {}  {}  {}".format(
                finding["kind"], finding["provenance_id"],
                finding["signature_state"],
                finding["path"]))
    if not findings:
        print("No BGS provenance or canary found.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
