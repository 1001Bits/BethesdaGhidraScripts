"""Canonical, target-bound Bethesda Ghidra Scripts provenance manifests."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path


SCHEMA_VERSION = 1
PROGRAM_INFO_KEY = "BGS_PROVENANCE"
CANARY_PREFIX = "BGS-CANARY-v1:"
PDB_CANARY_PREFIX = "__BGS_PROVENANCE_"
_HASH_FIELDS = ("generator_sha256", "toolchain_sha256")


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_hash(value) -> bool:
    return (isinstance(value, str) and len(value) == 64 and
            all(char in "0123456789abcdef" for char in value.lower()))


def _identity_payload(manifest):
    return {
        "schema_version": manifest["schema_version"],
        "release_id": manifest["release_id"],
        "generator_sha256": manifest["generator_sha256"],
        "toolchain_sha256": manifest["toolchain_sha256"],
        "target_sha256": manifest["target_sha256"],
    }


def unsigned_payload(manifest) -> bytes:
    document = dict(manifest)
    document.pop("signature", None)
    return canonical_json(document).encode("ascii")


def validate_manifest(manifest, public_key=None):
    if not isinstance(manifest, dict):
        raise ValueError("BGS provenance must be a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported BGS provenance schema")
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not release_id or len(release_id) > 128:
        raise ValueError("invalid BGS provenance release ID")
    for field in _HASH_FIELDS:
        if not _valid_hash(manifest.get(field)):
            raise ValueError("invalid BGS provenance " + field)
    targets = manifest.get("target_sha256")
    if not isinstance(targets, list) or not targets or targets != sorted(set(targets)):
        raise ValueError("target_sha256 must be a nonempty sorted unique list")
    if not all(_valid_hash(value) for value in targets):
        raise ValueError("invalid target SHA-256 in BGS provenance")
    expected_id = hashlib.sha256(
        canonical_json(_identity_payload(manifest)).encode("ascii")).hexdigest()
    if manifest.get("provenance_id") != expected_id:
        raise ValueError("BGS provenance ID does not match its manifest")
    expected_canary = CANARY_PREFIX + expected_id
    if manifest.get("canary") != expected_canary:
        raise ValueError("BGS provenance canary does not match its manifest")
    expected_comment = (expected_canary +
                        " | Bethesda Ghidra Scripts transparent provenance")
    if manifest.get("canary_comment") != expected_comment:
        raise ValueError("BGS provenance comment canary does not match")
    signature = manifest.get("signature")
    if signature is not None:
        if (not isinstance(signature, dict) or
                signature.get("algorithm") != "ed25519"):
            raise ValueError("invalid BGS provenance signature metadata")
        key_id = signature.get("key_id")
        if (not isinstance(key_id, str) or len(key_id) != 16 or
                any(char not in "0123456789abcdef" for char in key_id.lower())):
            raise ValueError("invalid BGS provenance signature key ID")
        try:
            value = base64.b64decode(signature.get("value", ""), validate=True)
        except Exception as exc:
            raise ValueError("invalid BGS provenance signature encoding") from exc
        if len(value) != 64:
            raise ValueError("invalid BGS provenance signature length")
    if public_key is not None:
        verify_manifest_signature(manifest, public_key)
    return manifest


def _load_release_id(repo_dir, release_id=None):
    value = release_id or os.environ.get("BGS_RELEASE_ID")
    if value:
        return str(value).strip()
    version_path = Path(repo_dir) / "VERSION"
    if version_path.is_file():
        value = version_path.read_text(encoding="ascii").strip()
    return value or "unreleased"


def build_manifest(repo_dir, generator_path, target_manifests,
                   release_id=None, signing_key=None):
    repo_dir = Path(repo_dir).resolve()
    hashes = []
    for item in target_manifests:
        if not isinstance(item, dict):
            raise ValueError("target manifest must be a JSON object")
        digest = str(item.get("sha256") or "").lower()
        if not _valid_hash(digest):
            raise ValueError("target manifest has no valid SHA-256")
        hashes.append(digest)
    hashes = sorted(set(hashes))
    if not hashes:
        raise ValueError("at least one target manifest is required")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "release_id": _load_release_id(repo_dir, release_id),
        "generator_sha256": sha256_file(generator_path),
        "toolchain_sha256": sha256_file(repo_dir / "toolchain.lock.json"),
        "target_sha256": hashes,
    }
    provenance_id = hashlib.sha256(
        canonical_json(_identity_payload(manifest)).encode("ascii")).hexdigest()
    manifest["provenance_id"] = provenance_id
    manifest["canary"] = CANARY_PREFIX + provenance_id
    manifest["canary_comment"] = (
        manifest["canary"] +
        " | Bethesda Ghidra Scripts transparent provenance")
    key_path = signing_key or os.environ.get("BGS_PROVENANCE_SIGNING_KEY")
    if key_path:
        manifest = sign_manifest(manifest, key_path)
    return validate_manifest(manifest)


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 support requires requirements-provenance.txt") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def _public_key_id(public_key, serialization) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()[:16]


def sign_manifest(manifest, private_key_path):
    serialization, Ed25519PrivateKey, _ = _crypto()
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("provenance signing key is not Ed25519")
    document = dict(manifest)
    document.pop("signature", None)
    signature = private_key.sign(unsigned_payload(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "key_id": _public_key_id(private_key.public_key(), serialization),
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return document


def verify_manifest_signature(manifest, public_key_path):
    serialization, _, Ed25519PublicKey = _crypto()
    signature = manifest.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        raise ValueError("BGS provenance has no Ed25519 signature")
    public_key = serialization.load_pem_public_key(
        Path(public_key_path).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("trusted provenance key is not Ed25519")
    key_id = _public_key_id(public_key, serialization)
    if signature.get("key_id") != key_id:
        raise ValueError("BGS provenance signature key ID is not trusted")
    try:
        value = base64.b64decode(signature.get("value", ""), validate=True)
        public_key.verify(value, unsigned_payload(manifest))
    except Exception as exc:
        raise ValueError("invalid BGS provenance signature") from exc
    return True


def generate_keypair(private_path, public_path):
    serialization, Ed25519PrivateKey, _ = _crypto()
    private_path = Path(private_path)
    public_path = Path(public_path)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing provenance key")
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return _public_key_id(private_key.public_key(), serialization)


def pdb_canary_name(manifest) -> str:
    validate_manifest(manifest)
    return PDB_CANARY_PREFIX + manifest["provenance_id"]


GHIDRA_PROVENANCE_APPLY_SNIPPET = r'''
def _apply_bgs_provenance():
    """Persist transparent provenance and tag real named functions only."""
    if not BGS_PROVENANCE:
        raise RuntimeError('Generated importer has no BGS_PROVENANCE manifest')
    tx = currentProgram.startTransaction('BGS provenance')
    success = False
    try:
        from ghidra.program.model.listing import Program
        raw = _json_target.dumps(BGS_PROVENANCE, sort_keys=True,
                                 separators=(',', ':'))
        info = currentProgram.getOptions(Program.PROGRAM_INFO)
        info.setString('BGS_PROVENANCE', raw)
        marker = BGS_PROVENANCE.get('canary_comment', '')
        tagged = 0
        for func in currentProgram.getFunctionManager().getFunctions(True):
            if tagged >= 3:
                break
            if func.isExternal():
                continue
            name = str(func.getName() or '')
            if (not name or name.startswith('FUN_') or name.startswith('sub_')
                    or name.startswith('thunk_FUN_')):
                continue
            _merge_plate_comment(func.getEntryPoint(), [marker])
            tagged += 1
        success = True
    finally:
        currentProgram.endTransaction(tx, success)
    print('BGS provenance stored; canary comments applied to ' + str(tagged) +
          ' real named functions.')
'''
