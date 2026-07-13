"""Target-identity sidecars for persistent enrichment evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile


SCHEMA = "bgs-enrichment-evidence-v2"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class EvidenceIdentityError(ValueError):
    pass


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sidecar_path(evidence_path):
    return str(evidence_path) + ".identity.json"


def program_sha256(program):
    imported = ""
    try:
        imported = str(program.getExecutableSHA256() or "").lower()
    except Exception:
        pass
    bound = ""
    try:
        from ghidra.program.model.listing import Program
        raw = program.getOptions(Program.PROGRAM_INFO).getString(
            "BGS Target Manifest", "") or ""
        bound = str(json.loads(raw).get("sha256") or "").lower() if raw else ""
    except Exception:
        pass
    if imported and bound and imported != bound:
        raise EvidenceIdentityError(
            "Program import SHA-256 disagrees with BGS target manifest")
    result = bound or imported
    if not _SHA256.fullmatch(result):
        raise EvidenceIdentityError(
            "Program has no trustworthy executable SHA-256; re-import it")
    return result


def _atomic_json(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp",
                                dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def bind_for_hash(evidence_path, kind, target_sha256, program_name="",
                  image_base=None, pointer_size=None,
                  address_coordinate="NONE"):
    target_sha256 = str(target_sha256).lower()
    if not _SHA256.fullmatch(target_sha256):
        raise EvidenceIdentityError("invalid evidence target SHA-256")
    if not os.path.isfile(evidence_path):
        raise EvidenceIdentityError("evidence file does not exist: " + str(evidence_path))
    coordinate = str(address_coordinate or "NONE").upper()
    if coordinate not in ("VA", "RVA", "NONE"):
        raise EvidenceIdentityError("evidence address coordinate is invalid")
    if coordinate != "NONE":
        if int(image_base or 0) <= 0:
            raise EvidenceIdentityError(
                "address-bearing evidence requires an image base")
        if int(pointer_size or 0) not in (4, 8):
            raise EvidenceIdentityError(
                "address-bearing evidence requires a pointer size")
    payload = {
        "schema": SCHEMA,
        "kind": str(kind),
        "program_name": str(program_name),
        "target_sha256": target_sha256,
        "evidence_sha256": _file_sha256(evidence_path),
        "address_coordinate": coordinate,
    }
    if coordinate != "NONE":
        payload["image_base"] = int(image_base)
        payload["pointer_size"] = int(pointer_size)
    _atomic_json(sidecar_path(evidence_path), payload)
    return payload


def bind_evidence(evidence_path, program, kind, address_coordinate="NONE"):
    return bind_for_hash(evidence_path, kind, program_sha256(program),
                         program.getName(),
                         image_base=int(program.getImageBase().getOffset()),
                         pointer_size=int(program.getDefaultPointerSize()),
                         address_coordinate=address_coordinate)


def read_binding(evidence_path, kind=None, require_content=False):
    path = sidecar_path(evidence_path)
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise EvidenceIdentityError(
            "missing/invalid evidence identity sidecar: " + path) from exc
    if payload.get("schema") != SCHEMA:
        raise EvidenceIdentityError("unsupported evidence identity schema")
    if kind is not None and payload.get("kind") != kind:
        raise EvidenceIdentityError(
            "evidence kind {} != {}".format(payload.get("kind"), kind))
    if not _SHA256.fullmatch(str(payload.get("target_sha256") or "")):
        raise EvidenceIdentityError("evidence sidecar has no target SHA-256")
    coordinate = str(payload.get("address_coordinate") or "").upper()
    if coordinate not in ("VA", "RVA", "NONE"):
        raise EvidenceIdentityError(
            "evidence sidecar has no explicit address coordinate")
    if coordinate != "NONE" and (
            int(payload.get("image_base") or 0) <= 0 or
            int(payload.get("pointer_size") or 0) not in (4, 8)):
        raise EvidenceIdentityError(
            "address-bearing evidence sidecar has no ABI/image binding")
    if require_content and _file_sha256(evidence_path) != payload.get("evidence_sha256"):
        raise EvidenceIdentityError("evidence content changed after mining")
    return payload


def validate_evidence(evidence_path, program, kind, require_content=False):
    payload = read_binding(evidence_path, kind, require_content)
    actual = program_sha256(program)
    if payload["target_sha256"].lower() != actual:
        raise EvidenceIdentityError(
            "evidence target {} does not match Program {}".format(
                payload["target_sha256"], actual))
    if payload["address_coordinate"] != "NONE":
        loaded_pointer_size = int(program.getDefaultPointerSize())
        if (payload["address_coordinate"] == "VA" and
                int(program.getImageBase().getOffset()) !=
                int(payload["image_base"])):
            raise EvidenceIdentityError(
                "evidence image base 0x{:X} does not match Program 0x{:X}".format(
                    int(payload["image_base"]),
                    int(program.getImageBase().getOffset())))
        if loaded_pointer_size != int(payload["pointer_size"]):
            raise EvidenceIdentityError(
                "evidence pointer size does not match Program")
    return payload
