"""Reproducible identity and layout metadata for PE inputs.

The improvement pipeline passes addresses between several independent tools.
Those artifacts are unsafe unless they are tied to the exact executable they
were derived from.  This module deliberately uses only the Python standard
library so it can be shared by the command-line runners and generators without
adding ``pefile`` as a bootstrap dependency.

The manifest is JSON serialisable.  Addresses stored in it are PE-relative
layout facts; consumers should still record the coordinate system of every
individual symbol (``rva`` or ``va``) alongside the symbol itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = 1

_MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "amd64",
    0xAA64: "arm64",
}

_DIRECTORY_NAMES = (
    "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "architecture", "globalptr", "tls", "load_config",
    "bound_import", "iat", "delay_import", "clr", "reserved",
)

_IDENTITY_KEYS = (
    "sha256",
    "file_size",
    "machine",
    "pointer_size",
    "image_base",
    "image_size",
    "timestamp",
    "file_version",
)


class PEIdentityError(ValueError):
    """Raised when a file is not a complete, supported PE image."""


def _read_exact(fh, size: int) -> bytes:
    data = fh.read(size)
    if len(data) != size:
        raise PEIdentityError("truncated PE image")
    return data


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _file_version(path: str) -> Optional[List[int]]:
    # Keep binary_identity usable when imported as either ``scripts.core`` or
    # as a loose module after scripts/core was put on sys.path.
    try:
        from .pe_version import get_pe_version
    except (ImportError, ValueError):
        try:
            from pe_version import get_pe_version
        except ImportError:
            return None
    value = get_pe_version(path)
    return list(value) if value else None


def inspect_pe(path: str, include_sha256: bool = True) -> Dict[str, Any]:
    """Return an exact-input manifest for *path*.

    The parser validates all header offsets against the physical file and
    includes section permissions so downstream address validation does not
    need to rediscover the PE layout.
    """
    path = os.path.abspath(path)
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if _read_exact(fh, 2) != b"MZ":
            raise PEIdentityError("missing DOS MZ signature: {}".format(path))
        fh.seek(0x3C)
        pe_offset = struct.unpack("<I", _read_exact(fh, 4))[0]
        if pe_offset < 0x40 or pe_offset + 24 > file_size:
            raise PEIdentityError("invalid PE header offset: 0x{:X}".format(pe_offset))
        fh.seek(pe_offset)
        if _read_exact(fh, 4) != b"PE\0\0":
            raise PEIdentityError("missing PE signature: {}".format(path))
        coff = _read_exact(fh, 20)
        machine, section_count, timestamp, _symptr, _symcount, opt_size, _chars = \
            struct.unpack("<HHIIIHH", coff)
        optional = _read_exact(fh, opt_size)
        if len(optional) < 60:
            raise PEIdentityError("truncated optional header")
        magic = struct.unpack_from("<H", optional, 0)[0]
        if magic == 0x20B:
            pointer_size = 8
            image_base = struct.unpack_from("<Q", optional, 24)[0]
            directory_count_offset = 108
            directory_offset = 112
        elif magic == 0x10B:
            pointer_size = 4
            image_base = struct.unpack_from("<I", optional, 28)[0]
            directory_count_offset = 92
            directory_offset = 96
        else:
            raise PEIdentityError("unsupported PE optional-header magic 0x{:X}".format(magic))
        expected_magic = {0x014C: 0x10B, 0x8664: 0x20B, 0xAA64: 0x20B}.get(machine)
        if expected_magic is None:
            raise PEIdentityError(
                "unsupported PE machine 0x{:04X}".format(machine))
        if magic != expected_magic:
            raise PEIdentityError(
                "machine 0x{:04X} is incompatible with optional-header magic "
                "0x{:X}".format(machine, magic))
        image_size = struct.unpack_from("<I", optional, 56)[0]
        directory_count = (struct.unpack_from("<I", optional,
                                              directory_count_offset)[0]
                           if len(optional) >= directory_count_offset + 4 else 0)
        available_directories = max(0, (len(optional) - directory_offset) // 8)
        data_directories = []
        for index in range(min(directory_count, available_directories, 16)):
            rva, size = struct.unpack_from(
                "<II", optional, directory_offset + index * 8)
            data_directories.append({
                "index": index,
                "name": _DIRECTORY_NAMES[index],
                "rva": rva,
                "size": size,
            })

        sections = []
        for _ in range(section_count):
            sh = _read_exact(fh, 40)
            raw_name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<8sIIII", sh, 0)
            characteristics = struct.unpack_from("<I", sh, 36)[0]
            name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
            if raw_offset and raw_size and raw_offset + raw_size > file_size:
                raise PEIdentityError(
                    "section {} extends beyond physical file".format(name or "<unnamed>"))
            sections.append({
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
            })

    version = _file_version(path)
    manifest = {
        "schema": SCHEMA_VERSION,
        "file_name": os.path.basename(path),
        "file_size": file_size,
        "machine": machine,
        "machine_name": _MACHINE_NAMES.get(machine, "0x{:04X}".format(machine)),
        "pointer_size": pointer_size,
        "image_base": image_base,
        "image_size": image_size,
        "timestamp": timestamp,
        "file_version": version,
        "version_string": ".".join(str(p) for p in version) if version else None,
        "sections": sections,
        "data_directories": data_directories,
        "anchors": _memory_anchors(path, sections),
        "function_starts": _runtime_function_starts(
            path, sections, machine, pointer_size, image_size,
            next((entry for entry in data_directories
                  if entry["name"] == "exception"), None)),
    }
    if include_sha256:
        manifest["sha256"] = _sha256(path)
    return manifest


def _memory_anchors(path: str, sections: Iterable[Dict[str, Any]],
                    width: int = 16, limit: int = 8) -> List[Dict[str, Any]]:
    """Select deterministic file-backed bytes at mapped section RVAs.

    Anchors are a fallback for old Ghidra programs that do not record the
    loader's executable SHA-256.  Multiple positions across executable and
    read-only sections detect a stale in-memory Program even when its backing
    file was replaced in place.
    """
    anchors = []
    ordered = sorted(sections, key=lambda s: (
        not s.get("executable"), not s.get("readable"), s.get("rva", 0)))
    with open(path, "rb") as fh:
        for section in ordered:
            raw_size = int(section.get("raw_size", 0))
            raw_offset = int(section.get("raw_offset", 0))
            if raw_size < width or not raw_offset:
                continue
            max_offset = raw_size - width
            positions = sorted(set((0, max_offset // 3, (2 * max_offset) // 3, max_offset)))
            for local in positions:
                fh.seek(raw_offset + local)
                data = fh.read(width)
                if len(data) != width or not any(data):
                    continue
                anchors.append({
                    "rva": int(section["rva"]) + local,
                    "bytes": data.hex(),
                    "section": section.get("name", ""),
                })
                if len(anchors) >= limit:
                    return anchors
    return anchors


def _raw_offset_for_rva(sections: Iterable[Dict[str, Any]], rva: int,
                        size: int = 1) -> Optional[int]:
    for section in sections:
        start = int(section.get("rva", 0))
        delta = rva - start
        if 0 <= delta and delta + size <= int(section.get("raw_size", 0)):
            return int(section.get("raw_offset", 0)) + delta
    return None


def _section_for_span(sections: Iterable[Dict[str, Any]], rva: int,
                      size: int = 1) -> Optional[Dict[str, Any]]:
    if size <= 0:
        return None
    for section in sections:
        start = int(section.get("rva", 0))
        span = max(int(section.get("virtual_size", 0)),
                   int(section.get("raw_size", 0)))
        if start <= rva and rva + size <= start + span:
            return section
    return None


def _valid_unwind_info(data: bytes, offset: int, sections: List[Dict[str, Any]],
                       image_size: int) -> bool:
    """Validate enough UNWIND_INFO to attest its owning function boundary."""
    owner = next((section for section in sections
                  if int(section.get("raw_offset", 0)) <= offset <
                  int(section.get("raw_offset", 0)) +
                  int(section.get("raw_size", 0))), None)
    owner_end = (int(owner.get("raw_offset", 0)) +
                 int(owner.get("raw_size", 0))) if owner else 0
    if owner is None or offset < 0 or offset + 4 > owner_end:
        return False
    vf, _prolog, code_count, frame = struct.unpack_from("<BBBB", data, offset)
    version = vf & 7
    flags = vf >> 3
    if version not in (1, 2) or flags & ~7:
        return False
    if (frame & 0x0F) == 0 and (frame >> 4):
        return False
    codes_start = offset + 4
    codes_end = codes_start + code_count * 2
    if codes_end > owner_end:
        return False
    slot = 0
    while slot < code_count:
        packed = data[codes_start + slot * 2 + 1]
        opcode, op_info = packed & 0x0F, packed >> 4
        if opcode > 10 or (opcode == 1 and op_info not in (0, 1)):
            return False
        if opcode == 3 and op_info != 0:
            return False
        if opcode in (6, 7) and version != 2:
            return False
        if opcode == 10 and op_info not in (0, 1):
            return False
        extra = (1 if opcode == 1 and op_info == 0 else
                 2 if opcode == 1 else
                 1 if opcode in (4, 8) else
                 2 if opcode in (5, 9) else 0)
        if slot + extra >= code_count:
            return False
        slot += 1 + extra
    tail = codes_start + ((code_count + 1) & ~1) * 2
    if tail > owner_end:
        return False
    if flags & 4:
        if flags & 3 or tail + 12 > owner_end:
            return False
        chained_begin, chained_end, chained_unwind = struct.unpack_from(
            "<III", data, tail)
        code = _section_for_span(sections, chained_begin,
                                 chained_end - chained_begin)
        if (not (0 < chained_begin < chained_end <= image_size)
                or code is None or not code.get("executable")
                or _raw_offset_for_rva(sections, chained_unwind, 4) is None):
            return False
    elif flags & 3:
        if tail + 4 > owner_end:
            return False
        handler_rva = struct.unpack_from("<I", data, tail)[0]
        handler = _section_for_span(sections, handler_rva)
        if handler is None or not handler.get("executable"):
            return False
    return True


def _runtime_function_starts(path: str, sections: Iterable[Dict[str, Any]],
                             machine: int, pointer_size: int, image_size: int,
                             exception_directory: Optional[Dict[str, Any]]) -> List[int]:
    """Extract validated AMD64 linker BeginAddress RVAs.

    Only records inside IMAGE_DIRECTORY_ENTRY_EXCEPTION are authoritative.
    Scanning all of a section named ``.pdata`` can mistake unrelated bytes or
    raw alignment padding for function boundaries.
    """
    if machine != 0x8664 or pointer_size != 8 or not exception_directory:
        return []
    sections = list(sections)
    directory_rva = int(exception_directory.get("rva", 0))
    directory_size = int(exception_directory.get("size", 0))
    if directory_rva <= 0 or directory_size < 12:
        return []
    table_offset = _raw_offset_for_rva(sections, directory_rva, directory_size)
    if table_offset is None:
        return []
    with open(path, "rb") as fh:
        data = fh.read()
    starts = set()
    for relative in range(0, directory_size - 11, 12):
        offset = table_offset + relative
        begin, end, unwind = struct.unpack_from("<III", data, offset)
        if not (0 < begin < end <= image_size and 0 < unwind < image_size):
            continue
        code = _section_for_span(sections, begin, end - begin)
        unwind_section = _section_for_span(sections, unwind, 4)
        unwind_offset = _raw_offset_for_rva(sections, unwind, 4)
        if (code is None or not code.get("executable")
                or unwind_section is None or unwind_section.get("executable")
                or unwind_offset is None
                or not _valid_unwind_info(data, unwind_offset, sections,
                                          image_size)):
            continue
        starts.add(begin)
    return sorted(starts)


def canonical_identity(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Return only stable equality fields from a full manifest."""
    return {key: manifest.get(key) for key in _IDENTITY_KEYS
            if manifest.get(key) is not None}


def manifest_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Compare two manifests and return ``(matches, human_readable_reasons)``.

    Only identity keys present in *expected* are compared.  A production
    artifact should always include ``sha256``; accepting partial expected
    manifests is useful for migration diagnostics and tests.
    """
    reasons = []
    for key in _IDENTITY_KEYS:
        if expected.get(key) is None:
            continue
        if actual.get(key) != expected.get(key):
            reasons.append("{}: expected {!r}, got {!r}".format(
                key, expected.get(key), actual.get(key)))
    return not reasons, reasons


def write_manifest(path: str, manifest: Dict[str, Any]) -> None:
    """Atomically write a manifest JSON file."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".identity-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def read_manifest(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError("manifest must be a JSON object: {}".format(path))
    return value


def artifact_is_fresh(source: str, artifact: str, sidecar: Optional[str] = None) -> bool:
    """True when *artifact* has a sidecar matching the exact current source.

    Mtime/size-only cache validation is intentionally not accepted.  The
    default sidecar path is ``artifact + '.identity.json'``.
    """
    if not os.path.isfile(source) or not os.path.isfile(artifact):
        return False
    sidecar = sidecar or artifact + ".identity.json"
    if not os.path.isfile(sidecar):
        return False
    try:
        payload = read_manifest(sidecar)
        expected = payload.get("source")
        expected_artifact = payload.get("artifact")
        metadata = payload.get("metadata")
        producer = metadata.get("producer") if isinstance(metadata, dict) else None
        if (not isinstance(expected, dict) or not expected.get("sha256")
                or not isinstance(expected_artifact, dict)
                or not expected_artifact.get("sha256")
                or expected_artifact.get("pointer_size") not in (4, 8)
                or not expected_artifact.get("image_base")
                or not expected_artifact.get("image_size")
                or not expected_artifact.get("sections")
                or not expected_artifact.get("anchors")
                or not isinstance(metadata, dict)
                or int(metadata.get("cache_policy", 0)) <= 0
                or not isinstance(producer, dict)
                or not producer.get("name")
                or not producer.get("sha256")
                or not isinstance(metadata.get("arguments"), list)):
            return False
        actual = inspect_pe(source)
        actual_artifact = inspect_pe(artifact)
        return (manifest_matches(expected, actual)[0]
                and manifest_matches(expected_artifact, actual_artifact)[0])
    except (OSError, ValueError, PEIdentityError, json.JSONDecodeError):
        return False


def make_artifact_sidecar(source: str, artifact: str, **metadata: Any) -> Dict[str, Any]:
    """Build the standard sidecar payload for a derived PE artifact.

    Both sides must be complete PEs.  A hash-only fallback would let a failed
    unpacker return arbitrary output on its first invocation even though the
    same sidecar would be rejected as stale on the next run.
    """
    artifact_manifest = inspect_pe(artifact)
    result = {
        "schema": SCHEMA_VERSION,
        "source": inspect_pe(source),
        "artifact": artifact_manifest,
    }
    if metadata:
        result["metadata"] = metadata
    return result


def _program_import_sha256(program) -> Optional[str]:
    try:
        value = program.getExecutableSHA256()
    except Exception:
        return None
    value = str(value or "").strip().lower()
    return value or None


def _is_sha256(value: Optional[str]) -> bool:
    if value is None or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value.lower())


def _program_executable_path(program) -> str:
    path = str(program.getExecutablePath() or "")
    # Ghidra commonly renders a Windows drive path as /C:/path.  Python's
    # Windows filesystem APIs interpret that as C:\C:\path, so canonicalize
    # only this unambiguous drive-prefix form before checking whether it exists.
    if (os.name == "nt" and len(path) >= 4 and path[0] == "/" and
            path[1].isalpha() and path[2] == ":" and path[3] in "/\\"):
        path = os.path.normpath(path[1:])
    return path


def _verify_loaded_program_layout(program, expected: Dict[str, Any],
                                  verify_anchors: bool,
                                  require_sections: bool = False) -> None:
    """Verify live Program layout, optionally including manifest anchor bytes."""
    try:
        pointer_size = int(expected["pointer_size"])
        image_base = int(expected["image_base"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PEIdentityError("allowed manifest has incomplete PE layout") from exc
    if int(program.getDefaultPointerSize()) != pointer_size:
        raise PEIdentityError("Program pointer width mismatch")
    base = program.getImageBase()
    if int(base.getOffset()) != image_base:
        raise PEIdentityError("Program image base mismatch")

    memory = program.getMemory()
    anchors = expected.get("anchors") or []
    if verify_anchors:
        if not anchors:
            raise PEIdentityError("Program identity requires memory anchors")
        for anchor in anchors:
            try:
                rva = int(anchor["rva"])
                wanted = bytes.fromhex(str(anchor["bytes"]).replace(" ", ""))
            except (KeyError, TypeError, ValueError) as exc:
                raise PEIdentityError("allowed manifest has an invalid memory anchor") from exc
            if not wanted:
                raise PEIdentityError("allowed manifest has an empty memory anchor")
            got = bytes(memory.getByte(base.add(rva + i)) & 0xFF
                        for i in range(len(wanted)))
            if got != wanted:
                raise PEIdentityError(
                    "Program memory anchor mismatch at RVA 0x{:X}".format(rva))

    verified_sections = 0
    for section in expected.get("sections", []):
        try:
            span = max(int(section.get("virtual_size", 0)),
                       int(section.get("raw_size", 0)))
        except (AttributeError, TypeError, ValueError) as exc:
            if require_sections:
                raise PEIdentityError(
                    "allowed manifest has an invalid section layout") from exc
            continue
        if span <= 0:
            continue
        try:
            rva = int(section["rva"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PEIdentityError(
                "allowed manifest has an invalid section layout") from exc
        first = base.add(rva)
        last = first.add(span - 1)
        if memory.getBlock(first) is None or memory.getBlock(last) is None:
            raise PEIdentityError(
                "Program section missing: {}".format(section.get("name", "")))
        verified_sections += 1
    if require_sections and verified_sections == 0:
        raise PEIdentityError("Program identity requires mapped PE sections")


def verify_ghidra_program(program, expected_manifests: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Verify a loaded Ghidra Program against exact PE manifests.

    This deliberately accepts a duck-typed Program so importing this module
    never requires Ghidra.  It protects standalone PyGhidra mutators from the
    stale-program case where the file at ``getExecutablePath()`` was replaced
    after the Program was imported.
    """
    manifests = list(expected_manifests)
    executable_path = _program_executable_path(program)
    stored_hash = _program_import_sha256(program)

    if executable_path and os.path.isfile(executable_path):
        # An extant path is authoritative.  Never fall back to import metadata
        # when that file was replaced or now identifies a different target.
        actual_file = inspect_pe(executable_path)
        expected = None
        reasons = []
        for candidate in manifests:
            matches, why = manifest_matches(candidate, actual_file)
            if matches:
                expected = candidate
                break
            reasons.extend(why)
        if expected is None:
            raise PEIdentityError(
                "backing executable mismatch: " + "; ".join(reasons[:8]))
        _verify_loaded_program_layout(
            program, expected, verify_anchors=not bool(stored_hash))
        if (stored_hash and
                stored_hash != str(expected.get("sha256") or "").lower()):
            raise PEIdentityError("Program import-time SHA-256 mismatch")
    else:
        if executable_path and os.path.lexists(executable_path):
            raise PEIdentityError(
                "backing executable exists but is not a regular file")
        # Ghidra projects can outlive a temporary import path.  In that narrow
        # case the loader-recorded SHA is the only acceptable manifest selector;
        # live anchors and mapped sections then independently attest its memory.
        if not _is_sha256(stored_hash):
            raise PEIdentityError(
                "missing backing executable requires an exact import-time SHA-256")
        matching = [candidate for candidate in manifests
                    if (_is_sha256(str(candidate.get("sha256") or "").lower()) and
                        str(candidate.get("sha256")).lower() == stored_hash)]
        if not matching:
            raise PEIdentityError(
                "missing backing executable import-time SHA-256 is not allowed")
        expected = matching[0]
        _verify_loaded_program_layout(
            program, expected, verify_anchors=True, require_sections=True)
    return expected
