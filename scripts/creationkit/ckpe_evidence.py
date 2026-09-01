"""Pure-Python parsing and reporting for exact-version CKPE evidence.

The Ghidra-facing driver lives in :mod:`apply_ckpe_evidence`.  Keeping the
database and C++ source parsing here makes the safety-critical parts testable
without importing Ghidra.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import os
import re
import tempfile


LOCK_SCHEMA = "bgs-ckpe-evidence-lock-v1"
REPORT_SCHEMA = "bgs-ckpe-evidence-report-v1"

_HEX_RVA = re.compile(r"^[0-9A-Fa-f]+$")
_MASK = re.compile(r"^(?:[0-9A-Fa-f]{2}|\?\?)+$")
_MASK_PREFIX = re.compile(r"^v\d+(?:_s\d+)?_(.*)$", re.IGNORECASE)
_MASK_OFFSET = re.compile(r"^(.*)-([0-9A-Fa-f]+)$")
_STRING_MASK = re.compile(r'^str_("(?:\\.|[^"\\])*")$')
_SET_NAME = re.compile(
    r"\bSetName\s*\(\s*(\"(?:\\.|[^\"\\])*\")\s*\)", re.DOTALL)
_DIRECT_OFFSET = re.compile(
    r"__CKPE_OFFSET\s*\(\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)")
_VERSION_STRING = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$")
_LABEL_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CKPEEvidenceError(ValueError):
    """Raised when CKPE inputs are missing, changed, or malformed."""


def _read_text(path):
    with open(path, "r", encoding="utf-8-sig", newline=None) as handle:
        return handle.read()


def _canonical_bytes(path):
    with open(path, "rb") as handle:
        value = handle.read()
    if value.startswith(b"\xef\xbb\xbf"):
        value = value[3:]
    return value.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def canonical_tree_sha256(root, paths):
    """Hash relative names and newline-normalised content deterministically."""
    root = os.path.abspath(root)
    normalised = sorted(
        (os.path.abspath(path) for path in paths),
        key=lambda path: os.path.relpath(path, root).replace(os.sep, "/"),
    )
    digest = hashlib.sha256()
    for path in normalised:
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        if relative == ".." or relative.startswith("../"):
            raise CKPEEvidenceError("tree member escapes CKPE root: " + path)
        blob = _canonical_bytes(path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
    return digest.hexdigest()


def read_lock(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CKPEEvidenceError("cannot read CKPE evidence lock: " + path) from exc
    if not isinstance(value, dict) or value.get("schema") != LOCK_SCHEMA:
        raise CKPEEvidenceError("unsupported CKPE evidence lock: " + path)
    return value


def annotation_profile(lock):
    """Derive collision-free annotation names from a verified source lock.

    The profile is deliberately derived instead of accepted as free-form lock
    input.  This prevents an otherwise valid evidence lock from injecting
    arbitrary label, bookmark, or report names.  Skyrim keeps its original
    namespace for idempotence with reports produced before Fallout 4 support.
    """
    if not isinstance(lock, dict):
        raise CKPEEvidenceError("CKPE evidence lock must be an object")
    target = lock.get("target") or {}
    source = lock.get("source") or {}
    database = source.get("database") or {}
    version = str(target.get("version_string") or "")
    if not _VERSION_STRING.fullmatch(version):
        raise CKPEEvidenceError(
            "CKPE evidence lock has an invalid target version string")

    database_path = str(database.get("path") or "").replace("\\", "/")
    parts = [part for part in database_path.split("/") if part]
    try:
        database_index = [part.casefold() for part in parts].index("database")
        family = parts[database_index + 1].upper()
    except (ValueError, IndexError):
        raise CKPEEvidenceError(
            "CKPE evidence lock has an unrecognised database path")
    if family not in ("SSE", "FO4"):
        raise CKPEEvidenceError(
            "unsupported Creation Kit evidence family: " + family)

    version_token = version.replace(".", "_")
    if family == "SSE":
        # Preserve the original Skyrim namespace and marker so reapplying the
        # parameterised importer updates, rather than duplicates, old notes.
        label_prefix = "CKPE_" + version_token
        marker_prefix = "[BGS:ckpe:{}:".format(version)
        bookmark_type = "BGS CKPE " + version
        report_stem = "ckpe_sse_" + version_token
        display_name = "Skyrim Creation Kit"
    else:
        label_prefix = "CKPE_FO4_" + version_token
        marker_prefix = "[BGS:ckpe:fo4:{}:".format(version)
        bookmark_type = "BGS CKPE FO4 " + version
        report_stem = "ckpe_fo4_" + version_token
        display_name = "Fallout 4 Creation Kit"
    if not _LABEL_PREFIX.fullmatch(label_prefix):
        raise CKPEEvidenceError("derived CKPE label prefix is invalid")
    return {
        "family": family,
        "version": version,
        "display_name": display_name,
        "label_prefix": label_prefix,
        "marker_prefix": marker_prefix,
        "bookmark_type": bookmark_type,
        "report_stem": report_stem,
    }


def verify_ckpe_checkout(root, lock):
    """Verify the exact relocation database and patch-source snapshots."""
    root = os.path.abspath(root)
    source = lock.get("source") or {}
    database = source.get("database") or {}
    patches = source.get("patch_sources") or {}
    database_dir = os.path.join(root, *str(database.get("path") or "").split("/"))
    patches_dir = os.path.join(root, *str(patches.get("path") or "").split("/"))
    if not os.path.isdir(database_dir):
        raise CKPEEvidenceError("missing pinned CKPE database directory: " + database_dir)
    if not os.path.isdir(patches_dir):
        raise CKPEEvidenceError("missing pinned CKPE patch-source directory: " + patches_dir)

    relb_paths = sorted(
        (os.path.join(database_dir, name) for name in os.listdir(database_dir)
         if name.lower().endswith(".relb")),
        key=lambda path: os.path.basename(path).casefold(),
    )
    cpp_paths = sorted(
        (os.path.join(patches_dir, name) for name in os.listdir(patches_dir)
         if name.lower().endswith(".cpp")),
        key=lambda path: os.path.basename(path).casefold(),
    )
    expected_relb_count = int(database.get("file_count", -1))
    expected_cpp_count = int(patches.get("file_count", -1))
    if len(relb_paths) != expected_relb_count:
        raise CKPEEvidenceError(
            "CKPE relocation database file count changed: expected {}, got {}".format(
                expected_relb_count, len(relb_paths)))
    if len(cpp_paths) != expected_cpp_count:
        raise CKPEEvidenceError(
            "CKPE patch-source file count changed: expected {}, got {}".format(
                expected_cpp_count, len(cpp_paths)))

    actual_database_hash = canonical_tree_sha256(root, relb_paths)
    actual_source_hash = canonical_tree_sha256(root, cpp_paths)
    if actual_database_hash != str(database.get("canonical_tree_sha256") or "").lower():
        raise CKPEEvidenceError(
            "CKPE relocation database content does not match pinned commit")
    if actual_source_hash != str(patches.get("canonical_tree_sha256") or "").lower():
        raise CKPEEvidenceError(
            "CKPE patch-source content does not match pinned commit")
    return {
        "root": root,
        "database_dir": database_dir,
        "patches_dir": patches_dir,
        "relb_paths": relb_paths,
        "cpp_paths": cpp_paths,
        "database_sha256": actual_database_hash,
        "patch_sources_sha256": actual_source_hash,
    }


def _parse_extended_row(line, path, line_number):
    parts = line.strip().split(None, 2)
    if len(parts) != 3 or not _HEX_RVA.fullmatch(parts[0]):
        raise CKPEEvidenceError(
            "malformed extended relocation row {}:{}".format(path, line_number))
    try:
        declared_length = int(parts[1], 10)
    except ValueError as exc:
        raise CKPEEvidenceError(
            "invalid mask length {}:{}".format(path, line_number)) from exc
    if declared_length < 0:
        raise CKPEEvidenceError(
            "negative mask length {}:{}".format(path, line_number))
    signature = parts[2].strip()
    if not signature:
        raise CKPEEvidenceError(
            "empty signature {}:{}".format(path, line_number))
    # CKPE's text loader reads this field but does not enforce it.  Preserve a
    # discrepancy as row evidence instead of silently repairing the database.
    length_consistent = (
        signature == "<nope>" or declared_length == 0 or
        declared_length == len(signature)
    )
    return int(parts[0], 16), declared_length, signature, length_consistent


def parse_relb_file(path):
    """Parse CKPE's plain or ``extended`` development database format."""
    text = _read_text(path)
    lines = text.splitlines()
    if len(lines) < 3:
        raise CKPEEvidenceError("truncated relocation database: " + path)
    patch_name = lines[0].strip()
    if not patch_name:
        raise CKPEEvidenceError("empty patch name: " + path)
    try:
        version = int(lines[1].strip(), 10)
    except ValueError as exc:
        raise CKPEEvidenceError("invalid patch version: " + path) from exc
    extended = lines[2].strip().casefold() == "extended"
    first_row = 3 if extended else 2
    rows = []
    for zero_index, raw_line in enumerate(lines[first_row:]):
        line_number = first_row + zero_index + 1
        if not raw_line.strip():
            continue
        if extended:
            rva, declared, signature, length_consistent = _parse_extended_row(
                raw_line, path, line_number)
        else:
            token = raw_line.strip().split(None, 1)[0]
            if not _HEX_RVA.fullmatch(token):
                raise CKPEEvidenceError(
                    "malformed plain relocation row {}:{}".format(path, line_number))
            rva = int(token, 16)
            declared = None
            signature = "<nope>"
            length_consistent = True
        rows.append({
            "index": len(rows),
            "rva": rva,
            "declared_mask_length": declared,
            "signature": signature,
            "signature_length_consistent": length_consistent,
            "database_line": line_number,
        })
    if not rows:
        raise CKPEEvidenceError("relocation database has no rows: " + path)
    return {
        "file": os.path.basename(path),
        "patch_name": patch_name,
        "version": version,
        "format": "extended" if extended else "plain",
        "rows": rows,
    }


def parse_relb_directory(database_dir):
    paths = sorted(
        (os.path.join(database_dir, name) for name in os.listdir(database_dir)
         if name.lower().endswith(".relb")),
        key=lambda path: os.path.basename(path).casefold(),
    )
    patches = [parse_relb_file(path) for path in paths]
    names = set()
    for patch in patches:
        folded = patch["patch_name"].casefold()
        if folded in names:
            raise CKPEEvidenceError(
                "duplicate CKPE patch name: " + patch["patch_name"])
        names.add(folded)
    return patches


def parse_signature(raw):
    """Return a conservative description of a CKPE signature expression."""
    raw = str(raw or "").strip()
    if raw == "<nope>":
        return {"kind": "absent", "pattern": None, "anchor_delta": 0}
    string_match = _STRING_MASK.fullmatch(raw)
    if string_match:
        try:
            text = ast.literal_eval(string_match.group(1))
            pattern = text.encode("utf-8")
        except (SyntaxError, ValueError, UnicodeError):
            return {"kind": "unsupported", "pattern": None, "anchor_delta": 0}
        # CKPE's ``str_`` syntax is a search/xref recipe, not an assertion that
        # the string bytes begin at EntryDB.Rva.  Retain it in the report, but
        # do not pretend that a global string occurrence proves the RVA.
        return {
            "kind": "string_anchor",
            "pattern": [(byte, 0xFF) for byte in pattern],
            "anchor_delta": 0,
        }

    value = raw
    prefix = _MASK_PREFIX.fullmatch(value)
    if prefix:
        value = prefix.group(1)
    anchor_delta = 0
    offset = _MASK_OFFSET.fullmatch(value)
    if offset:
        value = offset.group(1)
        anchor_delta = int(offset.group(2), 16)
    if not value or len(value) % 2 or not _MASK.fullmatch(value):
        return {"kind": "unsupported", "pattern": None, "anchor_delta": 0}
    pattern = []
    for index in range(0, len(value), 2):
        pair = value[index:index + 2]
        pattern.append((0, 0) if pair == "??" else (int(pair, 16), 0xFF))
    return {"kind": "mask", "pattern": pattern, "anchor_delta": anchor_delta}


def match_signature(reader, rva, signature):
    """Validate a parsed signature with ``reader(rva, size) -> bytes``."""
    parsed = parse_signature(signature)
    kind = parsed["kind"]
    if kind == "absent":
        return {"kind": kind, "status": "absent", "anchor_rva": rva}
    if kind in ("unsupported", "string_anchor"):
        return {"kind": kind, "status": "unsupported", "anchor_rva": rva}
    anchor_rva = int(rva) + int(parsed["anchor_delta"])
    pattern = parsed["pattern"]
    try:
        actual = reader(anchor_rva, len(pattern))
    except Exception:
        return {"kind": kind, "status": "unreadable", "anchor_rva": anchor_rva}
    actual = bytes(actual)
    if len(actual) != len(pattern):
        return {"kind": kind, "status": "unreadable", "anchor_rva": anchor_rva}
    matched = all((got & mask) == (wanted & mask)
                  for got, (wanted, mask) in zip(actual, pattern))
    return {
        "kind": kind,
        "status": "matched" if matched else "mismatch",
        "anchor_rva": anchor_rva,
    }


def _cpp_string(literal):
    try:
        value = ast.literal_eval(literal)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _statement_context(text, start, end):
    previous = max(text.rfind(";", 0, start), text.rfind("{", 0, start),
                   text.rfind("}", 0, start), start - 240)
    following = text.find(";", end)
    if following < 0 or following > end + 360:
        following = min(len(text), end + 240)
    else:
        following += 1
    return " ".join(text[previous + 1:following].split())[:480]


def classify_source_use(context):
    folded = context.casefold()
    if ("detours::detourcall" in folded or
            "detours::detourclasscall" in folded):
        return "detour_callsite"
    if ("detours::detourjump" in folded or
            "detours::detourclassjump" in folded):
        return "detour_or_entry_patch_site"
    if "detours::detourclassvtable" in folded:
        return "vtable_patch_site"
    if ("safewrite::" in folded or ".write(" in folded or
            ".writenop(" in folded):
        return "byte_patch_site"
    if "=" in context:
        return "bound_address"
    return "source_reference"


def parse_patch_source(path, ckpe_root):
    text = _read_text(path)
    names = []
    for match in _SET_NAME.finditer(text):
        value = _cpp_string(match.group(1))
        if value is not None:
            names.append(value)
    names = sorted(set(names), key=str.casefold)
    relative = os.path.relpath(path, ckpe_root).replace(os.sep, "/")
    uses = {}
    for match in _DIRECT_OFFSET.finditer(text):
        token = match.group(1)
        index = int(token, 0)
        line = text.count("\n", 0, match.start()) + 1
        context = _statement_context(text, match.start(), match.end())
        uses.setdefault(index, []).append({
            "source_file": relative,
            "source_line": line,
            "role": classify_source_use(context),
            "context": context,
        })
    for refs in uses.values():
        refs.sort(key=lambda row: (row["source_file"], row["source_line"],
                                   row["role"], row["context"]))
    return {"patch_names": names, "uses": uses, "source_file": relative}


def build_source_index(cpp_paths, ckpe_root):
    by_name = {}
    for path in sorted(cpp_paths, key=lambda value: os.path.basename(value).casefold()):
        parsed = parse_patch_source(path, ckpe_root)
        for name in parsed["patch_names"]:
            by_name.setdefault(name.casefold(), []).append(parsed)
    for sources in by_name.values():
        sources.sort(key=lambda source: source["source_file"])
    return by_name


def source_refs_for(source_index, patch_name, index):
    refs = []
    for source in source_index.get(patch_name.casefold(), []):
        refs.extend(source["uses"].get(index, []))
    return sorted(refs, key=lambda row: (
        row["source_file"], row["source_line"], row["role"], row["context"]))


def safe_label(database_file, index, prefix="CKPE_1_6_1378_1"):
    if not _LABEL_PREFIX.fullmatch(str(prefix or "")):
        raise CKPEEvidenceError("invalid CKPE evidence label prefix")
    stem = os.path.splitext(os.path.basename(database_file))[0]
    stem = re.sub(r"[^A-Za-z0-9_]", "_", stem)
    stem = re.sub(r"_+", "_", stem).strip("_") or "patch"
    return "{}_{}_{:03d}".format(prefix, stem, int(index))


def _atomic_write(path, writer):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ckpe-evidence-", suffix=".tmp",
                                     dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(report, output_dir, stem):
    """Write deterministic JSON and CSV views of one evidence pass."""
    output_dir = os.path.abspath(output_dir)
    json_path = os.path.join(output_dir, stem + ".json")
    csv_path = os.path.join(output_dir, stem + ".csv")

    def write_json(handle):
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    fields = [
        "database_file", "database_line", "patch_name", "patch_version",
        "index", "rva", "va", "memory_block", "executable",
        "signature", "signature_kind", "signature_anchor_rva",
        "signature_status", "source_refs", "label", "eligible", "action",
    ]

    def write_csv(handle):
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore",
                                lineterminator="\n")
        writer.writeheader()
        for row in report["rows"]:
            value = dict(row)
            value["rva"] = "0x{:X}".format(int(row["rva"]))
            value["va"] = ("0x{:X}".format(int(row["va"]))
                           if row.get("va") is not None else "")
            value["signature_anchor_rva"] = (
                "0x{:X}".format(int(row["signature_anchor_rva"]))
                if row.get("signature_anchor_rva") is not None else "")
            value["source_refs"] = " | ".join(
                "{}:{}:{}:{}".format(ref["source_file"], ref["source_line"],
                                      ref["role"], ref["context"])
                for ref in row.get("source_refs", []))
            writer.writerow(value)

    _atomic_write(json_path, write_json)
    _atomic_write(csv_path, write_csv)
    return json_path, csv_path
