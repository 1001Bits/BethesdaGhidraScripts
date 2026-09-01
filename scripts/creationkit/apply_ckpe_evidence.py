"""Ghidra driver: import exact-version CKPE relocation evidence.

This pass is deliberately annotation-only.  It creates neutral evidence
labels, plate comments, and bookmarks after exact target/source verification.
It never creates a function, changes a function name, calls ``setPrimary``, or
treats a detour callsite as a function entry.

Dry-run is the default.  Set ``BGS_CKPE_APPLY=go`` to apply annotations and
``BGS_CKPE_ROOT`` to the pinned Creation-Kit-Platform-Extended checkout.
Reports are written in both CSV and JSON form on every successful pass.
"""

from __future__ import annotations

import collections
import json
import os
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "core"))
for path in (SCRIPT_DIR, CORE_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import ckpe_evidence as evidence  # noqa: E402


def _windows_program_path(path):
    path = str(path or "")
    if (os.name == "nt" and len(path) >= 4 and path[0] == "/" and
            path[1].isalpha() and path[2] == ":" and path[3] in "/\\"):
        path = path[1:]
    return os.path.normpath(path)


def _find_ckpe_root():
    explicit = os.environ.get("BGS_CKPE_ROOT")
    candidates = []
    if explicit:
        candidates.append(explicit)
    repository = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
    candidates.extend([
        os.path.join(repository, "third_party", "Creation-Kit-Platform-Extended"),
        os.path.join(os.path.dirname(repository), "Creation-Kit-Platform-Extended"),
    ])
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return os.path.abspath(candidate)
    raise evidence.CKPEEvidenceError(
        "pinned CKPE checkout not found; set BGS_CKPE_ROOT or use the documented "
        "third_party/Creation-Kit-Platform-Extended location")


def _verify_target(program, lock):
    from binary_identity import (PEIdentityError, inspect_pe, manifest_matches,
                                 verify_ghidra_program)

    path = _windows_program_path(program.getExecutablePath())
    if not path or not os.path.isfile(path):
        raise evidence.CKPEEvidenceError(
            "CKPE evidence requires the exact imported CreationKit.exe backing file")
    actual = inspect_pe(path)
    expected = lock.get("target") or {}
    matches, reasons = manifest_matches(expected, actual)
    if not matches:
        raise evidence.CKPEEvidenceError(
            "Creation Kit target identity mismatch: " + "; ".join(reasons[:8]))
    if str(actual.get("version_string") or "") != str(expected.get("version_string") or ""):
        raise evidence.CKPEEvidenceError(
            "Creation Kit version mismatch: expected {}, got {}".format(
                expected.get("version_string"), actual.get("version_string")))
    try:
        verify_ghidra_program(program, [expected])
    except PEIdentityError as exc:
        raise evidence.CKPEEvidenceError(
            "loaded Ghidra Program identity mismatch: {}".format(exc)) from exc
    return actual


def _require_idle_analysis(program):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    manager = AutoAnalysisManager.getAnalysisManager(program)
    if manager.isAnalyzing():
        raise evidence.CKPEEvidenceError(
            "wait for Ghidra auto-analysis to finish before applying CKPE evidence")


def _reader(program, image_base):
    memory = program.getMemory()
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    def read(rva, size):
        address = address_space.getAddress(int(image_base) + int(rva))
        result = bytearray()
        for index in range(int(size)):
            current = address.add(index)
            if not memory.contains(current):
                raise ValueError("unmapped memory")
            result.append(memory.getByte(current) & 0xFF)
        return bytes(result)

    return read


def _java_symbols(iterator):
    if iterator is None:
        return
    if hasattr(iterator, "hasNext"):
        while iterator.hasNext():
            yield iterator.next()
    else:
        for value in iterator:
            yield value


def _same_address(left, right):
    try:
        left_space = left.getAddressSpace()
        right_space = right.getAddressSpace()
        try:
            same_space = bool(left_space.equals(right_space))
        except Exception:
            same_space = left_space == right_space
        return same_space and int(left.getOffset()) == int(right.getOffset())
    except Exception:
        return False


def _label_at(symbol_table, name, address):
    try:
        symbols = symbol_table.getSymbols(name)
    except Exception:
        return False
    for symbol in _java_symbols(symbols):
        try:
            if _same_address(symbol.getAddress(), address):
                return True
        except Exception:
            continue
    return False


def _unique_label(symbol_table, wanted, address, rva):
    candidate = wanted
    suffix = 0
    while True:
        try:
            symbols = list(_java_symbols(symbol_table.getSymbols(candidate)))
        except Exception:
            symbols = []
        if (not symbols or
                any(_same_address(symbol.getAddress(), address)
                    for symbol in symbols)):
            return candidate
        suffix += 1
        tail = "_rva_{:08X}".format(int(rva))
        if suffix > 1:
            tail += "_{}".format(suffix)
        candidate = wanted + tail


def _merge_plate_comment(listing, address, marker, note):
    from ghidra.program.model.listing import CodeUnit

    old = listing.getComment(CodeUnit.PLATE_COMMENT, address) or ""
    lines = [line for line in old.splitlines() if not line.startswith(marker)]
    lines.append(note)
    listing.setComment(address, CodeUnit.PLATE_COMMENT,
                       "\n".join(line for line in lines if line))


def _note(row, commit, profile):
    key = "{}:{}".format(row["database_file"], row["index"])
    marker = profile["marker_prefix"] + key + "]"
    roles = sorted(set(ref["role"] for ref in row.get("source_refs", [])))
    locations = sorted(set(
        "{}:{}".format(ref["source_file"], ref["source_line"])
        for ref in row.get("source_refs", [])))
    parts = [
        marker,
        "patch={!r}".format(row["patch_name"]),
        "RVA=0x{:X}".format(row["rva"]),
        "signature={}".format(row["signature_status"]),
        "CKPE={}".format(commit),
    ]
    if roles:
        parts.append("roles=" + ",".join(roles))
    if locations:
        parts.append("source=" + ",".join(locations))
    return marker, " ".join(parts)


def _plan_rows(program, target, patches, source_index, profile):
    image_base = int(target["image_base"])
    image_size = int(target["image_size"])
    memory = program.getMemory()
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    reader = _reader(program, image_base)
    rows = []
    for patch in patches:
        for database_row in patch["rows"]:
            rva = int(database_row["rva"])
            row = {
                "database_file": patch["file"],
                "database_line": database_row["database_line"],
                "patch_name": patch["patch_name"],
                "patch_version": patch["version"],
                "database_format": patch["format"],
                "index": database_row["index"],
                "rva": rva,
                "va": None,
                "memory_block": "",
                "executable": False,
                "declared_mask_length": database_row["declared_mask_length"],
                "signature_length_consistent": database_row[
                    "signature_length_consistent"],
                "signature": database_row["signature"],
                "signature_kind": "",
                "signature_anchor_rva": None,
                "signature_status": "not_checked",
                "source_refs": evidence.source_refs_for(
                    source_index, patch["patch_name"], database_row["index"]),
                "label": evidence.safe_label(
                    patch["file"], database_row["index"],
                    prefix=profile["label_prefix"]),
                "eligible": False,
                "action": "skipped",
            }
            if rva <= 0 or rva >= image_size:
                row["action"] = "skipped_invalid_rva"
                rows.append(row)
                continue
            address = address_space.getAddress(image_base + rva)
            block = memory.getBlock(address)
            if block is None or not memory.contains(address):
                row["action"] = "skipped_unmapped_rva"
                rows.append(row)
                continue
            row["va"] = int(address.getOffset())
            row["memory_block"] = str(block.getName())
            row["executable"] = bool(block.isExecute())
            checked = evidence.match_signature(reader, rva, row["signature"])
            row["signature_kind"] = checked["kind"]
            row["signature_status"] = checked["status"]
            row["signature_anchor_rva"] = checked["anchor_rva"]
            if not row["signature_length_consistent"]:
                row["action"] = "skipped_mask_length_mismatch"
            elif checked["status"] in ("mismatch", "unreadable", "unsupported"):
                row["action"] = "skipped_signature_" + checked["status"]
            else:
                row["eligible"] = True
                row["action"] = "would_apply"
            rows.append(row)
    return sorted(rows, key=lambda row: (
        row["database_file"].casefold(), row["index"], row["rva"]))


def _apply_rows(program, rows, commit, profile):
    from ghidra.program.model.symbol import SourceType

    memory = program.getMemory()
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    bookmarks = program.getBookmarkManager()
    by_address = collections.defaultdict(list)
    had_parent_transaction = program.getCurrentTransactionInfo() is not None
    transaction = program.startTransaction("BGS exact CKPE evidence")
    success = False
    try:
        for row in rows:
            if not row["eligible"]:
                continue
            address = address_space.getAddress(int(row["va"]))
            if not memory.contains(address):
                raise RuntimeError("eligible CKPE address became unmapped")
            entry_function = function_manager.getFunctionAt(address)
            function_name = (str(entry_function.getName())
                             if entry_function is not None else None)
            label = _unique_label(symbol_table, row["label"], address, row["rva"])
            row["label"] = label
            if _label_at(symbol_table, label, address):
                label_action = "label_present"
            elif entry_function is not None:
                # Ghidra may implicitly make a newly-created label at a
                # function entry primary, which renames the function even
                # though createLabel() was used rather than setName().  Keep
                # the recovered function symbol untouched; the plate comment
                # and bookmark still retain the complete CKPE provenance.
                label_action = "label_skipped_function_entry"
            else:
                created = symbol_table.createLabel(address, label, SourceType.IMPORTED)
                if created is None or not _same_address(created.getAddress(), address):
                    raise RuntimeError("Ghidra did not create CKPE evidence label " + label)
                label_action = "label_created"
            if (entry_function is not None and
                    str(entry_function.getName()) != function_name):
                raise RuntimeError(
                    "CKPE evidence label unexpectedly changed a function name")
            marker, note = _note(row, commit, profile)
            _merge_plate_comment(listing, address, marker, note)
            by_address[int(row["va"])].append((row, note))
            row["action"] = "applied_" + label_action

        for offset in sorted(by_address):
            address = address_space.getAddress(offset)
            notes = sorted(note for _row, note in by_address[offset])
            bookmarks.setBookmark(address, "Analysis", profile["bookmark_type"],
                                  " | ".join(notes))
        success = True
    finally:
        committed = bool(program.endTransaction(transaction, success))
        if success and not had_parent_transaction and not committed:
            raise RuntimeError("CKPE evidence transaction did not commit")


def run(program=None, lock_path=None):
    program = program or currentProgram  # noqa: F821
    lock_path = lock_path or os.environ.get("BGS_CKPE_LOCK") or os.path.join(
        SCRIPT_DIR, "refs", "ckpe_sse_1_6_1378_1.lock.json")
    lock = evidence.read_lock(lock_path)
    profile = evidence.annotation_profile(lock)
    target = _verify_target(program, lock)
    ckpe_root = _find_ckpe_root()
    checkout = evidence.verify_ckpe_checkout(ckpe_root, lock)
    patches = evidence.parse_relb_directory(checkout["database_dir"])
    source_index = evidence.build_source_index(checkout["cpp_paths"], ckpe_root)
    rows = _plan_rows(program, target, patches, source_index, profile)

    apply = os.environ.get("BGS_CKPE_APPLY", "dry").casefold() == "go"
    if apply:
        _require_idle_analysis(program)
        _apply_rows(program, rows, lock["source"]["commit"], profile)

    summary = dict(collections.Counter(row["action"] for row in rows))
    report = {
        "schema": evidence.REPORT_SCHEMA,
        "mode": "apply" if apply else "dry-run",
        "target": {
            key: target.get(key) for key in (
                "file_name", "file_size", "file_version", "version_string",
                "sha256", "machine", "pointer_size", "image_base", "image_size")
        },
        "source": {
            "repository": lock["source"]["repository"],
            "commit": lock["source"]["commit"],
            "database_sha256": checkout["database_sha256"],
            "patch_sources_sha256": checkout["patch_sources_sha256"],
        },
        "annotation_profile": profile,
        "policy": {
            "annotations_only": True,
            "creates_functions": False,
            "renames_functions": False,
            "calls_set_primary": False,
            "skips_new_labels_at_function_entries": True,
            "signature_mismatch_is_rejected": True,
        },
        "summary": {
            "database_files": len(patches),
            "rows": len(rows),
            "eligible": sum(1 for row in rows if row["eligible"]),
            "with_direct_source_use": sum(
                1 for row in rows if row.get("source_refs")),
            "actions": summary,
        },
        "rows": rows,
    }
    output_dir = os.environ.get("BGS_CKPE_REPORT_DIR") or os.path.join(
        SCRIPT_DIR, "refs", "generated")
    stem = profile["report_stem"] + "_" + str(target["sha256"])[:12]
    json_path, csv_path = evidence.write_reports(report, output_dir, stem)
    print("ckpe-evidence ({}): files={} rows={} eligible={} source-linked={}".format(
        "APPLIED" if apply else "DRY-RUN", len(patches), len(rows),
        report["summary"]["eligible"],
        report["summary"]["with_direct_source_use"]))
    print("  target sha256=" + str(target["sha256"]))
    print("  CKPE commit=" + lock["source"]["commit"])
    print("  report=" + json_path)
    print("  csv=" + csv_path)
    if not apply:
        print("  set BGS_CKPE_APPLY=go to add labels/comments/bookmarks")
    return report


if "currentProgram" in globals():
    run()
