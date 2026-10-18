#!/usr/bin/env python3
r"""Port function names between Skyrim builds by shared address-library ID.

Skyrim AE 1.6.640, 1.6.1170 and 1.7.104 share ONE address-library ID
namespace (SE/VR are a different one -- never cross it): the same ID denotes
the same function in each build, so a name known in one build belongs at the
target build's address for that ID.  Unlike ``commonlibf4/port_names_by_id.py``
this port also demands byte evidence and reciprocal uniqueness:

* the (source, target) pair must be in one shared-ID group
  (``port_names_by_id.shared_namespace``);
* the source address must map to exactly one ID (ambiguous reverse mappings are
  dropped), and every target address may receive at most one name;
* the target address must already be an analyzed function entry whose name is
  still a DEFAULT placeholder -- nothing is created and no real name replaced;
* the first 32 bytes of source and target function, with rel32 and RIP-relative
  operands masked, must be identical (``byte-confirmed``).  Rows where the
  bytes differ are reported as ``byte-mismatch`` and never applied: that is
  where an address-library entry points at a different function;
* vtable-slot placeholders (``X::FuncN``, ``X::Unk_XX``) are not ported.

``--create-missing`` also creates the function when the target build has none
at that address -- typically MSVC ``Unwind@`` exception funclets and leaf
functions, which have no ``.pdata`` entry and which Ghidra's analysis of the
target did not find.  The same evidence is required (shared ID, unique
mapping, masked bytes identical over at least 16 bytes, or 8 for an
``Unwind@`` funclet whose name only records its own address) plus: the
address lies in an executable block, is not inside any existing function, and
is not inside another function's ``.pdata`` range.

Names are applied with source ANALYSIS, so any later exact source (CommonLib,
PDB, analyst) still outranks them.  Dry-run is the default.

Both programs must BE the builds named by ``--source-build``/``--target-build``:
each program's executable SHA-256 is checked against the pinned SHA-256 of that
build (``BUILD_SHA256``), and ``--create-missing`` reads ``.pdata`` only from an
executable with the pinned target SHA-256.  Every run writes a NEW timestamped
evidence CSV under ``build/evidence/`` (never overwritten) with the mode, the
planned decision and -- for ``--apply`` -- the actual result of every row.

Usage (Ghidra GUI closed)::

    python scripts/commonlibsse/port_ae_family_by_id.py \
        --source-build ae --source-program /Skyrim/SkyrimAE_1_6_1170.exe \
        --target-build 17104 --target-program /Skyrim/SkyrimAE_1_7_104.exe [--apply]
"""
from __future__ import annotations

import argparse
import collections
import csv
import importlib.util
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "core"))
sys.path.insert(0, str(HERE))
from address_library import AddressLibrary, unique_reverse_ids  # noqa: E402
from ghidra_project import (find_program, open_program,  # noqa: E402
                            open_user_project)
from pyghidra_result import end_outer_transaction  # noqa: E402

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO / "tools" / "ghidra"))
# Both Skyrim groups are supported; a pair is refused unless it lies inside
# ONE group ({se, vr} or {ae, 16640, 17104}).
DBS = {"ae": "ae_db", "16640": "db_16640", "17104": "db_17104",
       "se": "se_db", "vr": "vr_db"}
# Exact executable SHA-256 of each build (the program import hash; the same
# pins as commonlibf4/bytesig_port_pdb_to_targets.TARGETS).  A program is used
# as a build only when its own SHA-256 is that build's pin.
BUILD_SHA256 = {
    "se": "5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12",
    "vr": "8d839e3de9aaf59d4bac94887611d6ac7199c3b601e9e8ff8d567648fc452c9f",
    "ae": "80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4",
    "16640": "d3c4f588b942e73a54240497886e35f094a3641ed2a7173332100eaf1c90ea60",
    "17104": "846efccf0c1374d71f892907f46549560f2fcb0a75cb87a3eed438baa0f1402f",
}
DEFAULT_EVIDENCE_DIR = REPO / "build" / "evidence"
EVIDENCE_FIELDS = ["name", "source_rva", "id", "target_rva", "decision",
                   "target_name_before", "mode", "result"]
PLACEHOLDER_RE = re.compile(r"^(?:FUN_|sub_|thunk_FUN_|thunk_sub_)[0-9A-Fa-f]+$")
SLOT_PLACEHOLDER_RE = re.compile(r"(?:^|::)(?:Func\d+(?:_v\d+)?|Unk_[0-9A-Fa-f]+)$")
WINDOW = 32
MIN_CREATE_BYTES = 16          # a created, named function needs this much evidence
MIN_FUNCLET_BYTES = 8          # an Unwind@ funclet's name only records its address
_EMBEDDED_ADDRESS = re.compile(r"^(.*?)([_@])(14[0-9A-Fa-f]{7})$")


def retarget_local_name(local_name, target_va):
    """``sub_1408E7530`` / ``Unwind@1415c4354`` name the SOURCE build's
    address; on the target that number would point elsewhere.  Keep the
    stem, substitute the target address (same letter case)."""
    match = _EMBEDDED_ADDRESS.match(local_name)
    if not match:
        return local_name
    digits = "{:X}".format(target_va)
    if match.group(3) != match.group(3).upper():
        digits = digits.lower()
    return match.group(1) + match.group(2) + digits


def _shared_namespace(source, target):
    spec = importlib.util.spec_from_file_location(
        "f4_port_names_by_id", REPO / "scripts" / "commonlibf4" / "port_names_by_id.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.shared_namespace("skyrim", source, target)


def masked_window(text, offset, size):
    """(signature, mask) of the first min(size, WINDOW) bytes, operands masked."""
    from bytesig_port import compute_masked_sig
    length = max(0, min(WINDOW, int(size)))
    if length < 8 or offset < 0 or offset + length > len(text):
        return None
    sig, mask = compute_masked_sig(text, offset, window=length)
    return bytes(sig), bytes(mask)


def bytes_agree(source, target):
    if source is None or target is None or len(source[0]) != len(target[0]):
        return False
    return all(ms == 0 or mt == 0 or bs == bt
               for bs, ms, bt, mt in zip(source[0], source[1], target[0], target[1]))


def _text_block(program):
    """(rva, bytes) of the program's executable ``.text`` block."""
    import jpype
    base = program.getImageBase().getOffset()
    for block in program.getMemory().getBlocks():
        if block.isExecute() and block.isInitialized() and \
                str(block.getName()) == ".text":
            size = int(block.getSize())
            buffer = jpype.JArray(jpype.JByte)(size)
            block.getBytes(block.getStart(), buffer)
            return block.getStart().getOffset() - base, bytes(buffer)
    raise RuntimeError("{} has no .text block".format(program.getName()))


def _function_sizes(program):
    base = program.getImageBase().getOffset()
    out = {}
    for function in program.getFunctionManager().getFunctions(True):
        body = function.getBody()
        entry = function.getEntryPoint()
        # contiguous bytes from the entry only
        size = 0
        for rng in body.getAddressRanges():
            if rng.contains(entry):
                size = int(rng.getMaxAddress().subtract(entry)) + 1
                break
        out[entry.getOffset() - base] = (function, size)
    return out


def collect_source(program):
    """{rva: (qualified, local, namespace parts, size)} of meaningful names."""
    from ghidra.program.model.symbol import SourceType
    out = {}
    stats = collections.Counter()
    for rva, (function, size) in _function_sizes(program).items():
        symbol = function.getSymbol()
        name = str(symbol.getName())
        if symbol.getSource() == SourceType.DEFAULT or PLACEHOLDER_RE.match(name):
            stats["placeholder"] += 1
            continue
        qualified = str(function.getName(True))
        if SLOT_PLACEHOLDER_RE.search(qualified):
            stats["slot-placeholder"] += 1
            continue
        parts = []
        namespace = symbol.getParentNamespace()
        while namespace is not None and not namespace.isGlobal():
            parts.insert(0, str(namespace.getName()))
            namespace = namespace.getParentNamespace()
        out[rva] = (qualified, name, tuple(parts), size)
    stats["named"] = len(out)
    return out, stats


def _inside_unwind_range(unwind_ranges, starts, rva):
    import bisect
    index = bisect.bisect_right(starts, rva) - 1
    return index >= 0 and unwind_ranges[index][0] < rva < unwind_ranges[index][1]


def plan(source_names, source_text, target_program, target_text,
         source_db, target_db, create_missing=False, unwind_ranges=()):
    from ghidra.program.model.symbol import SourceType
    reverse, ambiguous = unique_reverse_ids(source_db)
    target_functions = _function_sizes(target_program)
    source_rva0, source_bytes = source_text
    target_rva0, target_bytes = target_text
    unwind_ranges = sorted(unwind_ranges)
    starts = [begin for begin, _end in unwind_ranges]
    rows = []
    claims = collections.defaultdict(list)
    for rva, (qualified, local, parts, size) in source_names.items():
        ident = reverse.get(rva)
        if ident is None:
            rows.append((qualified, rva, None, None, "no-unique-id", ""))
            continue
        target_rva = target_db.get(ident)
        if target_rva is None:
            rows.append((qualified, rva, ident, None, "id-absent-in-target", ""))
            continue
        claims[target_rva].append((qualified, local, parts, rva, ident, size))
    for target_rva, claimants in claims.items():
        if len(claimants) != 1:
            for qualified, _l, _p, rva, ident, _s in claimants:
                rows.append((qualified, rva, ident, target_rva, "target-claimed-twice", ""))
            continue
        qualified, local, parts, rva, ident, size = claimants[0]
        entry = target_functions.get(target_rva)
        if entry is None:
            rows.append(_plan_create(
                target_program, target_bytes, target_rva0, source_bytes,
                source_rva0, unwind_ranges, starts, create_missing,
                qualified, local, parts, rva, ident, target_rva, size))
            continue
        function, target_size = entry
        current = str(function.getName(True))
        symbol = function.getSymbol()
        if current == qualified:
            rows.append((qualified, rva, ident, target_rva, "already-named-same", current))
            continue
        if symbol.getSource() != SourceType.DEFAULT and not PLACEHOLDER_RE.match(
                str(symbol.getName())):
            rows.append((qualified, rva, ident, target_rva, "target-already-named", current))
            continue
        source_sig = masked_window(source_bytes, rva - source_rva0, size)
        target_sig = masked_window(target_bytes, target_rva - target_rva0,
                                   min(size, target_size))
        if not bytes_agree(source_sig, target_sig):
            rows.append((qualified, rva, ident, target_rva,
                         "byte-mismatch" if source_sig and target_sig else "too-small",
                         current))
            continue
        target_va = target_program.getImageBase().getOffset() + target_rva
        local = retarget_local_name(local, target_va)
        qualified = "::".join(parts + (local,))
        rows.append((qualified, rva, ident, target_rva, "apply", current,
                     local, parts, function))
    return rows


def _plan_create(program, target_bytes, target_rva0, source_bytes, source_rva0,
                 unwind_ranges, starts, create_missing, qualified, local, parts,
                 rva, ident, target_rva, size):
    if not create_missing:
        return (qualified, rva, ident, target_rva, "no-target-function", "")
    address = program.getImageBase().add(target_rva)
    block = program.getMemory().getBlock(address)
    if block is None or not block.isExecute() or not block.isInitialized():
        return (qualified, rva, ident, target_rva, "missing-not-executable", "")
    containing = program.getFunctionManager().getFunctionContaining(address)
    if containing is not None:
        return (qualified, rva, ident, target_rva, "missing-inside-function",
                str(containing.getName(True)))
    if _inside_unwind_range(unwind_ranges, starts, target_rva):
        return (qualified, rva, ident, target_rva, "missing-inside-unwind-range", "")
    funclet = local.startswith("Unwind@")
    length = min(size, WINDOW)
    if length < (MIN_FUNCLET_BYTES if funclet else MIN_CREATE_BYTES):
        return (qualified, rva, ident, target_rva, "missing-too-small", "")
    source_sig = masked_window(source_bytes, rva - source_rva0, length)
    target_sig = masked_window(target_bytes, target_rva - target_rva0, length)
    if not bytes_agree(source_sig, target_sig):
        return (qualified, rva, ident, target_rva, "missing-byte-mismatch", "")
    local = retarget_local_name(local, program.getImageBase().getOffset() + target_rva)
    return ("::".join(parts + (local,)), rva, ident, target_rva, "create", "",
            local, parts, address)


def apply_rows(program, rows, monitor=None, results=None):
    """Apply ``apply``/``create`` rows.  ``results`` (optional dict) receives
    the ACTUAL outcome per row index -- not the planned decision."""
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.symbol import SourceType
    table = program.getSymbolTable()
    functions = program.getFunctionManager()
    listing = program.getListing()
    done = failed = created = skipped_now_inside = 0
    errors = []
    results = {} if results is None else results
    for index, row in sorted(enumerate(rows),
                             key=lambda item: (item[1][4] != "apply", item[1][3] or 0)):
        if row[4] not in ("apply", "create"):
            continue
        local, parts = row[6], row[7]
        outcome = "renamed"
        if row[4] == "create":
            address = row[8]
            # An earlier creation in this run may have absorbed the address.
            if functions.getFunctionContaining(address) is not None:
                skipped_now_inside += 1
                results[index] = "absorbed-by-earlier-creation"
                continue
            if listing.getInstructionAt(address) is None:
                DisassembleCommand(address, None, True).applyTo(program, monitor)
            if listing.getInstructionAt(address) is None:
                failed += 1
                results[index] = "no-instruction"
                if len(errors) < 10:
                    errors.append("create {} @0x{:X}: no instruction".format(
                        row[0], row[3]))
                continue
            if not CreateFunctionCmd(address).applyTo(program, monitor):
                failed += 1
                results[index] = "create-failed"
                if len(errors) < 10:
                    errors.append("create {} @0x{:X} failed".format(row[0], row[3]))
                continue
            function = functions.getFunctionAt(address)
            if function is None:
                failed += 1
                results[index] = "create-failed"
                continue
            created += 1
            outcome = "created+renamed"
        else:
            function = row[8]
        namespace = program.getGlobalNamespace()
        try:
            for part in parts:
                child = table.getNamespace(part, namespace)
                if child is None:
                    child = table.createNameSpace(namespace, part, SourceType.ANALYSIS)
                namespace = child
            function.getSymbol().setNameAndNamespace(local, namespace, SourceType.ANALYSIS)
            done += 1
            results[index] = outcome
        except Exception as exc:  # noqa: BLE001 -- counted and reported
            failed += 1
            results[index] = "{}rename-failed: {}".format(
                "created, " if outcome == "created+renamed" else "", exc)
            if len(errors) < 10:
                errors.append("{} @0x{:X}: {}".format(row[0], row[3], exc))
    budget = max(25, (done + created) // 100)
    if failed > budget:
        raise RuntimeError("{} renames/creations failed (budget {}): {}".format(
            failed, budget, "; ".join(errors)))
    if skipped_now_inside:
        errors.append("{} planned creations were absorbed by an earlier new "
                      "function and skipped".format(skipped_now_inside))
    return done, failed, errors, created


def require_build(program, build, role):
    """Refuse a program that is not the pinned executable of ``build``."""
    from evidence_identity import program_sha256
    actual = program_sha256(program)
    if actual != BUILD_SHA256[build]:
        raise SystemExit(
            "{} program {} has SHA-256 {}, not the pinned {} build {}".format(
                role, program.getName(), actual, build, BUILD_SHA256[build]))
    return actual


def pinned_target_pe(program, build, target_pe=None):
    """Path of an executable whose SHA-256 is ``build``'s pin, verified
    against the program (never the program's own import path alone)."""
    from binary_identity import verify_ghidra_program
    from target_pe import select_target_pe
    path, manifest = select_target_pe(program, [target_pe] if target_pe else ())
    if str(manifest.get("sha256") or "").lower() != BUILD_SHA256[build]:
        raise SystemExit("{} has SHA-256 {}, not the pinned {} build".format(
            path, manifest.get("sha256"), build))
    verify_ghidra_program(program, [manifest])
    return path


def evidence_path(source_build, target_build, mode, explicit=None,
                  directory=DEFAULT_EVIDENCE_DIR, now=None):
    """A ledger path that does not exist yet (an explicit one must be new)."""
    if explicit:
        path = Path(explicit)
        if path.exists():
            raise SystemExit("refusing to overwrite evidence {}".format(path))
        return path
    now = now or datetime.now(timezone.utc)
    stem = "id_port_{}_to_{}.{}.{}".format(
        source_build, target_build, mode, now.strftime("%Y%m%dT%H%M%SZ"))
    path = Path(directory) / (stem + ".csv")
    serial = 1
    while path.exists():
        serial += 1
        path = Path(directory) / "{}-{}.csv".format(stem, serial)
    return path


def write_evidence(path, rows, mode, results):
    """Exclusive create: an existing evidence file is never overwritten."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(EVIDENCE_FIELDS)
        for index in sorted(range(len(rows)), key=lambda i: (rows[i][4], rows[i][0])):
            row = rows[index]
            if mode == "dry-run":
                result = "dry-run"
            else:
                result = results.get(index, "not-applied")
            writer.writerow([row[0], "0x%X" % row[1], row[2] if row[2] is not None else "",
                             "0x%X" % row[3] if row[3] is not None else "", row[4], row[5],
                             mode, result])
    return path


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--source-build", required=True, choices=sorted(DBS))
    ap.add_argument("--source-program", required=True)
    ap.add_argument("--target-build", required=True, choices=sorted(DBS))
    ap.add_argument("--target-program", required=True)
    ap.add_argument("--evidence", help="new CSV path (default: a timestamped "
                    "file under build/evidence/; never overwritten)")
    ap.add_argument("--create-missing", action="store_true",
                    help="create the target function when none exists (see above)")
    ap.add_argument("--target-pe", help="exact target executable, for its .pdata "
                    "ranges; must carry the target build's pinned SHA-256 "
                    "(default: the program's recorded import path)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    if args.source_build == args.target_build or not _shared_namespace(
            args.source_build, args.target_build):
        ap.error("{} -> {} is not a shared-ID pair".format(
            args.source_build, args.target_build))

    library = AddressLibrary()
    library.load_all(str(REPO / "addresslibrary"))
    source_db = getattr(library, DBS[args.source_build])
    target_db = getattr(library, DBS[args.target_build])
    mode = "apply" if args.apply else "dry-run"
    evidence = evidence_path(args.source_build, args.target_build, mode,
                             explicit=args.evidence)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    results = {}

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang

    monitor = ConsoleTaskMonitor()
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()
        consumer = java.lang.Object()
        source_file = find_program(root, args.source_program)
        target_file = find_program(root, args.target_program)
        if source_file is None or target_file is None:
            raise SystemExit("source or target program not found")
        source = open_program(source_file, consumer, monitor, write=False)
        try:
            require_build(source, args.source_build, "source")
            source_names, source_stats = collect_source(source)
            source_text = _text_block(source)
        finally:
            source.release(consumer)
        print("source {}: {}".format(args.source_program, dict(source_stats)))
        target = open_program(target_file, consumer, monitor, write=args.apply)
        try:
            require_build(target, args.target_build, "target")
            unwind_ranges = ()
            if args.create_missing:
                from pe_unwind import extract_runtime_functions
                executable = pinned_target_pe(target, args.target_build, args.target_pe)
                unwind_ranges = [
                    (int(row["begin_rva"]), int(row["end_rva"]))
                    for row in extract_runtime_functions(executable)["runtime_functions"]]
            rows = plan(source_names, source_text, target, _text_block(target),
                        source_db, target_db, create_missing=args.create_missing,
                        unwind_ranges=unwind_ranges)
            counts = collections.Counter(row[4] for row in rows)
            done = failed = 0
            created = 0
            if args.apply and (counts["apply"] or counts["create"]):
                tx = target.startTransaction("AE-family ID port (byte-confirmed)")
                commit = False
                try:
                    done, failed, errors, created = apply_rows(
                        target, rows, monitor, results=results)
                    for line in errors:
                        print("  FAILED " + line)
                    commit = True
                except Exception as exc:
                    write_evidence(evidence, rows, mode, {
                        index: "rolled-back: {}".format(exc)
                        for index in range(len(rows))})
                    raise
                finally:
                    end_outer_transaction(target, tx, commit, "AE-family ID port")
                target.save("AE-family ID port {} -> {}".format(
                    args.source_build, args.target_build), monitor)
        finally:
            target.release(consumer)

    write_evidence(evidence, rows, mode, results)
    print("{} {} -> {}:".format("APPLIED" if args.apply else "DRY-RUN",
                                args.source_build, args.target_build))
    for decision, count in counts.most_common():
        print("  {:<24} {}".format(decision, count))
    if args.apply:
        print("  renamed={} created={} failed={}".format(done, created, failed))
    print("  evidence -> {}".format(evidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
