#!/usr/bin/env python3
"""Remove symbols that an importer placed at provably wrong addresses.

Input is the CSV written by ``diff_importer_symbols.py`` (``name, kind,
wrong_rva, ...``).  Re-applying a corrected importer never removes what the old
one wrote, so the stale labels have to be taken out explicitly.

DRY-RUN IS THE DEFAULT and opens the program read-only.  ``--apply`` mutates,
inside one transaction, and only what matches exactly:

  label    a LABEL symbol with that exact name at that exact address whose
           source is IMPORTED is deleted.
  func     a function at that address whose name matches and whose source is
           IMPORTED is reset to its default name (the function itself is kept).
  vfunc    collateral of a wrong ``VTABLE_<Class>`` label: the importer's
           unnamed vtable walk read "slots" at the wrong address and named the
           functions they happened to point at ``<Class>::Func<N>`` (source
           ANALYSIS, comment line ``VTABLE <Class>::Func<N>``).  A secondary
           table ``VTABLE_<Class>_<K>`` names its slots ``<Class>::Func<N>_v<K>``
           (the importer's ``sec_re``).  Reset only when name, source and that
           comment line all agree; every walked slot is reported.

A ``USER_DEFINED`` symbol is never touched unless ``--include-user-defined``
is given, which the owner must ask for explicitly (an earlier pipeline once
created importer labels as USER_DEFINED; the exact name, address and -- for
collateral -- the vtable-walk evidence line still have to match).  Everything
that does not match is reported (``absent``, ``source-mismatch``,
``name-mismatch``) and left alone.  Every run writes a NEW timestamped ledger
under ``build/evidence/`` (never overwritten) recording the mode, the planned
action and the actual result of every row.

The incident CSV is bound to the program it was computed for: ``--apply``
requires a ``<csv>.identity.json`` sidecar (RVA coordinates) and refuses a
program, or a backing executable, whose SHA-256 is not the bound one::

  python scripts/core/bind_evidence.py <csv> --exe <exact exe> \\
      --kind importer_wrong_symbols --coordinate RVA

Usage:
  python remove_wrong_importer_symbols.py --program-path /Skyrim/SkyrimAE_1_7_104.exe \\
      --csv refs/incidents/skyrim_17104_wrong_symbols_20260921.csv [--apply]
"""
from __future__ import annotations

import argparse
import bisect
import collections
import csv
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "core"))
from binary_identity import (_program_executable_path, inspect_pe,  # noqa: E402
                             verify_ghidra_program)
from evidence_identity import (EvidenceIdentityError,  # noqa: E402
                               read_binding, validate_evidence)
from ghidra_project import (find_program, open_program,  # noqa: E402
                            open_user_project)
from pyghidra_result import end_outer_transaction  # noqa: E402

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO / "tools" / "ghidra"))
MAX_WALK_SLOTS = 512
DEFAULT_LEDGER_DIR = REPO / "build" / "evidence"
# The importer's unnamed walk (ghidra_import_gen ``sec_re``): VTABLE_<C>_<K>
# is the K-th table of class C and names its slots C::Func<N>_v<K>.
_SECONDARY_VTABLE = re.compile(r"^(.+?)_(\d+)$")
LEDGER_FIELDS = ["name", "kind", "rva", "mode", "action", "result", "detail"]


def walk_owner(label_name):
    """(class, slot suffix) the importer derived from a ``VTABLE_`` label."""
    short = label_name[len("VTABLE_"):]
    match = _SECONDARY_VTABLE.match(short)
    if match:
        return match.group(1), "_v" + match.group(2)
    return short, ""


def slot_name(label_name, slot):
    owner, suffix = walk_owner(label_name)
    return "{}::Func{}{}".format(owner, slot, suffix)


def name_matches(function, name):
    """The importer stores ``C::FuncN`` as ONE literal Global name; another
    pipeline may have made ``C`` a real namespace.  Accept both shapes."""
    return function.getName(True) == name or function.getName() == name


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row.get("kind") not in ("label", "func") or not row.get("name"):
            raise SystemExit("unsupported row in {}: {}".format(path, row))
        row["rva"] = int(row["wrong_rva"], 16)
    return rows


def plan(program, rows, include_user_defined=False):
    """[(row, action, detail, target)]; pure inspection, never mutates."""
    from ghidra.program.model.symbol import SourceType, SymbolType

    # Sources this tool may remove.  USER_DEFINED only on explicit request;
    # it is compared against, never assigned.
    if include_user_defined:
        removable = {SourceType.IMPORTED, SourceType.USER_DEFINED}
        walk_sources = {SourceType.ANALYSIS, SourceType.USER_DEFINED}
    else:
        removable = {SourceType.IMPORTED}
        walk_sources = {SourceType.ANALYSIS}

    base = program.getImageBase()
    memory = program.getMemory()
    listing = program.getListing()
    table = program.getSymbolTable()
    functions = program.getFunctionManager()
    decisions = []
    # The importer's walk stops at the next VTABLE_ label in the same block,
    # so collateral can only exist up to there (the old fixed 512-slot walk was
    # needlessly slow on programs with thousands of labels).
    vtable_starts = sorted(
        symbol.getAddress().getOffset()
        for symbol in table.getSymbolIterator('VTABLE_*', True))

    def walk_limit(address):
        start = address.getOffset()
        index = bisect.bisect_right(vtable_starts, start)
        block = memory.getBlock(address)
        end = block.getEnd().getOffset() + 1 if block is not None else start
        if index < len(vtable_starts):
            end = min(end, vtable_starts[index])
        return max(0, min(MAX_WALK_SLOTS, (end - start) // 8))

    def decide(row, action, detail, target=None):
        decisions.append((row, action, detail, target))

    for row in rows:
        address = base.add(row["rva"])
        if row["kind"] == "func":
            function = functions.getFunctionAt(address)
            if function is None:
                decide(row, "absent", "no function at address")
            elif not name_matches(function, row["name"]):
                decide(row, "name-mismatch", function.getName(True))
            elif function.getSymbol().getSource() not in removable:
                decide(row, "source-mismatch", str(function.getSymbol().getSource()))
            else:
                decide(row, "reset-function-name", function.getName(True), function)
            continue

        matches = [symbol for symbol in table.getSymbols(address)
                   if symbol.getName() == row["name"]]
        if not matches:
            decide(row, "absent", "no symbol of that name at address")
        for symbol in matches:
            if symbol.getSymbolType() != SymbolType.LABEL:
                decide(row, "name-mismatch", "not a label: " + str(symbol.getSymbolType()))
            elif symbol.getSource() not in removable:
                decide(row, "source-mismatch", str(symbol.getSource()))
            else:
                decide(row, "delete-label", str(symbol.getSource()) + " label", symbol)

        # Collateral of the unnamed vtable walk from this wrong label.
        if not row["name"].startswith("VTABLE_"):
            continue
        for slot in range(1, walk_limit(address) + 1):
            try:
                pointer = memory.getLong(address.add((slot - 1) * 8)) & 0xFFFFFFFFFFFFFFFF
                target = base.getNewAddress(pointer)
            except Exception:  # noqa: BLE001 -- end of block / unmapped
                break
            block = memory.getBlock(target)
            if block is None or not block.isExecute():
                break
            function = functions.getFunctionAt(target)
            semantic = slot_name(row["name"], slot)
            collateral = {"name": semantic, "kind": "vfunc",
                          "wrong_rva": "0x%X" % (pointer - base.getOffset()),
                          "rva": pointer - base.getOffset()}
            if function is None:
                decide(collateral, "absent", "no function at walked slot target")
                continue
            if not name_matches(function, semantic):
                decide(collateral, "name-mismatch", function.getName(True))
                continue
            # The importer's _merge_plate_comment writes comment type 0, which
            # is the END-OF-LINE comment; accept the evidence line in either.
            evidence = "\n".join(listing.getComment(kind, target) or ""
                                 for kind in _evidence_comment_types())
            if function.getSymbol().getSource() not in walk_sources:
                decide(collateral, "source-mismatch",
                       str(function.getSymbol().getSource()))
            elif ("VTABLE " + semantic) not in evidence.splitlines():
                decide(collateral, "name-mismatch",
                       "no matching vtable-walk evidence comment")
            else:
                decide(collateral, "reset-function-name",
                       "unnamed vtable walk from " + row["name"], function)
    return decisions


def _evidence_comment_types():
    from ghidra.program.model.listing import CommentType
    return (CommentType.EOL, CommentType.PLATE)


def apply(program, decisions):
    """Mutate; returns (counts, per-decision result).  Raises on failure so
    the caller rolls the whole transaction back."""
    from ghidra.program.model.symbol import SourceType

    done = collections.Counter()
    results = []
    for _row, action, _detail, target in decisions:
        if action == "delete-label":
            if not target.delete():
                raise RuntimeError("could not delete " + target.getName())
            results.append("deleted")
        elif action == "reset-function-name":
            target.setParentNamespace(program.getGlobalNamespace())
            target.setName(None, SourceType.DEFAULT)
            results.append("reset")
        else:
            results.append("unchanged")
            continue
        done[action] += 1
    return done, results


def ledger_path(csv_path, mode, ledger_dir=DEFAULT_LEDGER_DIR, now=None):
    """A ledger path that does not exist yet: ``<stem>.<mode>.<UTC>.csv``."""
    now = now or datetime.now(timezone.utc)
    stem = "{}.{}.{}".format(Path(csv_path).stem, mode,
                             now.strftime("%Y%m%dT%H%M%SZ"))
    ledger_dir = Path(ledger_dir)
    candidate = ledger_dir / (stem + ".csv")
    serial = 1
    while candidate.exists():
        serial += 1
        candidate = ledger_dir / "{}-{}.csv".format(stem, serial)
    return candidate


def write_ledger(path, decisions, mode, results):
    """Exclusive create: an existing ledger is never overwritten."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(LEDGER_FIELDS)
        for (row, action, detail, _target), result in zip(decisions, results):
            writer.writerow([row["name"], row["kind"], row["wrong_rva"],
                             mode, action, result, detail])
    return path


def incident_binding(csv_path, require):
    """The incident CSV's identity sidecar, or None for an unbound dry run."""
    try:
        binding = read_binding(csv_path, require_content=True)
    except EvidenceIdentityError as exc:
        if require:
            raise SystemExit(
                "--apply needs the incident CSV bound to its program ({}); run "
                "scripts/core/bind_evidence.py {} --exe <exact exe> --kind "
                "importer_wrong_symbols --coordinate RVA".format(exc, csv_path))
        print("WARNING: {} is not bound to a program ({}); --apply will "
              "refuse".format(csv_path, exc))
        return None
    if binding.get("address_coordinate") != "RVA":
        raise SystemExit("incident CSV evidence must use RVA coordinates")
    return binding


def verify_bound_program(program, csv_path, binding, target_pe=None):
    """Prove the program IS the build the incident CSV was computed for: the
    bound SHA-256 (not the program's own import path) selects the manifest."""
    from target_pe import select_target_pe
    validate_evidence(csv_path, program, binding.get("kind"), require_content=True)
    expected = binding["target_sha256"].lower()
    _path, manifest = select_target_pe(program, [target_pe] if target_pe else ())
    if str(manifest.get("sha256") or "").lower() != expected:
        raise SystemExit("backing executable SHA-256 {} is not the incident "
                         "CSV's bound {}".format(manifest.get("sha256"), expected))
    verify_ghidra_program(program, [manifest])
    return manifest


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--program-path", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--target-pe", help="exact executable, when the path the "
                    "program recorded at import no longer exists")
    ap.add_argument("--include-user-defined", action="store_true",
                    help="also remove matching USER_DEFINED symbols (owner-approved only)")
    ap.add_argument("--apply", action="store_true",
                    help="mutate and save (default: read-only dry run)")
    ap.add_argument("--ledger-dir", default=str(DEFAULT_LEDGER_DIR),
                    help="where the timestamped ledger goes (default build/evidence)")
    args = ap.parse_args()

    rows = read_rows(args.csv)
    binding = incident_binding(args.csv, require=args.apply)
    mode = "applied" if args.apply else "dryrun"
    report = ledger_path(args.csv, mode, args.ledger_dir)
    report.parent.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang

    monitor = ConsoleTaskMonitor()
    with open_user_project(args.project_dir, args.project_name) as project:
        domain_file = find_program(
            project.getProjectData().getRootFolder(), args.program_path)
        if domain_file is None:
            raise SystemExit("{} is not in the project".format(args.program_path))
        consumer = java.lang.Object()
        program = open_program(domain_file, consumer, monitor, write=args.apply)
        try:
            if binding is not None:
                verify_bound_program(program, args.csv, binding, args.target_pe)
            else:
                # Unbound dry run only: proves no more than "unchanged since
                # import" -- which is why --apply requires the binding.
                executable = args.target_pe or _program_executable_path(program)
                verify_ghidra_program(program, [inspect_pe(executable)])
            decisions = plan(program, rows,
                             include_user_defined=args.include_user_defined)
            counts = collections.Counter(action for _r, action, _d, _t in decisions)
            done = collections.Counter()
            results = ["dry-run"] * len(decisions)
            if args.apply:
                tx = program.startTransaction("Remove wrong importer symbols")
                commit = False
                try:
                    done, results = apply(program, decisions)
                    commit = True
                except Exception as exc:
                    write_ledger(report, decisions, mode,
                                 ["rolled-back: {}".format(exc)] * len(decisions))
                    raise
                finally:
                    end_outer_transaction(program, tx, commit, "symbol cleanup")
                program.save("remove wrong importer symbols", monitor)
        finally:
            program.release(consumer)

    write_ledger(report, decisions, mode, results)
    print("{} {}: {} input rows".format(
        "APPLIED" if args.apply else "DRY-RUN", args.program_path, len(rows)))
    for action, count in sorted(counts.items()):
        print("  {:<22} {}".format(action, count))
    if args.apply:
        print("  mutated: " + (", ".join(
            "{}={}".format(k, v) for k, v in sorted(done.items())) or "nothing"))
    else:
        print("  nothing was changed; re-run with --apply after review")
    print("  ledger -> {}".format(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
