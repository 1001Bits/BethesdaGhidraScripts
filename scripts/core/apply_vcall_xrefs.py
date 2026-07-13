#!/usr/bin/env python3
"""Apply runtime virtual-dispatch edges to Ghidra as COMPUTED_CALL xrefs.

Static analysis can't resolve indirect / vtable calls (``call qword [rax+0x48]``),
so Ghidra's call graph has no edge at those sites.  A runtime tracer (TTD,
Intel PT, DynamoRIO, Frida -- see ``ttd_dump_calls.js``) records which target
each indirect call actually reached; this driver places those ``(site ->
target)`` edges as ``COMPUTED_CALL`` references so the call graph and
"references to" populate for virtual dispatches.

Edge CSV (header optional; RVAs hex or 0x-prefixed):

    caller_rva,target_rva[,count]

``caller_rva`` is whatever the tracer reports for the call -- usually the
RETURN address (the instruction *after* the call).  We resolve it to the real
call instruction via the disassembly (``getInstructionContaining`` /
``getInstructionBefore``), so both call-site and return-address inputs work.
``count`` (optional) is how many times the edge was observed.

Dry-run by default (resolves + counts, no writes); ``--apply`` places the refs
and saves the program.  Idempotent: an edge whose ref already exists is
skipped.  A polymorphic site legitimately gets multiple targets (one per object
type observed) -- all are placed.

``--apply`` requires an ``<edges_csv>.identity.json`` trace-manifest sidecar
(full PE manifest of the traced module + the TTD session id); produce it with::

  python scripts/core/bind_evidence.py <edges_csv> --exe <traced_exe> \
      --kind ttd_vcall_edges --trace-session-id <TTD SessionID>

Usage:
  python apply_vcall_xrefs.py <project_dir> <project_name> <program_path> \
      <edges_csv> [--apply] [--min-count N] [--max N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GHIDRA_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"


def parse_edges(path):
    """Yield (caller_rva, target_rva, count) from the edge CSV. Pure stdlib."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.replace("\t", ",").split(",") if p.strip()]
            if len(parts) < 2:
                continue
            try:
                caller = int(parts[0], 16)   # RVAs are hex (0x-prefixed or bare)
                target = int(parts[1], 16)
            except ValueError:
                continue  # header / junk line
            count = 1
            if len(parts) >= 3:
                try:
                    count = int(parts[2])
                except ValueError:
                    count = 1
            if count <= 0:
                continue
            out.append((caller, target, count))
    return out


def load_trace_manifest(edge_path, manifest_path=None):
    """Load the required trace/binary lineage sidecar."""
    path = manifest_path or str(edge_path) + '.identity.json'
    if not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8') as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError('trace manifest must be an object')
    target = value.get('target') or value.get('artifact')
    trace = value.get('trace') or {}
    if not isinstance(target, dict) or not target.get('sha256'):
        raise ValueError('trace manifest requires exact target.sha256')
    if not trace.get('session_id'):
        raise ValueError('trace manifest requires trace.session_id')
    return value


def _resolve_program(project, program_path):
    pd = project.getProjectData()
    df = pd.getFile(program_path) if program_path.startswith("/") else None
    if df is None:
        target = program_path.lstrip("/").split("/")[-1]

        def walk(folder):
            for f in folder.getFiles():
                if f.getName() == target:
                    return f
            for sub in folder.getFolders():
                r = walk(sub)
                if r is not None:
                    return r
            return None

        df = walk(pd.getRootFolder())
    return df


def _call_site(listing, addr):
    """Return the call Instruction for ``addr`` (a call site or its return addr)."""
    inst = listing.getInstructionContaining(addr)
    if inst is not None and inst.getFlowType().isCall():
        return inst
    prev = listing.getInstructionBefore(addr)
    if prev is not None and prev.getFlowType().isCall():
        # addr should be exactly the byte after the call (the return address)
        if prev.getMaxAddress().add(1).equals(addr):
            return prev
    return None


def apply_edges(program, edges, do_apply, monitor, min_count=1):
    from ghidra.program.model.symbol import RefType, SourceType

    image_base = program.getImageBase().getOffset()
    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    mem = program.getMemory()
    refmgr = program.getReferenceManager()

    def addr(rva):
        return space.getAddress(image_base + rva)

    st = {"total": 0, "applied": 0, "dup": 0, "no_site": 0,
          "target_oob": 0, "low_count": 0, "self": 0}

    tx = program.startTransaction("apply vcall xrefs") if do_apply else None
    commit = False
    try:
        for caller_rva, target_rva, count in edges:
            st["total"] += 1
            if count < min_count:
                st['low_count'] += 1
                continue
            site_a = addr(caller_rva)
            tgt_a = addr(target_rva)
            target_block = mem.getBlock(tgt_a)
            site_block = mem.getBlock(site_a)
            if (target_block is None or not target_block.isInitialized()
                    or not target_block.isExecute()):
                st["target_oob"] += 1
                continue
            if site_block is None or not site_block.isExecute():
                st['no_site'] += 1
                continue
            inst = _call_site(listing, site_a)
            if inst is None:
                st["no_site"] += 1
                continue
            from_a = inst.getAddress()
            if from_a.equals(tgt_a):
                st["self"] += 1
                continue
            # idempotent: skip if a call ref to this target already exists here
            if any(r.getToAddress().equals(tgt_a) and r.getReferenceType().isCall()
                   for r in refmgr.getReferencesFrom(from_a)):
                st["dup"] += 1
                continue
            if do_apply:
                refmgr.addMemoryReference(
                    from_a, tgt_a, RefType.COMPUTED_CALL,
                    SourceType.ANALYSIS, 0)
            st["applied"] += 1
        commit = True
    finally:
        if tx is not None:
            program.endTransaction(tx, commit)
    return st


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("program_path")
    ap.add_argument("edges_csv")
    ap.add_argument("--apply", action="store_true",
                    help="place the refs + save (default: dry-run)")
    ap.add_argument("--max", type=int, default=0, help="limit to first N edges")
    ap.add_argument('--min-count', type=int, default=1,
                    help='minimum observations required for an edge')
    ap.add_argument('--manifest', help='trace identity sidecar (default edges_csv.identity.json)')
    args = ap.parse_args()

    edges = parse_edges(args.edges_csv)
    if args.max:
        edges = edges[:args.max]
    print("Edges parsed: %d" % len(edges))
    if not edges:
        return
    trace_manifest = load_trace_manifest(args.edges_csv, args.manifest)
    if args.apply and trace_manifest is None:
        print('ERROR: applying runtime edges requires an exact trace identity sidecar')
        sys.exit(2)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    with pyghidra.open_project(pdir, pname, create=False) as project:
        df = _resolve_program(project, args.program_path)
        if df is None:
            print("ERROR: program not found: %s" % args.program_path)
            sys.exit(3)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, True, False, monitor)
        try:
            if trace_manifest is not None:
                from binary_identity import verify_ghidra_program
                expected = trace_manifest.get('target') or trace_manifest.get('artifact')
                verify_ghidra_program(program, [expected])
            st = apply_edges(program, edges, args.apply, monitor,
                             min_count=max(1, args.min_count))
            if args.apply and st["applied"]:
                program.save("apply vcall xrefs", monitor)
        finally:
            program.release(consumer)

    mode = "APPLIED" if args.apply else "DRY-RUN"
    print("%s: %d/%d edges placed  (dup %d, no-call-site %d, target-oob %d, low-count %d, self %d)"
          % (mode, st["applied"], st["total"], st["dup"], st["no_site"],
             st["target_oob"], st['low_count'], st["self"]))
    if not args.apply:
        print("  re-run with --apply to write the COMPUTED_CALL refs + save.")


if __name__ == "__main__":
    main()
