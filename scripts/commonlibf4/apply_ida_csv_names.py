#!/usr/bin/env python3
"""Apply the community IDA OG/AE function-name cross-map to a Ghidra program.

Input: ``IDA_Functions_OG_AE.csv`` -- a ``;``-separated table

    Name;OG_Addr;OG_REL_ID;AE_Addr;AE_REL_ID

with ~267k demangled C++ signatures keyed by *both* the OG (1.10.163) and AE
(1.11.191) RVA, so it doubles as an OG<->AE correspondence.  Its AE column is
the valuable half: our AE program is named mostly from CommonLibF4 + byte-sig
ports, and this adds tens of thousands of functions those miss.

Names arrive demangled (``BGSAIWorldLocation::~BGSAIWorldLocation(void)``), so
they are applied structurally: the parameter list is dropped and the ``::``
path becomes a real Ghidra namespace, giving ``BGSAIWorldLocation::~...`` in
the decompiler rather than one flat string.

Identity-gated like the other appliers: ``--apply`` requires an
``<csv>.identity.json`` evidence sidecar bound to the exact target executable.
The CSV carries TWO address columns, so the sidecar must also say WHICH column
belongs to that executable -- the evidence ``kind`` names it::

  python scripts/core/bind_evidence.py <csv> --exe <og_exe> \
      --kind ida_og_ae_names_og --coordinate RVA
  python scripts/core/bind_evidence.py <csv> --exe <ae_exe> \
      --kind ida_og_ae_names_ae --coordinate RVA

``--version`` must agree with the bound column: a CSV bound to the AE
executable and run with ``--version og`` would otherwise stamp OG RVAs onto the
AE program with every identity check passing.  (``port_names_by_id.py`` writes
target RVAs into ``AE_Addr`` and binds kind ``<game>_<src>_to_<tgt>``: column
``ae``.)  A kind that names no column is refused.

``--create-missing`` never creates inside an existing function (Ghidra would
split it), disassembles first and requires an instruction at the address, and
-- when the target executable is available (``--target-pe`` or the program's
recorded import path, verified against ``--target-sha256``) -- requires the
address to be a linker ``.pdata`` function start.

Usage:
  python apply_ida_csv_names.py <project_dir> <project_name> <program_path> \
      <csv> --version {og,ae} --target-sha256 <sha> \
      [--apply] [--create-missing [--target-pe EXE]] [--overwrite] [--max N]
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import sys
from pathlib import Path

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (Path(__file__).resolve().parent.parent.parent / "tools" / "ghidra"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from evidence_identity import read_binding, validate_evidence  # noqa: E402

_PLACEHOLDER = ("FUN_", "sub_", "thunk_FUN_", "thunk_sub_")
_IMAGE_BASE = 0x140000000
_COLUMNS = {"og": "OG_Addr", "ae": "AE_Addr"}
# Ghidra rejects these in symbol names; the demangled corpus is full of them.
_BAD_CHARS = re.compile(r"[\s'\"]+")
_COLUMN_KIND = re.compile(r"^ida_og_ae_names_(og|ae)$")
_PORT_BY_ID_KIND = re.compile(r"^[a-z0-9]+_[A-Za-z0-9]+_to_[A-Za-z0-9]+$")


def bound_column(kind):
    """Address column an evidence ``kind`` binds (``'og'``/``'ae'``), or None."""
    kind = str(kind or "")
    match = _COLUMN_KIND.match(kind)
    if match:
        return match.group(1)
    if _PORT_BY_ID_KIND.match(kind):
        return "ae"      # port_names_by_id.py: AE_Addr carries the target RVA
    return None


def require_bound_column(binding, version):
    """Refuse unless the sidecar binds exactly the column ``--version`` reads."""
    column = bound_column(binding.get("kind"))
    if column is None:
        raise RuntimeError(
            "CSV evidence kind %r does not say which address column belongs to "
            "the bound executable; re-bind with --kind ida_og_ae_names_og or "
            "ida_og_ae_names_ae" % (binding.get("kind"),))
    if column != version:
        raise RuntimeError(
            "CSV evidence binds the %s address column to this executable, but "
            "--version %s was requested" % (column.upper(), version))
    return column


def create_refusal(program, addr, function_starts=None):
    """Why no function may be created at ``addr`` (None: allowed).

    Pure inspection.  ``CreateFunctionCmd`` at an address inside an existing
    function returns True and SPLITS that function, so a containing function
    refuses; ``function_starts`` (linker ``.pdata`` begin RVAs of the verified
    target executable, when available) must contain the address.
    """
    block = program.getMemory().getBlock(addr)
    if block is None or not block.isExecute() or not block.isInitialized():
        return "not-executable"
    if program.getFunctionManager().getFunctionContaining(addr) is not None:
        return "inside-function"
    if function_starts is not None:
        rva = addr.getOffset() - program.getImageBase().getOffset()
        if rva not in function_starts:
            return "not-pdata-start"
    return None


def create_missing_function(program, addr, monitor, function_starts=None):
    """``(function, outcome)``; mirrors ``port_ae_family_by_id``: refuse
    (``create_refusal``), disassemble first, and require an instruction at
    ``addr`` -- on undefined bytes ``CreateFunctionCmd`` alone makes a 1-byte
    function with no instruction."""
    refusal = create_refusal(program, addr, function_starts)
    if refusal is not None:
        return None, refusal
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    listing = program.getListing()
    if listing.getInstructionAt(addr) is None:
        DisassembleCommand(addr, None, True).applyTo(program, monitor)
        if listing.getInstructionAt(addr) is None:
            return None, "no-instruction"
    if not CreateFunctionCmd(addr).applyTo(program, monitor):
        return None, "create-failed"
    function = program.getFunctionManager().getFunctionAt(addr)
    return function, ("created" if function is not None else "create-failed")


def verified_function_starts(program, target_sha256, target_pe=None):
    """Linker function starts of the target executable, or None when no
    executable is available.  The file must carry ``target_sha256`` (the
    evidence-bound hash) and match the program."""
    from binary_identity import verify_ghidra_program
    from target_pe import TargetPEError, select_target_pe
    try:
        path, manifest = select_target_pe(
            program, [target_pe] if target_pe else ())
    except TargetPEError as exc:
        if target_pe:
            raise
        print("WARNING: no target executable for .pdata function starts "
              "({}); --create-missing keeps only the structural checks".format(
                  str(exc).splitlines()[0]))
        return None
    if str(manifest.get("sha256") or "").lower() != target_sha256.lower():
        raise RuntimeError("{} is not the --target-sha256 executable".format(path))
    verify_ghidra_program(program, [manifest])
    starts = manifest.get("function_starts") or ()
    return frozenset(int(rva) for rva in starts) or None


def rename_function(func, namespace, leaf, source_type):
    """Move + rename in ONE symbol operation.

    ``setParentNamespace`` followed by ``setName`` is two mutations: when the
    rename fails (duplicate / invalid name) the function has already been
    moved and is left as ``Namespace::FUN_x``.  ``setNameAndNamespace``
    either does both or neither.
    """
    func.getSymbol().setNameAndNamespace(leaf, namespace, source_type)


def parse_csv(path, version, limit=0):
    """Return [(rva, namespace_parts, leaf), ...] for the chosen version."""
    column = _COLUMNS[version]
    out = []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle, delimiter=";"):
            raw = (row.get(column) or "").strip()
            name = (row.get("Name") or "").strip()
            if not raw or not name:
                continue
            try:
                rva = int(raw, 16)
            except ValueError:
                continue
            parts = _split_name(name)
            if parts is None:
                continue
            out.append((rva, parts[0], parts[1]))
            if limit and len(out) >= limit:
                break
    return out


def _strip_param_list(name):
    """Drop a trailing ``(...)`` parameter list, keeping ``operator()``.

    Cutting at the FIRST '(' would truncate ``operator()`` to ``operator``,
    so the trailing balanced group is removed instead -- and only when what
    precedes it is not the operator's own parentheses.
    """
    name = name.strip()
    if not name.endswith(")"):
        return name
    depth = 0
    for i in range(len(name) - 1, -1, -1):
        ch = name[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                head = name[:i].rstrip()
                if head.endswith("operator"):
                    return name  # these parens ARE the name: operator()
                return head or name
    return name


def _split_name(name):
    """``A::B::f(int, char)`` -> (['A', 'B'], 'f').  None when unusable."""
    stem = _strip_param_list(name)
    if not stem:
        return None
    # Split on '::' only at template depth 0 so RE::BSTArray<A::B> stays whole.
    parts, depth, current = [], 0, ""
    i = 0
    while i < len(stem):
        ch = stem[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if depth == 0 and stem.startswith("::", i):
            parts.append(current)
            current = ""
            i += 2
            continue
        current += ch
        i += 1
    parts.append(current)
    parts = [_BAD_CHARS.sub("_", p).strip() for p in parts if p.strip()]
    if not parts:
        return None
    return parts[:-1], parts[-1]


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


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("program_path")
    ap.add_argument("csv_file")
    ap.add_argument("--version", required=True, choices=("og", "ae"))
    ap.add_argument("--target-sha256", required=True,
                    help="exact analyzed executable SHA-256")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--create-missing", action="store_true",
                    help="create a function where Ghidra has none (never "
                         "inside an existing one; see above)")
    ap.add_argument("--target-pe",
                    help="exact target executable for --create-missing's "
                         ".pdata check (default: the recorded import path)")
    ap.add_argument("--overwrite", action="store_true",
                    help="replace any existing name, not just placeholders")
    ap.add_argument("--max", type=int, default=0)
    args = ap.parse_args()

    if args.apply:
        binding = read_binding(args.csv_file, require_content=True)
        if binding["target_sha256"].lower() != args.target_sha256.lower():
            raise RuntimeError("CSV evidence targets another executable")
        if binding.get("address_coordinate") != "RVA":
            raise RuntimeError("CSV evidence must use RVA coordinates")
        require_bound_column(binding, args.version)

    rows = parse_csv(args.csv_file, args.version, args.max)
    print("parsed %d %s names from CSV" % (len(rows), args.version.upper()))

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    from ghidra_project import open_program, open_user_project
    with open_user_project(pdir, pname) as project:
        df = _resolve_program(project, args.program_path)
        if df is None:
            print("ERROR: program not found: %s" % args.program_path)
            sys.exit(3)
        consumer = java.lang.Object()
        # Read-only for a dry run; never destroys crash-recovery data.
        program = open_program(df, consumer, monitor, write=bool(args.apply))
        try:
            actual = (program.getExecutableSHA256() or "").lower()
            if actual != args.target_sha256.lower():
                raise RuntimeError("target executable SHA-256 mismatch")
            if args.apply:
                validate_evidence(args.csv_file, program, binding.get("kind"),
                                  require_content=True)
            function_starts = None
            if args.apply and args.create_missing:
                function_starts = verified_function_starts(
                    program, args.target_sha256, args.target_pe)

            base = program.getImageBase()
            fm = program.getFunctionManager()
            mem = program.getMemory()
            symtab = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()
            st = {"total": 0, "named": 0, "created": 0, "no_func": 0,
                  "skip_named": 0, "oob": 0, "fail": 0}
            refused = collections.Counter()
            ns_cache = {}

            def namespace_for(parts):
                if not parts:
                    return global_ns
                key = "::".join(parts)
                if key in ns_cache:
                    return ns_cache[key]
                parent = global_ns
                for part in parts:
                    sub = symtab.getNamespace(part, parent)
                    if sub is None:
                        sub = symtab.createNameSpace(
                            parent, part, SourceType.IMPORTED)
                    parent = sub
                ns_cache[key] = parent
                return parent

            tx = program.startTransaction("apply IDA CSV names") if args.apply else None
            commit = False
            try:
                for rva, ns_parts, leaf in rows:
                    st["total"] += 1
                    addr = base.add(rva)
                    if not mem.contains(addr):
                        st["oob"] += 1
                        continue
                    func = fm.getFunctionAt(addr)
                    if func is None:
                        if args.apply and args.create_missing:
                            func, outcome = create_missing_function(
                                program, addr, monitor, function_starts)
                            if func is not None:
                                st["created"] += 1
                            else:
                                refused[outcome] += 1
                        if func is None:
                            st["no_func"] += 1
                            continue
                    if (not args.overwrite and
                            not func.getName().startswith(_PLACEHOLDER)):
                        st["skip_named"] += 1
                        continue
                    if not args.apply:
                        st["named"] += 1
                        continue
                    try:
                        rename_function(func, namespace_for(ns_parts), leaf,
                                        SourceType.IMPORTED)
                        st["named"] += 1
                    except Exception:  # noqa: BLE001
                        # duplicate/invalid name: skip this one, keep the batch
                        st["fail"] += 1
                commit = True
            finally:
                if tx is not None:
                    if not program.endTransaction(tx, commit) and commit:
                        raise RuntimeError("transaction did not commit; nothing was saved")
            if args.apply and commit and (st["named"] or st["created"]):
                program.save("apply IDA CSV names (%s)" % args.version, monitor)
        finally:
            program.release(consumer)

    mode = "APPLIED" if args.apply else "DRY-RUN"
    print("%s: %d named  (created %d, no-func %d, skip-already-named %d, "
          "oob %d, fail %d)"
          % (mode, st["named"], st["created"], st["no_func"], st["skip_named"],
             st["oob"], st["fail"]))
    if refused:
        print("  creation refused: " + ", ".join(
            "{}={}".format(k, v) for k, v in sorted(refused.items())))
    if not args.apply:
        print("  re-run with --apply --create-missing to write + save.")


if __name__ == "__main__":
    main()
