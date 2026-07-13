#!/usr/bin/env python3
"""Sync naming from Combined.gpr/Starfield 1.16.236 to
BethesdaGhidraScripts.gpr/starfield/sf/Starfield.exe (same MD5).

Strategy: dump named functions from Combined.gpr, apply them to BGS.

Why not just run all the CSVs separately against BGS?  The CSV
pipeline involves:
  - sf116_combined_names.csv (byte-sig + BSim merge)
  - sf116_union_names.csv (cross-merge of named copies)
  - sf116_vtable_func_names.csv (vtable slot expansion)
  - sf116_func_ids.csv (CommonLibSF IDs.h direct names)
  - sf116_constructors.csv (vtable LEA scan ctors)
  - The Func{N} -> real-name replacements that happened inside Ghidra

The cleanest sync: dump Combined.gpr's current named-function list,
apply it to BGS in one go.  Also includes the function-creation pass
since BGS may not have Ghidra functions at all the vtable-slot VAs.
"""
from __future__ import annotations

import csv
import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"
CORE_DIR    = REPO_DIR / "scripts" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
from evidence_identity import bind_evidence, validate_evidence  # noqa: E402

DUMP_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_named_from_combined_final.csv"
DUMP_IDENTITY = Path(str(DUMP_CSV) + '.identity.json')
EVIDENCE_KIND = 'sf-exact-program-named-functions'

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def sanitize_component(part):
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full):
    return [sanitize_component(p) for p in full.split("::")]


def dump_from_combined(project_dir, project_name, program_path):
    """Dump every named function from Combined.gpr/Starfield 1.16.236."""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            raise RuntimeError('source program not found: {}'.format(program_path))
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            fm = program.getFunctionManager()
            n = 0
            DUMP_CSV.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix='.sf-names-', suffix='.tmp', dir=str(DUMP_CSV.parent))
            try:
                with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
                    w = csv.writer(fh)
                    w.writerow(["target_rva", "name"])
                    image_base = (program.getImageBase().getOffset() &
                                  0xFFFFFFFFFFFFFFFF)
                    for func in fm.getFunctions(True):
                        nm = func.getName(True)
                        leaf = func.getName()
                        if leaf.startswith(("FUN_", "thunk_FUN_", "sub_")):
                            continue
                        addr = func.getEntryPoint().getOffset()
                        if addr < image_base:
                            raise RuntimeError(
                                'source function precedes Program image base')
                        w.writerow([f"0x{addr - image_base:x}", nm])
                        n += 1
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(temporary, DUMP_CSV)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            print(f"Dumped {n} named functions to {DUMP_CSV}")
            bind_evidence(
                str(DUMP_CSV), program, EVIDENCE_KIND,
                address_coordinate="RVA")
        finally:
            program.release(consumer)


def apply_to_bgs(project_dir, project_name, program_path):
    """Apply DUMP_CSV to BethesdaGhidraScripts, creating funcs as needed."""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    # pyghidra.start is idempotent

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.cmd.disassemble import DisassembleCommand
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            print(f"ERROR: {program_path} not found")
            return
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            validate_evidence(
                str(DUMP_CSV), program, EVIDENCE_KIND, require_content=True)
            image_base = (program.getImageBase().getOffset() &
                          0xFFFFFFFFFFFFFFFF)
            fm = program.getFunctionManager()
            sym = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            memory = program.getMemory()
            listing = program.getListing()

            text_start = text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()

            txid = program.startTransaction("Sync names from Combined.gpr")
            commit = False
            try:
                ns_cache = {}
                def get_or_create_namespace(path_parts):
                    if not path_parts:
                        return global_ns
                    key = "::".join(path_parts)
                    if key in ns_cache:
                        return ns_cache[key]
                    parent = global_ns
                    for part in path_parts:
                        sub = sym.getNamespace(part, parent)
                        if sub is None:
                            sub = sym.createNameSpace(parent, part, SourceType.ANALYSIS)
                        parent = sub
                    ns_cache[key] = parent
                    return parent

                n_total = 0
                n_renamed = 0
                n_already = 0
                n_created = 0
                n_create_fail = 0
                n_err = 0

                seen_rvas = set()
                with open(DUMP_CSV, encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)
                    if (not reader.fieldnames or
                            not {"target_rva", "name"} <= set(reader.fieldnames)):
                        raise RuntimeError(
                            'bound name evidence must use target_rva coordinates')
                    for row in reader:
                        n_total += 1
                        try:
                            rva = int(row["target_rva"], 16)
                        except ValueError as exc:
                            raise RuntimeError(
                                'invalid RVA in bound name evidence') from exc
                        if rva < 0 or rva in seen_rvas:
                            raise RuntimeError(
                                'negative/duplicate RVA in bound name evidence')
                        seen_rvas.add(rva)
                        va_int = image_base + rva
                        if va_int < text_start or va_int >= text_end:
                            raise RuntimeError(
                                'bound name evidence points outside executable memory')
                        addr = default_space.getAddress(va_int)
                        block = memory.getBlock(addr)
                        if (block is None or not block.isExecute() or
                                not block.isInitialized()):
                            raise RuntimeError(
                                'bound name evidence points outside initialized code')
                        func = fm.getFunctionAt(addr)
                        if func is None:
                            inside = fm.getFunctionContaining(addr)
                            if inside is not None:
                                n_create_fail += 1
                                continue
                            if listing.getInstructionAt(addr) is None:
                                DisassembleCommand(addr, None, True).applyTo(program, monitor)
                            if not CreateFunctionCmd(addr).applyTo(program, monitor):
                                n_create_fail += 1
                                continue
                            func = fm.getFunctionAt(addr)
                            if func is None:
                                n_create_fail += 1
                                continue
                            n_created += 1
                        cur = func.getName()
                        if func.getSymbol().getSource() in (
                                SourceType.USER_DEFINED, SourceType.IMPORTED):
                            n_already += 1
                            continue
                        if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_") or cur.startswith("sub_")):
                            n_already += 1
                            continue
                        parts = split_namespaced(row["name"])
                        leaf = parts[-1]
                        ns_path = parts[:-1]
                        try:
                            target_ns = get_or_create_namespace(ns_path)
                            func.setParentNamespace(target_ns)
                            func.setName(leaf, SourceType.ANALYSIS)
                            n_renamed += 1
                        except Exception as e:
                            n_err += 1
                            raise RuntimeError(
                                f"rename failed at 0x{va_int:x} "
                                f"'{row['name'][:50]}': {e}") from e
                        if n_total % 5000 == 0:
                            print(f"  {n_total} processed  renamed={n_renamed}  created={n_created}  already={n_already}  err={n_err}", flush=True)
                commit = True
            finally:
                program.endTransaction(txid, commit)
            if commit:
                print(f"\nSaving program ...")
                program.save("Sync names from Combined.gpr", monitor)
            print(f"\n=== Summary ===")
            print(f"  total rows:        {n_total}")
            print(f"  renamed:           {n_renamed}")
            print(f"  funcs created:     {n_created}")
            print(f"  already named:     {n_already}")
            print(f"  create-fail:       {n_create_fail}")
            print(f"  errors:            {n_err}")
        finally:
            program.release(consumer)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-project-dir', required=True)
    ap.add_argument('--source-project-name', required=True)
    ap.add_argument('--source-program', required=True)
    ap.add_argument('--target-project-dir',
                    default=str(REPO_DIR / 'ghidraprojects' / 'BethesdaGhidraScripts'))
    ap.add_argument('--target-project-name', default='BethesdaGhidraScripts')
    ap.add_argument('--target-program', required=True)
    args = ap.parse_args()
    print("=== Step 1: dump Combined.gpr named functions ===")
    dump_from_combined(args.source_project_dir, args.source_project_name,
                       args.source_program)
    print("\n=== Step 2: apply to BethesdaGhidraScripts.gpr ===")
    apply_to_bgs(args.target_project_dir, args.target_project_name,
                 args.target_program)


if __name__ == "__main__":
    main()
