#!/usr/bin/env python3
"""For each VA in the input CSV that has no Ghidra function, try to
create a function there (via Ghidra's createFunction).  Then apply
the name from the CSV.

Used after expand_vtables_to_funcs.py to convert the ~157k "no
function at addr" cases into real renames.

Usage:
  python create_funcs_and_rename.py <project_dir> <project_name> <program_path> <csv>
      --target-sha256 <sha256>

New functions are created only for rows carrying a trusted
``boundary_source`` value (``pdata``, ``pdb``, or ``ghidra_function``).
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
CORE_DIR    = REPO_DIR / "scripts" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
from evidence_identity import read_binding, validate_evidence  # noqa: E402

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def sanitize_component(part: str) -> str:
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full: str):
    return [sanitize_component(p) for p in full.split("::")]


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    project_dir, project_name, program_path, csv_path = sys.argv[1:5]
    commit_msg = "Create functions at vtable slot VAs and rename"
    if "--commit-msg" in sys.argv:
        commit_msg = sys.argv[sys.argv.index("--commit-msg") + 1]
    if "--target-sha256" not in sys.argv:
        print('ERROR: --target-sha256 is required')
        sys.exit(1)
    expected_sha256 = sys.argv[sys.argv.index("--target-sha256") + 1].lower()
    if not Path(csv_path).is_file():
        print(f"ERROR: CSV missing: {csv_path}")
        sys.exit(2)
    binding = read_binding(csv_path, require_content=True)
    if binding['target_sha256'].lower() != expected_sha256:
        raise RuntimeError('CSV evidence targets another executable')
    if binding.get('address_coordinate') != 'VA':
        raise RuntimeError('target_va CSV evidence must use VA coordinates')

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import Function
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.cmd.disassemble import DisassembleCommand
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"PROJECT: {project_dir}/{project_name}")
    print(f"PROGRAM: {program_path}")
    print(f"CSV:     {csv_path}")

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        domain_file = None
        if program_path.startswith("/"):
            domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            root = project.getProjectData().getRootFolder()
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
            domain_file = walk(root)
        if domain_file is None:
            print(f"ERROR: program not found: {program_path}")
            sys.exit(3)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            actual_sha256 = (program.getExecutableSHA256() or '').lower()
            if not actual_sha256 or actual_sha256 != expected_sha256:
                raise RuntimeError('target executable SHA-256 mismatch')
            validate_evidence(
                csv_path, program, binding.get('kind'), require_content=True)
            fm = program.getFunctionManager()
            sym = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            memory = program.getMemory()

            # Determine .text bounds
            text_start = None
            text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f".text: 0x{text_start:x} - 0x{text_end:x}")

            txid = program.startTransaction(commit_msg)
            commit = False
            try:
                ns_cache = {}
                def get_or_create_namespace(path_parts):
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

                seen = set()
                n_total = 0
                n_created_renamed = 0
                n_already_named = 0
                n_renamed_existing = 0
                n_create_fail = 0
                n_outside_text = 0
                n_err = 0
                report_every = 5000

                with open(csv_path, encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        n_total += 1
                        try:
                            va_int = int(row["target_va"], 16)
                        except (KeyError, ValueError) as exc:
                            raise RuntimeError(
                                'invalid target_va in bound CSV evidence') from exc
                        if va_int in seen:
                            raise RuntimeError(
                                f'duplicate target VA 0x{va_int:x} in bound evidence')
                        seen.add(va_int)
                        if va_int < text_start or va_int >= text_end:
                            n_outside_text += 1
                            continue
                        addr = default_space.getAddress(va_int)
                        block = memory.getBlock(addr)
                        if (block is None or not block.isExecute() or
                                not block.isInitialized()):
                            n_outside_text += 1
                            continue
                        func = fm.getFunctionAt(addr)
                        if func is None:
                            if row.get('boundary_source', '').lower() not in {
                                    'pdata', 'pdb', 'ghidra_function'}:
                                n_create_fail += 1
                                continue
                            # If addr lies inside an existing function, skip
                            inside = fm.getFunctionContaining(addr)
                            if inside is not None:
                                n_create_fail += 1
                                continue
                            # Disassemble first if no instruction exists yet
                            listing = program.getListing()
                            if listing.getInstructionAt(addr) is None:
                                dcmd = DisassembleCommand(addr, None, True)
                                if not dcmd.applyTo(program, monitor):
                                    raise RuntimeError(
                                        f'disassembly failed at 0x{va_int:x}')
                            # Now create a function (auto-detects body via flow)
                            ccmd = CreateFunctionCmd(addr)
                            if not ccmd.applyTo(program, monitor):
                                n_create_fail += 1
                                raise RuntimeError(
                                    f'function creation failed at 0x{va_int:x}')
                            func = fm.getFunctionAt(addr)
                            if func is None:
                                n_create_fail += 1
                                raise RuntimeError(
                                    f'created function missing at 0x{va_int:x}')
                        cur = func.getName()
                        if func.getSymbol().getSource() in (
                                SourceType.USER_DEFINED, SourceType.IMPORTED):
                            n_already_named += 1
                            continue
                        if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_") or cur.startswith("sub_")):
                            n_already_named += 1
                            continue

                        parts = split_namespaced(row["name"])
                        if not parts:
                            n_err += 1
                            continue
                        leaf = parts[-1]
                        ns_path = parts[:-1]
                        try:
                            target_ns = get_or_create_namespace(ns_path) if ns_path else global_ns
                            func.setParentNamespace(target_ns)
                            func.setName(leaf, SourceType.ANALYSIS)
                            n_created_renamed += 1
                        except Exception as e:
                            n_err += 1
                            raise RuntimeError(
                                f"rename failed at 0x{va_int:x} "
                                f"'{row['name'][:60]}': {e}") from e

                        if n_total % report_every == 0:
                            print(f"  {n_total} processed  created+renamed={n_created_renamed}  "
                                  f"already={n_already_named}  create_fail={n_create_fail}  err={n_err}",
                                  flush=True)
                commit = True
            finally:
                program.endTransaction(txid, commit)

            if commit:
                print(f"\nSaving program ...")
                program.save(commit_msg, monitor)
            print(f"\n=== Summary ===")
            print(f"  total CSV rows:        {n_total}")
            print(f"  unique VAs seen:       {len(seen)}")
            print(f"  created+renamed:       {n_created_renamed}")
            print(f"  already named:         {n_already_named}")
            print(f"  create-function fail:  {n_create_fail}")
            print(f"  outside .text:         {n_outside_text}")
            print(f"  errors:                {n_err}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
