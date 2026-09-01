#!/usr/bin/env python3
"""Identify thunk functions: tiny FUN_* functions whose first/only
instruction is a JMP to a named function.

Generates: scripts/commonlibsf/refs/sf116_thunks.csv
  columns: target_va, name

Where 'name' is 'j_<callee_name>' (Ghidra convention).

Two thunk patterns handled:
  1. Direct relative jump:    E9 XX XX XX XX                (5 bytes)
  2. Indirect via memory:     FF 25 XX XX XX XX             (6 bytes, RIP-rel)

We use Ghidra's instruction analysis (not raw bytes) so we correctly
handle whatever the disassembler produced.  We only consider funcs
whose body is exactly one instruction OR a single jump.
"""
from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "ExampleProject"
PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

OUT_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_thunks.csv"


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            fm = program.getFunctionManager()
            listing = program.getListing()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            memory = program.getMemory()

            n_total = 0
            n_fun_prefix = 0
            n_thunk_found = 0

            with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["target_va", "name"])
                for func in fm.getFunctions(True):
                    n_total += 1
                    if not func.getName().startswith("FUN_"):
                        continue
                    n_fun_prefix += 1
                    body = func.getBody()
                    if body is None:
                        continue
                    # Quick size check: a thunk function is small (<=16 bytes)
                    body_size = body.getNumAddresses()
                    if body_size > 16:
                        continue
                    entry = func.getEntryPoint()
                    instr = listing.getInstructionAt(entry)
                    if instr is None:
                        continue
                    mnemonic = instr.getMnemonicString()
                    if mnemonic != "JMP":
                        continue
                    # Get reference's TO address
                    refs = instr.getReferencesFrom()
                    target_va = None
                    for r in refs:
                        if r.getReferenceType().isFlow():  # the call/jump target
                            target_va = r.getToAddress().getOffset()
                            break
                    if target_va is None:
                        continue

                    # Resolve target name.  For E9 (direct rel32) the
                    # target is a function; for FF 25 (indirect via .idata)
                    # the target is the import slot, which Ghidra's "thunk"
                    # facility resolves via its own getThunkedFunction.
                    # Try both: target function or via memory dereference.
                    tgt_func = fm.getFunctionAt(default_space.getAddress(target_va))
                    if tgt_func is None:
                        # Maybe FF 25 indirect: read pointer at target_va
                        try:
                            indirect_addr = memory.getLong(default_space.getAddress(target_va)) & 0xFFFFFFFFFFFFFFFF
                            tgt_func = fm.getFunctionAt(default_space.getAddress(indirect_addr))
                        except Exception:
                            pass
                    if tgt_func is None:
                        continue
                    tgt_name = tgt_func.getName(True)
                    tgt_leaf = tgt_func.getName()
                    # Only emit if the target itself has a meaningful name
                    if tgt_leaf.startswith(("FUN_", "thunk_FUN_", "sub_")):
                        continue
                    entry_va = entry.getOffset()
                    # Use Ghidra "j_" prefix on the LEAF only; preserve the
                    # target's namespace path so the thunk lives next to the
                    # target in the symbol tree.
                    parts = tgt_name.split("::")
                    new_name = "::".join(parts[:-1] + [f"j_{parts[-1]}"]) if len(parts) > 1 else f"j_{tgt_leaf}"
                    w.writerow([f"0x{entry_va:x}", new_name])
                    n_thunk_found += 1
                    if n_thunk_found % 1000 == 0:
                        print(f"  found {n_thunk_found} thunks  ({n_fun_prefix} FUN_ candidates scanned)", flush=True)

            print(f"\n=== Summary ===")
            print(f"  total funcs scanned:  {n_total}")
            print(f"  FUN_ candidates:      {n_fun_prefix}")
            print(f"  thunks identified:    {n_thunk_found}")
            print(f"  wrote {OUT_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
