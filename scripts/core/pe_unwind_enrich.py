"""Ghidra driver: improve AMD64 functions from linker ``.pdata/.xdata``.

Runtime-function entries provide exact function starts/ranges and unwind facts
without relying on prologue bytes.  The driver validates every destination
against its individual memory block.  Dry-run is the default; set
``BGS_ENRICH_APPLY=go`` to create missing entries and add provenance comments.
"""

import os
import sys


CORE_DIR = os.path.dirname(os.path.abspath(__file__))
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)


APPLY = os.environ.get("BGS_ENRICH_APPLY", "dry").lower() == "go"
MARKER = "[BGS:pe-unwind]"


def _require_command_success(result, operation):
    if not result:
        raise RuntimeError("pe-unwind {} failed; rolling back pass".format(
            operation))


def _append_comment(listing, address, text):
    from ghidra.program.model.listing import CodeUnit
    old = listing.getComment(CodeUnit.PLATE_COMMENT, address) or ""
    kept = [line for line in old.splitlines() if not line.startswith(MARKER)]
    kept.append(text)
    listing.setComment(address, CodeUnit.PLATE_COMMENT,
                       "\n".join(line for line in kept if line))


def run():
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd

    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print("pe-unwind: AMD64 runtime-function format does not apply to " + cp.getName())
        return
    from binary_identity import (PEIdentityError, _program_executable_path,
                                 verify_ghidra_program)
    from pe_unwind import extract_runtime_functions

    # Ghidra records Windows paths in URI-like form (for example
    # ``/C:/Games/...``).  Use the central normalizer so the identity guard
    # checks the real backing file instead of rejecting a valid import.
    executable_path = _program_executable_path(cp) or ""
    if not executable_path or not os.path.isfile(executable_path):
        raise RuntimeError(
            "pe-unwind requires the exact imported executable to remain available")
    try:
        extracted = extract_runtime_functions(executable_path)
        verify_ghidra_program(cp, [extracted["target"]])
    except (OSError, ValueError, PEIdentityError) as exc:
        raise RuntimeError("pe-unwind target verification failed: {}".format(exc))

    memory = cp.getMemory()
    runtime_functions = extracted.get("runtime_functions", [])
    if not runtime_functions:
        print("pe-unwind: no validated PE exception-directory entries in " + cp.getName())
        return
    af = cp.getAddressFactory().getDefaultAddressSpace()
    image_base = cp.getImageBase().getOffset()
    listing = cp.getListing()
    fm = cp.getFunctionManager()
    bookmarks = cp.getBookmarkManager()

    valid = len(runtime_functions)
    rejected = len(extracted.get("rejected", []))
    existing = created = annotated = 0
    success = False
    had_parent_transaction = (
        APPLY and cp.getCurrentTransactionInfo() is not None)
    tx = cp.startTransaction("BGS PE unwind improvement") if APPLY else None
    try:
        for row in runtime_functions:
            begin_rva = int(row["begin_rva"])
            end_rva = int(row["end_rva"])
            unwind_rva = int(row["unwind_rva"])
            unwind_info = row["unwind"]
            start = af.getAddress(image_base + begin_rva)
            end = af.getAddress(image_base + end_rva - 1)
            unwind = af.getAddress(image_base + unwind_rva)
            start_block = memory.getBlock(start)
            end_block = memory.getBlock(end)
            unwind_block = memory.getBlock(unwind)
            same_code_block = bool(
                start_block is not None and end_block is not None and
                start_block.getStart() == end_block.getStart() and
                start_block.getEnd() == end_block.getEnd())
            if (start_block is None or end_block is None or
                    not start_block.isExecute() or not end_block.isExecute() or
                    not same_code_block or unwind_block is None or
                    unwind_block.isExecute()):
                rejected += 1
                continue
            version = int(unwind_info["version"])
            flags = int(unwind_info["flags"])
            prolog = int(unwind_info["prolog_size"])
            handler_rva = unwind_info.get("handler_rva")
            function = fm.getFunctionAt(start)
            if function is not None:
                existing += 1
            elif APPLY:
                containing = fm.getFunctionContaining(start)
                if containing is not None:
                    # Never split or rewrite an existing function body merely
                    # because Ghidra's analysis disagrees with linker ranges.
                    rejected += 1
                    continue
                if listing.getInstructionAt(start) is None:
                    _require_command_success(
                        DisassembleCommand(start, None, True).applyTo(  # noqa: F821
                            cp, monitor), "disassembly")
                _require_command_success(
                    CreateFunctionCmd(start).applyTo(cp, monitor),  # noqa: F821
                    "function creation")
                function = fm.getFunctionAt(start)
                if function is None:
                    raise RuntimeError(
                        "pe-unwind function creation reported success but "
                        "no entry exists")
                created += 1
            else:
                created += 1  # would-create

            handler_text = (" handler_rva=0x%X" % handler_rva
                            if handler_rva is not None else "")
            chain_text = ""
            if unwind_info.get("chained"):
                chain = unwind_info["chained"]
                chain_text = " chain=rva:0x%X-0x%X" % (
                    chain["begin_rva"], chain["end_rva"])
            note = ("%s range=rva:0x%X-0x%X unwind=rva:0x%X "
                    "version=%d flags=0x%X prolog=%d%s%s" % (
                        MARKER, begin_rva, end_rva, unwind_rva, version,
                        flags, prolog, handler_text, chain_text))
            if APPLY and function is not None:
                _append_comment(listing, start, note)
                bookmarks.setBookmark(start, "Analysis", "BGS PE Unwind", note)
                annotated += 1
            elif not APPLY:
                annotated += 1
        success = True
    finally:
        if tx is not None:
            committed = bool(cp.endTransaction(tx, success))
            if success and not had_parent_transaction and not committed:
                raise RuntimeError(
                    "pe-unwind improvement transaction did not commit")

    print("pe-unwind (%s): %s valid=%d existing=%d %s=%d %s=%d rejected=%d" % (
        cp.getName(), "APPLIED" if APPLY else "DRY-RUN", valid, existing,
        "created" if APPLY else "would-create", created,
        "annotated" if APPLY else "would-annotate", annotated, rejected))


if "currentProgram" in globals():
    run()
