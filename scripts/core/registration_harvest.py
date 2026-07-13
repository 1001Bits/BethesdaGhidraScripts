"""P-code registry harvester for Papyrus, console, Scaleform and factories.

The pass looks for a repeated direct registration call receiving exactly one
identifier-like string and one executable function pointer.  It never scans
raw instruction bytes.  Candidates are aggregated by registration callee and
must be one-to-one before they can be applied.  Evidence is always written to
CSV; mutation is dry-run unless ``BGS_ENRICH_APPLY=go``.
"""

import collections
import csv
import os
import re
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from evidence_identity import bind_evidence, program_sha256  # noqa: E402


APPLY = os.environ.get("BGS_ENRICH_APPLY", "dry").lower() == "go"
MAX_FUNCS = int(os.environ.get("BGS_REGISTRY_MAX_FUNCS", "0") or 0)
MIN_SITES = int(os.environ.get("BGS_REGISTRY_MIN_SITES", "4") or 4)
MARKER = "[BGS:registry]"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_:.<>-]{1,95}$")
_DEFAULT_FUNCTION = re.compile(r"^(?:FUN|thunk_FUN)_[0-9A-Fa-f]+$")


def _same_address_space(address, address_space):
    try:
        return bool(address.getAddressSpace().equals(address_space))
    except Exception:
        try:
            return address.getAddressSpace() == address_space
        except Exception:
            return False


def _is_default_image_address(address, address_space, memory,
                              image_start, image_end):
    if address is None or not _same_address_space(address, address_space):
        return False
    try:
        offset = int(address.getOffset())
    except Exception:
        return False
    return (image_start <= offset < image_end and
            bool(memory.contains(address)))


def _is_overwritable(function, default_source):
    symbol = function.getSymbol()
    return bool(symbol is not None and symbol.getSource() == default_source and
                _DEFAULT_FUNCTION.fullmatch(function.getName() or ""))


def aggregate_observations(observations, min_sites=4):
    """Return unambiguous registry rows from observation dictionaries."""
    by_callee = collections.defaultdict(list)
    for row in observations:
        by_callee[row["callee"]].append(row)
    accepted = []
    global_names_by_handler = collections.defaultdict(set)
    global_handlers_by_name = collections.defaultdict(set)
    for row in observations:
        global_names_by_handler[row["handler"]].add(row["name"])
        global_handlers_by_name[row["name"]].add(row["handler"])
    for callee, rows in by_callee.items():
        callsites = {row["callsite"] for row in rows}
        names = {row["name"] for row in rows}
        if len(callsites) < min_sites or len(names) < min_sites:
            continue
        argument_pairs = {
            (row.get("name_arg"), row.get("handler_arg")) for row in rows
        }
        # A direct registration API has a stable calling convention.  If the
        # apparent identifier/handler move between argument positions, these
        # observations do not describe one proven registry contract.
        if (len(argument_pairs) != 1 or
                None in next(iter(argument_pairs))):
            continue
        names_by_handler = collections.defaultdict(set)
        handlers_by_name = collections.defaultdict(set)
        for row in rows:
            names_by_handler[row["handler"]].add(row["name"])
            handlers_by_name[row["name"]].add(row["handler"])
        for row in rows:
            if len(names_by_handler[row["handler"]]) != 1:
                continue
            if len(handlers_by_name[row["name"]]) != 1:
                continue
            # Different registration APIs can reuse a handler or identifier.
            # A global rename is safe only when the association remains
            # one-to-one across every registry family we observed.
            if len(global_names_by_handler[row["handler"]]) != 1:
                continue
            if len(global_handlers_by_name[row["name"]]) != 1:
                continue
            confidence = "high" if len(callsites) >= max(8, min_sites) else "medium"
            accepted.append(dict(row, confidence=confidence,
                                 registry_sites=len(callsites)))
    unique = {}
    for row in accepted:
        unique[(row["callee"], row["name"], row["handler"])] = row
    return sorted(unique.values(), key=lambda row: (
        row["callee"], row["name"], row["handler"]))


def _resolve_address(vn, address_space, memory, image_start=0,
                     image_end=(1 << 64), depth=0):
    from ghidra.program.model.pcode import PcodeOp
    if vn is None or depth > 6:
        return None
    if vn.isAddress():
        address = vn.getAddress()
        return address if _is_default_image_address(
            address, address_space, memory, image_start, image_end) else None
    if vn.isConstant():
        try:
            address = address_space.getAddress(vn.getOffset())
        except Exception:
            return None
        return address if _is_default_image_address(
            address, address_space, memory, image_start, image_end) else None
    definition = vn.getDef()
    if definition is None:
        return None
    opcode = definition.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.CAST):
        return _resolve_address(
            definition.getInput(0), address_space, memory,
            image_start, image_end, depth + 1)
    if opcode in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
        base = _resolve_address(
            definition.getInput(0), address_space, memory,
            image_start, image_end, depth + 1)
        delta = definition.getInput(1)
        if base is None or not delta.isConstant():
            return None
        try:
            result = base.add(delta.getOffset())
        except Exception:
            return None
        return result if _is_default_image_address(
            result, address_space, memory, image_start, image_end) else None
    if opcode == PcodeOp.PTRADD:
        base = _resolve_address(
            definition.getInput(0), address_space, memory,
            image_start, image_end, depth + 1)
        index = definition.getInput(1)
        scale = definition.getInput(2)
        if (base is None or not index.isConstant() or
                not scale.isConstant()):
            return None
        try:
            result = base.add(index.getOffset() * scale.getOffset())
        except Exception:
            return None
        return result if _is_default_image_address(
            result, address_space, memory, image_start, image_end) else None
    return None


def _read_identifier(memory, address):
    block = memory.getBlock(address)
    if block is None or block.isExecute():
        return None
    raw = bytearray()
    for index in range(97):
        try:
            value = memory.getByte(address.add(index)) & 0xFF
        except Exception:
            return None
        if value == 0:
            break
        if value < 0x20 or value > 0x7E:
            return None
        raw.append(value)
    if not raw or len(raw) > 96:
        return None
    try:
        value = raw.decode("ascii")
    except Exception:
        return None
    return value if _IDENT.match(value) else None


def _target_sha(program):
    # This also rejects disagreement between Ghidra's import metadata and a
    # BGS target manifest instead of silently preferring either assertion.
    return program_sha256(program)


def _append_comment(listing, address, text):
    from ghidra.program.model.listing import CodeUnit
    old = listing.getComment(CodeUnit.PLATE_COMMENT, address) or ""
    lines = [line for line in old.splitlines()
             if not line.startswith(MARKER)]
    lines.append(text)
    listing.setComment(address, CodeUnit.PLATE_COMMENT,
                       "\n".join(line for line in lines if line))


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import SourceType

    program = currentProgram  # noqa: F821
    # Establish exact target provenance before any output or Program mutation.
    # A detached/legacy Program with no executable SHA-256 is not a safe
    # source of persistent enrichment evidence.
    target_sha = _target_sha(program)
    from binary_identity import inspect_pe, verify_ghidra_program
    backing_manifest = inspect_pe(str(program.getExecutablePath()))
    verify_ghidra_program(program, [backing_manifest])
    memory = program.getMemory()
    fm = program.getFunctionManager()
    listing = program.getListing()
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    image_start = int(backing_manifest["image_base"])
    image_end = image_start + int(backing_manifest["image_size"])
    observations = []
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    scanned = 0
    try:
        for function in fm.getFunctions(True):
            if MAX_FUNCS and scanned >= MAX_FUNCS:
                break
            scanned += 1
            try:
                if not _is_default_image_address(
                        function.getEntryPoint(), address_space, memory,
                        image_start, image_end):
                    continue
                result = decompiler.decompileFunction(function, 30, monitor)  # noqa: F821
                if not result or not result.decompileCompleted():
                    continue
                for op in result.getHighFunction().getPcodeOps():
                    if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 3:
                        continue
                    target = op.getInput(0)
                    if not target.isAddress():
                        continue
                    target_address = target.getAddress()
                    callsite_address = op.getSeqnum().getTarget()
                    if (not _is_default_image_address(
                            target_address, address_space, memory,
                            image_start, image_end) or
                            not _is_default_image_address(
                                callsite_address, address_space, memory,
                                image_start, image_end)):
                        continue
                    callee_fn = fm.getFunctionAt(target_address)
                    if callee_fn is None:
                        continue
                    names = []
                    handlers = []
                    for index in range(1, op.getNumInputs()):
                        address = _resolve_address(
                            op.getInput(index), address_space, memory,
                            image_start, image_end)
                        if address is None:
                            continue
                        name = _read_identifier(memory, address)
                        if name:
                            names.append((index, name, address))
                        block = memory.getBlock(address)
                        if block is not None and block.isExecute():
                            handler = fm.getFunctionAt(address)
                            if handler is not None and address != callee_fn.getEntryPoint():
                                handlers.append((index, handler))
                    if len(names) != 1 or len(handlers) != 1:
                        continue
                    name_arg, name, string_addr = names[0]
                    handler_arg, handler = handlers[0]
                    observations.append({
                        "callee": callee_fn.getEntryPoint().getOffset(),
                        "callsite": op.getSeqnum().getTarget().getOffset(),
                        "caller": function.getEntryPoint().getOffset(),
                        "name_arg": name_arg,
                        "handler_arg": handler_arg,
                        "name": name,
                        "string": string_addr.getOffset(),
                        "handler": handler.getEntryPoint().getOffset(),
                    })
            except Exception:
                continue
    finally:
        decompiler.dispose()

    rows = aggregate_observations(observations, MIN_SITES)
    out_path = os.environ.get("BGS_REGISTRY_CSV") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "refs",
        "registrations_%s.csv" % program.getName().replace(".", "_"))
    directory = os.path.dirname(out_path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["program", "target_sha256", "address_coordinate",
                         "registry_callee", "callsite", "caller", "name_arg",
                         "handler_arg", "name", "string_address", "handler",
                         "confidence", "registry_sites"])
        for row in rows:
            writer.writerow([
                program.getName(), target_sha, "VA", "0x%X" % row["callee"],
                "0x%X" % row["callsite"], "0x%X" % row["caller"],
                row["name_arg"], row["handler_arg"], row["name"],
                "0x%X" % row["string"],
                "0x%X" % row["handler"], row["confidence"],
                row["registry_sites"],
            ])
    bind_evidence(out_path, program, "registration_evidence", "VA")

    applied = 0
    success = False
    had_parent_transaction = (
        APPLY and program.getCurrentTransactionInfo() is not None)
    tx = program.startTransaction("BGS registration enrichment") if APPLY else None
    try:
        if APPLY:
            for row in rows:
                if row["confidence"] != "high":
                    continue
                address = address_space.getAddress(row["handler"])
                block = memory.getBlock(address)
                function = fm.getFunctionAt(address)
                if (not _is_default_image_address(
                        address, address_space, memory, image_start, image_end) or
                        block is None or not block.isExecute() or function is None):
                    continue
                note = "%s name=%s registry=0x%X sites=%d" % (
                    MARKER, row["name"], row["callee"], row["registry_sites"])
                _append_comment(listing, address, note)
                if _is_overwritable(function, SourceType.DEFAULT):
                    safe = re.sub(r"[^A-Za-z0-9_]", "_", row["name"])
                    function.setName("Registered_" + safe, SourceType.ANALYSIS)
                applied += 1
        success = True
    finally:
        if tx is not None:
            committed = bool(program.endTransaction(tx, success))
            if success and not had_parent_transaction and not committed:
                raise RuntimeError(
                    "registration enrichment transaction did not commit")

    print("registry-harvest (%s): scanned=%d raw=%d accepted=%d %s=%d -> %s" % (
        program.getName(), scanned, len(observations), len(rows),
        "applied" if APPLY else "would-apply-high",
        applied if APPLY else sum(1 for row in rows
                                  if row["confidence"] == "high"), out_path))


if "currentProgram" in globals():
    run()
