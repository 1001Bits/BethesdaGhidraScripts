#!/usr/bin/env python3
r"""Apply an ID-keyed Skyrim name table (``kind,name,ae_id,se_id``) to a program.

Community tables such as ``Skyrim_FunctionNames_and_IDs_SE_AE.csv`` pair a
name with its Address Library ID in the SE namespace (SE 1.5.97 / VR 1.4.15)
and/or the AE namespace (1.6.640 / 1.6.1170 / 1.7.104).  This applier uses
ONLY the column of the target's own namespace -- the two namespaces are
disjoint and must never be mixed -- and admits a row only on evidence read
from the target program itself:

* ``func``      the ID must resolve to an analyzed function ENTRY (never an
                address inside another function); its name must still be a
                DEFAULT placeholder.  A missing function is created only at a
                linker ``.pdata`` start of the exact target PE (``--target-pe``),
                or -- with ``--create-leaf`` -- at a referenced leaf address
                outside every ``.pdata`` range whose new body ends in a return
                before the next function (otherwise it is removed again).
* ``VTABLE_X``  the qword before the table must point to an MSVC Complete
                Object Locator whose TypeDescriptor names class ``X``.
* ``RTTI_X``    the address must BE the TypeDescriptor of class ``X``.
* ``NiRTTI_X``  the object's name pointer must point to the string ``X``.
* ``gs_X``      a game ``Setting``: its key pointer (+0x10) must point to ``X``.
* ``ini_X_Y``   an INI setting: its key pointer must point to ``X:Y``.
* anything else (``g_*`` …) has no byte evidence and is skipped unless
  ``--include-unverified-data`` is given (still only in non-executable data).

Rows whose ID claims several different names, rows whose SE and AE IDs are
the same number (the signature of an SE ID copied into the AE column), and AE
rows that contradict a CommonLibSSE ``RELOCATION_ID(se, ae)`` pair are
refused.  Existing names are never replaced unless they are placeholders --
``FUN_``/``sub_`` leaves, or a vtable-walk ``Class::FuncN`` slot whose class
matches the table's -- and never when the symbol is USER_DEFINED (reported as
``placeholder-user-defined``) unless the owner opts in with
``--upgrade-user-defined``; a real USER_DEFINED name is never touched, flag or
not.  Agreement with real existing names is counted
as a precision signal.  Names are applied with source ANALYSIS.
Dry run by default; every decision is written to an evidence CSV under the
gitignored ``build/evidence/``.

Usage (Ghidra GUI closed)::

    python scripts/commonlibsse/apply_id_name_table.py --table NAMES.csv \
        --build se --program-path /Skyrim/SkyrimSE_1_5_97.exe \
        --target-pe exes/skyrim/se/SkyrimSE.exe [--apply]
"""
from __future__ import annotations

import argparse
import bisect
import collections
import csv
import os
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "core"))
sys.path.insert(0, str(HERE))
from address_library import AddressLibrary  # noqa: E402
from ghidra_project import find_program, open_program, open_user_project  # noqa: E402
from pyghidra_result import end_outer_transaction  # noqa: E402
import vtable_label_check as vlc  # noqa: E402

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO / "tools" / "ghidra"))
# build -> (address-library attribute, ID column of that namespace)
BUILDS = {
    "se": ("se_db", "se_id"), "vr": ("vr_db", "se_id"),
    "ae": ("ae_db", "ae_id"), "16640": ("db_16640", "ae_id"),
    "17104": ("db_17104", "ae_id"),
}
PLACEHOLDER_RE = re.compile(r"^(?:FUN_|sub_|thunk_FUN_|thunk_sub_)[0-9A-Fa-f]+$")
# Vtable-walk placeholders (``Class::Func12``, ``Class::Func3_v8``) and
# CommonLib's ``Class::Unk_A3``: a slot number, not a name.
SLOT_PLACEHOLDER_RE = re.compile(r"^(?:Func\d+(?:_v\d+)?|Unk_[0-9A-Fa-f]+)$")
SETTING_KEY_OFFSET = 0x10          # RE::Setting { vtbl; value; const char* key }
MAX_LEAF_BYTES = 0x400             # leaf functions without unwind data are small


class PdataIndex:
    """Function starts and every unwind range of the target PE's ``.pdata``."""

    def __init__(self, runtime_functions=(), is_start=lambda row: True):
        self.starts = set()
        ranges = []
        for row in runtime_functions:
            begin, end = int(row["begin_rva"]), int(row["end_rva"])
            ranges.append((begin, end))
            if is_start(row):
                self.starts.add(begin)
        ranges.sort()
        self._begins = [begin for begin, _end in ranges]
        self._ranges = ranges

    def __contains__(self, rva):
        return rva in self.starts

    def overlaps(self, lo, hi):
        """True when [lo, hi) touches any unwind range."""
        i = bisect.bisect_right(self._begins, lo) - 1
        if i >= 0 and self._ranges[i][1] > lo:
            return True
        j = bisect.bisect_left(self._begins, lo)
        return j < len(self._begins) and self._begins[j] < hi


def read_table(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    missing = {"kind", "name", "ae_id", "se_id"} - set(rows[0] if rows else ())
    if missing:
        raise SystemExit("table lacks columns: {}".format(sorted(missing)))
    return rows


def commonlib_pairs():
    """{se_id: ae_id} from CommonLibSSE ``RELOCATION_ID(se, ae)``."""
    pairs = {}
    root = REPO / "extern" / "CommonLibSSE"
    pattern = re.compile(r"RELOCATION_ID\(\s*(\d+)\s*,\s*(\d+)\s*\)")
    for path in list(root.rglob("*.h")) + list(root.rglob("*.cpp")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in pattern.finditer(text):
            pairs[int(match.group(1))] = int(match.group(2))
    return pairs


def select_rows(rows, column, clib_pairs):
    """[(kind, name, id)] for the target namespace, plus refusal counts."""
    refused = collections.Counter()
    by_id = collections.defaultdict(set)
    chosen = []
    for row in rows:
        value = (row.get(column) or "").strip()
        if not value:
            continue
        ident = int(value)
        se_id, ae_id = (row.get("se_id") or "").strip(), (row.get("ae_id") or "").strip()
        if se_id and ae_id and se_id == ae_id:
            refused["se_id-equals-ae_id"] += 1
            continue
        if column == "ae_id" and se_id and int(se_id) in clib_pairs \
                and clib_pairs[int(se_id)] != ident:
            refused["contradicts-commonlib-pair"] += 1
            continue
        kind = row["kind"].strip()
        chosen.append((kind, row["name"].strip(), ident))
        if kind == "func":
            by_id[ident].add(row["name"].strip())
    ambiguous = {ident for ident, names in by_id.items() if len(names) > 1}
    out = []
    for kind, name, ident in chosen:
        if kind == "func" and ident in ambiguous:
            refused["func-id-claims-several-names"] += 1
            continue
        out.append((kind, name, ident))
    return out, refused


def _program_image(program):
    """SectionImage of the program's initialized non-executable blocks."""
    import jpype
    base = program.getImageBase().getOffset()
    sections = []
    for block in program.getMemory().getBlocks():
        if block.isExecute() or not block.isInitialized() or block.isOverlay():
            continue
        size = int(block.getSize())
        buffer = jpype.JArray(jpype.JByte)(size)
        block.getBytes(block.getStart(), buffer)
        sections.append((block.getStart().getOffset() - base, bytes(buffer)))
    max_rva = max((rva + len(data) for rva, data in sections), default=0)
    return vlc.SectionImage(base, max_rva, sections)


def _pointer_string(image, rva):
    raw = image.read(rva, 8)
    if raw is None:
        return None
    pointer = struct.unpack("<Q", raw)[0]
    if not image.image_base <= pointer < image.image_base + image.image_size:
        return None
    text = image.read_cstring(pointer - image.image_base, 512)
    return None if text is None else text.decode("latin-1")


def data_evidence(name, rva, image):
    """('ok'|reason) for one non-RTTI data row."""
    if name.startswith("NiRTTI_"):
        # NiRTTI objects are filled by static initialisers at run time: in the
        # image the name pointer is still zero, so there is nothing to check.
        raw = image.read(rva, 8)
        if raw is None or raw == bytes(8):
            return "unverifiable"
        return "ok" if _pointer_string(image, rva) == name[len("NiRTTI_"):] else "nirtti-name-mismatch"
    if name.startswith("gs_"):
        return "ok" if _pointer_string(image, rva + SETTING_KEY_OFFSET) == name[3:] else "setting-key-mismatch"
    if name.startswith("ini_"):
        key = _pointer_string(image, rva + SETTING_KEY_OFFSET)
        if key is not None and key.replace(":", "_") == name[4:]:
            return "ok"
        return "ini-key-mismatch"
    return "unverifiable"


def name_action(current, name, is_default, is_user_defined, upgrade_user_defined=False):
    """Decision for a table name against a function's current full name."""
    if current == name:
        return "already-same"
    if is_default:
        return "rename"
    current_leaf, table_leaf = current.split("::")[-1], name.split("::")[-1]
    placeholder = None
    if PLACEHOLDER_RE.match(current_leaf):
        placeholder = "rename"
    elif current_leaf == table_leaf:
        return "agrees-other-namespace"
    elif (SLOT_PLACEHOLDER_RE.match(current_leaf) and not SLOT_PLACEHOLDER_RE.match(table_leaf)
          and current.split("::")[:-1] == name.split("::")[:-1]):
        # Our vtable walk named this slot ``Class::FuncN``; the table knows
        # the method's real name in the same class.
        placeholder = "upgrade-placeholder"
    if placeholder is None:
        return "differs-kept"
    if is_user_defined and not upgrade_user_defined:
        return "placeholder-user-defined"
    return placeholder


def _leaf_candidate(program, address, rva, pdata):
    """A referenced, undefined executable address outside every unwind range."""
    block = program.getMemory().getBlock(address)
    if block is None or not block.isExecute() or not block.isInitialized():
        return False
    if program.getListing().getDefinedDataContaining(address) is not None:
        return False
    if not pdata.starts or pdata.overlaps(rva, rva + 1):
        return False
    return program.getReferenceManager().getReferenceCountTo(address) > 0


def plan(program, rows, image, pdata_starts, include_unverified, create_leaf=False,
         upgrade_user_defined=False):
    from ghidra.program.model.symbol import SourceType
    base = program.getImageBase()
    functions = program.getFunctionManager()
    table = program.getSymbolTable()
    memory = program.getMemory()
    decisions = []
    vt_rows, rtti_rows = [], []
    for kind, name, ident, rva in rows:
        if kind == "func":
            address = base.add(rva)
            function = functions.getFunctionAt(address)
            if function is None:
                containing = functions.getFunctionContaining(address)
                if containing is not None:
                    decisions.append((kind, name, ident, rva, "inside-function",
                                      str(containing.getName(True)), "", None))
                elif rva in pdata_starts:
                    decisions.append((kind, name, ident, rva, "create", "", "", None))
                elif isinstance(pdata_starts, PdataIndex) and \
                        _leaf_candidate(program, address, rva, pdata_starts):
                    decisions.append((kind, name, ident, rva,
                                      "create-leaf" if create_leaf else "leaf-candidate",
                                      "", "", None))
                else:
                    decisions.append((kind, name, ident, rva, "no-function", "", "", None))
                continue
            # Older passes stored ``Class::Func2`` as one literal Global name,
            # so judge the full path string, never the bare symbol name.
            current = str(function.getName(True))
            source = function.getSymbol().getSource()
            action = name_action(current, name, source == SourceType.DEFAULT,
                                 source == SourceType.USER_DEFINED, upgrade_user_defined)
            decisions.append((kind, name, ident, rva, action, current, str(source),
                              function if action in ("rename", "upgrade-placeholder") else None))
            continue
        if name.startswith("VTABLE_"):
            vt_rows.append((name, rva, None))
            continue
        if name.startswith("RTTI_"):
            rtti_rows.append((name, rva, None))
            continue
        evidence = data_evidence(name, rva, image)
        if evidence == "unverifiable" and include_unverified:
            block = memory.getBlock(base.add(rva))
            evidence = "ok" if block is not None and not block.isExecute() else "not-data"
        decisions.append((kind, name, ident, rva, "label" if evidence == "ok" else evidence, "", "", None))
    for result in (vlc.check_vtable_labels(vt_rows, image), vlc.check_rtti_labels(rtti_rows, image)):
        ids = {}
        for kind, name, ident, rva in rows:
            ids.setdefault((name, rva), ident)
        for verdict in result.verdicts:
            ok = verdict.verdict == vlc.MATCH and not result.is_dropped(verdict.name, verdict.rva)
            decisions.append(("data", verdict.name, ids.get((verdict.name, verdict.rva)), verdict.rva,
                              "label" if ok else "rtti-" + verdict.verdict,
                              verdict.decorated or verdict.reason, "", None))
    # Labels: skip when the exact name already sits at the address.
    final = []
    for decision in decisions:
        kind, name, ident, rva, action, detail, source, target = decision
        if action == "label":
            address = base.add(rva)
            existing = [str(s.getName(True)) for s in table.getSymbols(address)]
            if name in existing:
                decision = (kind, name, ident, rva, "already-same", name, "", None)
        final.append(decision)
    return final


def _split(name):
    parts = [part for part in name.split("::") if part]
    return tuple(parts[:-1]), parts[-1]


def _namespace(program, parts):
    from ghidra.program.model.symbol import SourceType
    table = program.getSymbolTable()
    namespace = program.getGlobalNamespace()
    for part in parts:
        child = table.getNamespace(part, namespace)
        if child is None:
            child = table.createNameSpace(namespace, part, SourceType.ANALYSIS)
        namespace = child
    return namespace


def _create_leaf(program, address, rva, pdata, monitor):
    """Create a leaf function and keep it only if its body is plausible."""
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    functions = program.getFunctionManager()
    listing = program.getListing()
    # Every instruction this call disassembles is cleared again on refusal,
    # not just the first one: a refused leaf leaves the listing as it was.
    disassembled = None
    if listing.getInstructionAt(address) is None:
        command = DisassembleCommand(address, None, True)
        command.applyTo(program, monitor)
        disassembled = command.getDisassembledAddressSet()
    if listing.getInstructionAt(address) is None:
        return "leaf-no-instruction"
    if not CreateFunctionCmd(address).applyTo(program, monitor):
        reason = "leaf-create-failed"
    else:
        function = functions.getFunctionAt(address)
        body = function.getBody()
        lo, hi = body.getMinAddress(), body.getMaxAddress()
        later = functions.getFunctions(address.add(1), True)
        following = later.next() if later.hasNext() else None
        terminal = any(inst.getFlowType().isTerminal()
                       for inst in listing.getInstructions(body, True))
        span = hi.subtract(address) + 1
        if lo != address or span > MAX_LEAF_BYTES or not terminal:
            reason = "leaf-implausible-body"
        elif following is not None and hi.compareTo(following.getEntryPoint()) >= 0:
            reason = "leaf-runs-into-next-function"
        elif pdata.overlaps(rva, rva + span):
            reason = "leaf-overlaps-pdata"
        else:
            return None
        functions.removeFunction(address)
    if disassembled is not None:
        for span_range in disassembled.getAddressRanges():
            listing.clearCodeUnits(span_range.getMinAddress(), span_range.getMaxAddress(), False)
    return reason


def apply(program, decisions, monitor, pdata=None):
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.symbol import SourceType
    base = program.getImageBase()
    functions = program.getFunctionManager()
    listing = program.getListing()
    table = program.getSymbolTable()
    done = collections.Counter()
    errors = []
    for kind, name, ident, rva, action, detail, source, target in decisions:
        if action not in ("rename", "upgrade-placeholder", "create", "create-leaf", "label"):
            continue
        address = base.add(rva)
        try:
            parts, local = _split(name)
            if action == "create":
                if functions.getFunctionContaining(address) is not None:
                    done["create-skipped-now-inside"] += 1
                    continue
                if listing.getInstructionAt(address) is None:
                    DisassembleCommand(address, None, True).applyTo(program, monitor)
                if not CreateFunctionCmd(address).applyTo(program, monitor):
                    raise RuntimeError("CreateFunctionCmd failed")
                target = functions.getFunctionAt(address)
            if action == "create-leaf":
                if functions.getFunctionContaining(address) is not None:
                    done["create-skipped-now-inside"] += 1
                    continue
                refused = _create_leaf(program, address, rva, pdata, monitor)
                if refused:
                    done[refused] += 1
                    continue
                target = functions.getFunctionAt(address)
            if action in ("rename", "upgrade-placeholder", "create", "create-leaf"):
                target.getSymbol().setNameAndNamespace(local, _namespace(program, parts),
                                                       SourceType.ANALYSIS)
            else:
                symbol = table.createLabel(address, local, _namespace(program, parts),
                                           SourceType.ANALYSIS)
                primary = table.getPrimarySymbol(address)
                if primary is not None and primary.getSource() == SourceType.DEFAULT:
                    symbol.setPrimary()
            done[action] += 1
        except Exception as error:  # noqa: BLE001 -- counted, budgeted
            done["error"] += 1
            if len(errors) < 10:
                errors.append("{} {} @0x{:X}: {}".format(action, name, rva, error))
    budget = max(25, sum(done.values()) // 100)
    if done["error"] > budget:
        raise RuntimeError("{} applications failed (budget {}): {}".format(
            done["error"], budget, "; ".join(errors)))
    return done, errors


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", required=True)
    ap.add_argument("--build", required=True, choices=sorted(BUILDS))
    ap.add_argument("--program-path", required=True)
    ap.add_argument("--target-pe", help="exact target PE: verifies identity and "
                    "allows creating functions at its .pdata starts")
    ap.add_argument("--include-unverified-data", action="store_true")
    ap.add_argument("--upgrade-user-defined", action="store_true",
                    help="owner-approved: also replace USER_DEFINED placeholder "
                    "names (Class::FuncN, Class::sub_X); real names stay")
    ap.add_argument("--create-leaf", action="store_true",
                    help="also create referenced leaf functions outside .pdata "
                    "(needs --target-pe)")
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--evidence", help="CSV path (default build/evidence/...)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    db_attr, column = BUILDS[args.build]
    library = AddressLibrary()
    library.load_all(str(REPO / "addresslibrary"))
    db = getattr(library, db_attr)
    rows, refused = select_rows(read_table(args.table), column, commonlib_pairs())
    resolved = []
    for kind, name, ident in rows:
        rva = db.get(ident)
        if rva is None:
            refused["id-absent-in-target"] += 1
            continue
        resolved.append((kind, name, ident, int(rva)))
    print("table: {} rows for {} via {} (refused: {})".format(
        len(resolved), args.build, column, dict(refused)))

    pdata_starts = PdataIndex()
    if args.target_pe:
        from pe_unwind import extract_runtime_functions, is_function_start
        pdata_starts = PdataIndex(
            extract_runtime_functions(args.target_pe)["runtime_functions"], is_function_start)
    elif args.create_leaf:
        raise SystemExit("--create-leaf needs --target-pe")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA_DIR)
    launcher.add_vmargs("-Xmx4g")
    launcher.start()
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    from binary_identity import inspect_pe, verify_ghidra_program

    monitor = ConsoleTaskMonitor()
    evidence = Path(args.evidence) if args.evidence else (
        REPO / "build" / "evidence" / "id_name_table_{}.csv".format(args.build))
    if args.apply and evidence.exists():
        # An apply record is the undo record: a rerun never overwrites it.
        from datetime import datetime, timezone
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence = evidence.with_name("{}.{}{}".format(evidence.stem, stamp, evidence.suffix))
    with open_user_project(args.project_dir, args.project_name) as project:
        domain_file = find_program(project.getProjectData().getRootFolder(), args.program_path)
        if domain_file is None:
            raise SystemExit("{} is not in the project".format(args.program_path))
        consumer = java.lang.Object()
        program = open_program(domain_file, consumer, monitor, write=args.apply)
        try:
            if args.target_pe:
                verify_ghidra_program(program, [inspect_pe(args.target_pe)])
            decisions = plan(program, resolved, _program_image(program), pdata_starts,
                             args.include_unverified_data, args.create_leaf,
                             args.upgrade_user_defined)
            counts = collections.Counter(d[4] for d in decisions)
            done = collections.Counter()
            if args.apply and (counts["rename"] or counts["create"] or counts["label"]
                               or counts["upgrade-placeholder"] or counts["create-leaf"]):
                tx = program.startTransaction("Apply ID name table")
                commit = False
                try:
                    done, errors = apply(program, decisions, monitor, pdata_starts)
                    for line in errors:
                        print("  FAILED " + line)
                    commit = True
                finally:
                    end_outer_transaction(program, tx, commit, "ID name table")
                program.save("ID name table ({})".format(Path(args.table).name), monitor)
        finally:
            program.release(consumer)

    evidence.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["kind", "name", "id", "rva", "decision", "current_or_detail", "source"])
        for kind, name, ident, rva, action, detail, source, _t in sorted(
                decisions, key=lambda d: (d[4], d[1])):
            writer.writerow([kind, name, ident, "0x%X" % rva, action, detail, source])
    # Precision against REAL existing names only; placeholders carry no claim.
    judged = counts["already-same"] + counts["agrees-other-namespace"] + counts["differs-kept"]
    print("{} {} ({}):".format("APPLIED" if args.apply else "DRY-RUN", args.program_path, args.build))
    for action, count in counts.most_common():
        print("  {:<28} {}".format(action, count))
    if judged:
        print("  agreement with existing names: {:.1%} ({} of {})".format(
            (judged - counts["differs-kept"]) / judged, judged - counts["differs-kept"], judged))
    if args.apply:
        print("  applied: " + ", ".join("{}={}".format(k, v) for k, v in sorted(done.items())))
    print("  evidence -> {}".format(evidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
