#!/usr/bin/env python3
"""Propagate function names between game versions via shared address-library IDs.

Builds that share one meh321 address-library ID namespace resolve the same ID
to a (usually different) RVA in each build, so a name known at one build's RVA
can be placed at the *exact* corresponding RVA in a sibling -- no byte-signature
guessing.  The shared groups are F4 NG/AE/1.11.221/1.11.240, Skyrim SE/VR, and
Skyrim AE 1.6.640/1.6.1170/1.7.104.  Skyrim SE and AE are DIFFERENT namespaces:
387k AE IDs also exist numerically in the SE database, but for none of the 930
CommonLibSSE ``RELOCATION_ID(se, ae)`` pairs does the AE ID resolve to the right
SE address, so an SE<->AE port by ID mis-places every name.  This is how a poorer decomp
(F4 221 was 36.8% named) inherits a richer one (AE reached 72%+ after the
IDA-name port).  Pick the game with ``--game`` (default f4).

It emits a CSV in the ``IDA_Functions`` shape (``Name;;;<target_rva>;<id>``)
plus a bound ``.identity.json`` sidecar, then hands off to
``apply_ida_csv_names.py`` -- so the actual mutation goes through the same
identity-gated, namespace-aware, ``--create-missing`` applier already in use.

Namespaces that do NOT share IDs (OG and VR are each disjoint from NG/AE/221)
are rejected: an ID means nothing across them, so porting would mis-place every
name.  Use byte-signature porting (``run_bytesig_port.py``) for those.

Nothing is guessed: a source RVA that several IDs share (identical-code
folding) has no unique ID and is dropped, a target RVA claimed by two different
names is dropped, vtable-slot placeholders (``X::FuncN``, ``X::Unk_XX``) are not
ported, and a name embedding the source function's own address
(``Unwind@1415c4354``, ``Foo_14053EB00``) is retargeted to the target address --
or dropped when the embedded address is not its own.

Two source modes:
  * ``--from-program <name>``   pull names from a sibling Ghidra program
  * ``--from-pdb <publics.txt>``  pull names from a PDB-publics dump (keyed by
                                  the source build's RVAs)

Usage:
  python port_names_by_id.py <project_dir> <project_name> \
      --source {ng,ae,221} --target {ng,ae,221} \
      (--from-program <PROGRAM> | --from-pdb <FILE>) \
      --target-program <PROGRAM> --target-exe <EXE> [--apply] [--create-missing]
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "scripts" / "commonlibsse"))
sys.path.insert(0, str(REPO / "scripts" / "core"))
from ghidra_project import open_program, open_user_project  # noqa: E402

_PDB_LINE = re.compile(r'^\s*public \[0x([0-9A-Fa-f]+)\]\s+(.*\S)\s*$')
# Slot-numbered vtable placeholders: the number is a build-specific slot.
SLOT_PLACEHOLDER_RE = re.compile(r"(?:^|::)(?:Func\d+(?:_v\d+)?|Unk_[0-9A-Fa-f]+)$")
_EMBEDDED_ADDRESS = re.compile(r"^(.*?)([_@])(14[0-9A-Fa-f]{7})$")
IMAGE_BASE = 0x140000000    # every F4 / Skyrim x64 build

# Per game: the GROUPS of builds that share one address-library ID namespace (an
# ID ports exactly only inside a group), and how each build maps onto the
# loader's per-build dict.  F4 OG/VR are intentionally absent -- use byte-sig
# porting there.  test_port_names_by_id.py checks every group, and every pair
# kept apart, against the address libraries themselves.
_GAMES = {
    "f4": {
        "groups": [{"ng", "ae", "221", "240"}],
        "attr": {"ng": "ng_db", "ae": "ae_db", "221": "db_221",
                 "240": "db_240"},
    },
    "skyrim": {
        "groups": [{"se", "vr"}, {"ae", "16640", "17104"}],
        "attr": {"se": "se_db", "ae": "ae_db", "vr": "vr_db",
                 "16640": "db_16640", "17104": "db_17104"},
    },
}


def shared_namespace(game, source, target):
    """True only when both builds sit in the same shared-ID group."""
    return any(source in group and target in group
               for group in _GAMES[game]["groups"])


def _load_module(rel_path, mod_name):
    """Load a repo module by explicit path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(mod_name, REPO / rel_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_library(game):
    if game == "f4":
        mod = _load_module("scripts/commonlibf4/address_library.py",
                            "f4_address_library")
        lib = mod.F4AddressLibrary()
        lib.load_all(str(REPO / "addresslibrary" / "f4"))
        return lib
    if game == "skyrim":
        mod = _load_module("scripts/commonlibsse/address_library.py",
                            "sse_address_library")
        lib = mod.AddressLibrary()
        lib.load_all(str(REPO / "addresslibrary"))
        return lib
    raise SystemExit("unknown game: " + game)


def _rva_to_id(db):
    """(RVA -> ID, ambiguous RVAs).  An RVA that several IDs share (identical
    code folding) has no unique ID: it is dropped, never first-wins (the same
    rule as ``commonlibsse/address_library.unique_reverse_ids``)."""
    reverse = {}
    ambiguous = set()
    for ident, rva in db.items():
        if rva in ambiguous:
            continue
        if rva in reverse:
            reverse.pop(rva)
            ambiguous.add(rva)
        else:
            reverse[rva] = ident
    return reverse, ambiguous


def port_name(name, source_rva, target_rva):
    """The name to place at ``target_rva``, or None when it must not travel.

    Slot placeholders carry a build-specific slot number.  A local name that
    embeds the source function's OWN address is rewritten to the target
    address (same separator and letter case); one embedding any other address
    names something else in the source build and is dropped.
    """
    if SLOT_PLACEHOLDER_RE.search(name):
        return None
    namespace, separator, local = name.rpartition("::")
    match = _EMBEDDED_ADDRESS.match(local)
    if match:
        if int(match.group(3), 16) != IMAGE_BASE + source_rva:
            return None
        digits = "{:X}".format(IMAGE_BASE + target_rva)
        if match.group(3) != match.group(3).upper():
            digits = digits.lower()
        local = match.group(1) + match.group(2) + digits
    return namespace + separator + local


def plan_rows(pairs, src_db, tgt_db):
    """CSV rows ``(name, '', '', target_rva_hex, id)`` plus drop statistics.

    Every target RVA receives at most one name: when different names claim
    it, all of them are dropped (no first-wins)."""
    reverse, ambiguous = _rva_to_id(src_db)
    stats = collections.Counter()
    claims = collections.defaultdict(dict)       # target rva -> {name: ids}
    for rva, name in pairs:
        ident = reverse.get(rva)
        if ident is None:
            stats["ambiguous-source-rva" if rva in ambiguous else "no-id"] += 1
            continue
        tgt_rva = tgt_db.get(ident)
        if tgt_rva is None:
            stats["id-absent-in-target"] += 1
            continue
        ported = port_name(str(name), rva, tgt_rva)
        if ported is None:
            stats["not-portable"] += 1
            continue
        claims[tgt_rva].setdefault(ported, set()).add(ident)
    rows = []
    for tgt_rva in sorted(claims):
        names = claims[tgt_rva]
        if len(names) != 1:
            stats["target-claimed-twice"] += sum(len(ids) for ids in names.values())
            continue
        (ported, ids), = names.items()
        rows.append((ported, "", "", "%X" % tgt_rva, str(min(ids))))
    return rows, stats


def _source_pairs_from_pdb(path):
    """[(rva, name), ...] from a PDB-publics dump."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            m = _PDB_LINE.match(line)
            if m:
                out.append((int(m.group(1), 16), m.group(2)))
    return out


def _source_pairs_from_program(project_dir, project_name, program_name):
    """[(rva, namespaced_name), ...] of every non-placeholder function."""
    ghidra_dir = Path(os.environ.get("GHIDRA_INSTALL_DIR") or
                      (REPO / "tools" / "ghidra"))
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_dir))
    import pyghidra
    pyghidra.start(install_dir=ghidra_dir)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = project_dir, project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    out = []
    with open_user_project(pdir, pname) as project:
        df = _walk(project.getProjectData().getRootFolder(), program_name)
        if df is None:
            raise SystemExit("source program not found: " + program_name)
        consumer = java.lang.Object()
        program = open_program(df, consumer, monitor, write=False)
        try:
            base = program.getImageBase().getOffset()
            for func in program.getFunctionManager().getFunctions(True):
                if func.getName().startswith(("FUN_", "sub_", "thunk_FUN_")):
                    continue
                out.append((func.getEntryPoint().getOffset() - base,
                            func.getName(True)))
        finally:
            program.release(consumer)
    return out


def _walk(folder, name):
    for f in folder.getFiles():
        if f.getName() == name:
            return f
    for sub in folder.getFolders():
        r = _walk(sub, name)
        if r is not None:
            return r
    return None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("--game", default="f4", choices=sorted(_GAMES))
    ap.add_argument("--source", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--from-program", help="source Ghidra program filename")
    ap.add_argument("--from-pdb", help="source PDB-publics dump file")
    ap.add_argument("--target-program", required=True,
                    help="target Ghidra program filename")
    ap.add_argument("--target-exe", required=True,
                    help="exact target executable, for identity binding")
    ap.add_argument("--out", help="CSV path (default under build/idres/)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--create-missing", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()

    game = _GAMES[args.game]
    for role, value in (("source", args.source), ("target", args.target)):
        if value not in game["attr"]:
            ap.error("{} build {!r} is unknown for {} (known: {})".format(
                role, value, args.game, sorted(game["attr"])))
    if args.source == args.target:
        ap.error("source and target are the same build")
    if not shared_namespace(args.game, args.source, args.target):
        ap.error("{} and {} do not share an address-library ID namespace "
                 "(shared groups: {}); an ID means nothing across them, so "
                 "use byte-signature porting".format(
                     args.source, args.target,
                     [sorted(group) for group in game["groups"]]))
    if not (bool(args.from_program) ^ bool(args.from_pdb)):
        ap.error("pass exactly one of --from-program / --from-pdb")

    lib = _load_library(args.game)
    src_db = getattr(lib, game["attr"][args.source])
    tgt_db = getattr(lib, game["attr"][args.target])

    if args.from_pdb:
        pairs = _source_pairs_from_pdb(args.from_pdb)
    else:
        pairs = _source_pairs_from_program(
            args.project_dir, args.project_name, args.from_program)
    print("source names: %d" % len(pairs))

    rows, dropped = plan_rows(pairs, src_db, tgt_db)
    print("mapped to %s RVAs via shared id: %d" % (args.target, len(rows)))
    if dropped:
        print("  dropped: " + ", ".join(
            "{}={}".format(k, v) for k, v in sorted(dropped.items())))

    out = Path(args.out) if args.out else (
        REPO / "build" / "idres" / "port_by_id" /
        ("%s_%s_to_%s.csv" % (args.game, args.source, args.target)))
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Name", "OG_Addr", "OG_REL_ID", "AE_Addr", "AE_REL_ID"])
        writer.writerows(rows)
    print("wrote %s" % out)

    # Bind evidence + hand off to the identity-gated applier.
    bind = [sys.executable, str(REPO / "scripts" / "core" / "bind_evidence.py"),
            str(out), "--exe", args.target_exe,
            "--kind", "%s_%s_to_%s" % (args.game, args.source, args.target),
            "--coordinate", "RVA", "--program-name", args.target_program]
    print("+ " + " ".join(bind))
    result = subprocess.run(bind, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sha = ""
    for line in result.stdout.splitlines():
        if line.startswith("target sha256:"):
            sha = line.split(":", 1)[1].strip()
    if not sha:
        raise SystemExit("bind_evidence did not report a target sha256")

    apply_cmd = [sys.executable,
                 str(HERE / "apply_ida_csv_names.py"),
                 args.project_dir, args.project_name, args.target_program,
                 str(out), "--version", "ae",  # column carries target RVA
                 "--target-sha256", sha]
    if args.apply:
        apply_cmd.append("--apply")
    if args.create_missing:
        # the applier checks .pdata starts of this exact (bound) executable
        apply_cmd += ["--create-missing", "--target-pe", args.target_exe]
    if args.overwrite:
        apply_cmd.append("--overwrite")
    print("+ " + " ".join(apply_cmd))
    sys.exit(subprocess.run(apply_cmd).returncode)


if __name__ == "__main__":
    main()
