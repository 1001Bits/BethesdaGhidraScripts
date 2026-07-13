#!/usr/bin/env python3
"""Propagate function names between game versions via shared address-library IDs.

F4's NG/AE/1.11.221 and Skyrim's SE/AE/VR each share one meh321 address-library
ID namespace: the same ID resolves to a (usually different) RVA in each build,
so a name known at one build's RVA can be placed at the *exact* corresponding
RVA in a sibling -- no byte-signature guessing.  This is how a poorer decomp
(F4 221 was 36.8% named) inherits a richer one (AE reached 72%+ after the
IDA-name port).  Pick the game with ``--game`` (default f4).

It emits a CSV in the ``IDA_Functions`` shape (``Name;;;<target_rva>;<id>``)
plus a bound ``.identity.json`` sidecar, then hands off to
``apply_ida_csv_names.py`` -- so the actual mutation goes through the same
identity-gated, namespace-aware, ``--create-missing`` applier already in use.

Namespaces that do NOT share IDs (OG and VR are each disjoint from NG/AE/221)
are rejected: an ID means nothing across them, so porting would mis-place every
name.  Use byte-signature porting (``run_bytesig_port.py``) for those.

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

_PDB_LINE = re.compile(r'^\s*public \[0x([0-9A-Fa-f]+)\]\s+(.*\S)\s*$')

# Per game: the builds that share ONE address-library ID namespace (so an ID
# ports exactly), and how each maps onto the loader's per-build dict.  OG/VR
# (F4) are each disjoint and intentionally absent -- use byte-sig porting there.
_GAMES = {
    "f4": {
        "shared": {"ng", "ae", "221"},
        "attr": {"ng": "ng_db", "ae": "ae_db", "221": "db_221"},
    },
    "skyrim": {
        "shared": {"se", "ae", "vr"},
        "attr": {"se": "se_db", "ae": "ae_db", "vr": "vr_db"},
    },
}


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
    out = {}
    for ident, rva in db.items():
        out.setdefault(rva, ident)
    return out


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
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(REPO / "tools" / "ghidra"))
    import pyghidra
    pyghidra.start(install_dir=REPO / "tools" / "ghidra")
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = project_dir, project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    out = []
    with pyghidra.open_project(pdir, pname, create=False) as project:
        df = _walk(project.getProjectData().getRootFolder(), program_name)
        if df is None:
            raise SystemExit("source program not found: " + program_name)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, False, False, monitor)
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
        if value not in game["shared"]:
            ap.error("{} build {!r} is not in {}'s shared-ID namespace {} "
                     "(disjoint builds need byte-sig porting)".format(
                         role, value, args.game, sorted(game["shared"])))
    if args.source == args.target:
        ap.error("source and target are the same build")
    if not (bool(args.from_program) ^ bool(args.from_pdb)):
        ap.error("pass exactly one of --from-program / --from-pdb")

    lib = _load_library(args.game)
    src_db = getattr(lib, game["attr"][args.source])
    tgt_db = getattr(lib, game["attr"][args.target])
    src_rva_to_id = _rva_to_id(src_db)

    if args.from_pdb:
        pairs = _source_pairs_from_pdb(args.from_pdb)
    else:
        pairs = _source_pairs_from_program(
            args.project_dir, args.project_name, args.from_program)
    print("source names: %d" % len(pairs))

    rows = []
    seen = set()
    for rva, name in pairs:
        ident = src_rva_to_id.get(rva)
        if ident is None:
            continue
        tgt_rva = tgt_db.get(ident)
        if tgt_rva is None or tgt_rva in seen:
            continue
        seen.add(tgt_rva)
        rows.append((name, "", "", "%X" % tgt_rva, str(ident)))
    print("mapped to %s RVAs via shared id: %d" % (args.target, len(rows)))

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
        apply_cmd.append("--create-missing")
    if args.overwrite:
        apply_cmd.append("--overwrite")
    print("+ " + " ".join(apply_cmd))
    sys.exit(subprocess.run(apply_cmd).returncode)


if __name__ == "__main__":
    main()
