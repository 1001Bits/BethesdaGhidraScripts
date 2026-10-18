#!/usr/bin/env python3
"""READ-ONLY: detect names that were ported between programs through the WRONG
address-library ID namespace.

Skyrim SE/VR and Skyrim AE (1.6.640 / 1.6.1170 / 1.7.104) are different ID
namespaces, yet most AE IDs also exist numerically in the SE database.  A port
"by shared ID" from AE to SE therefore maps nearly every name -- onto an
unrelated SE address.  ``port_names_by_id.py`` allowed exactly that until
2026-09-21.

Signature of such a port: for an ID ``X``, the function at ``target_db[X]`` in
the target program carries the same qualified name as the function at
``source_db[X]`` in the source program.  Across different namespaces that can
only happen by chance, so more than a handful of hits proves the port happened
and the hit list is the exact set of wrong names.

Both programs are opened read-only; nothing is modified.  Output: a CSV of hits
(name, id, source rva, target rva, target symbol source) and a summary.

Usage:
  python audit_id_port_pollution.py --source-build ae \\
      --source-program /Skyrim/SkyrimAE_1_6_1170.exe \\
      --target-build se --target-program /Skyrim/SkyrimSE_1_5_97.exe \\
      --out se_id_port_pollution.csv
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "scripts" / "core"))
from address_library import AddressLibrary  # noqa: E402
from ghidra_project import (find_program, open_program,  # noqa: E402
                            open_user_project)

GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO / "tools" / "ghidra"))
_DBS = {"se": "se_db", "ae": "ae_db", "vr": "vr_db",
        "16640": "db_16640", "17104": "db_17104"}
_PLACEHOLDER = ("FUN_", "sub_", "thunk_FUN_")


def named_functions(program):
    """{rva: (qualified name, symbol source)} of every non-placeholder function."""
    base = program.getImageBase().getOffset()
    out = {}
    for function in program.getFunctionManager().getFunctions(True):
        if function.getName().startswith(_PLACEHOLDER):
            continue
        out[function.getEntryPoint().getOffset() - base] = (
            function.getName(True), str(function.getSymbol().getSource()))
    return out


def find_hits(source_db, target_db, source_names, target_names):
    hits = []
    for ident, source_rva in source_db.items():
        target_rva = target_db.get(ident)
        if target_rva is None:
            continue
        source = source_names.get(source_rva)
        target = target_names.get(target_rva)
        if source and target and source[0] == target[0]:
            hits.append((target[0], ident, source_rva, target_rva, target[1]))
    return hits


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--source-build", required=True, choices=sorted(_DBS))
    ap.add_argument("--source-program", required=True)
    ap.add_argument("--target-build", required=True, choices=sorted(_DBS))
    ap.add_argument("--target-program", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    same_namespace = [{"se", "vr"}, {"ae", "16640", "17104"}]
    if any(args.source_build in group and args.target_build in group
           for group in same_namespace):
        ap.error("{} and {} share one ID namespace; equal names at equal IDs "
                 "are correct there, not pollution".format(
                     args.source_build, args.target_build))

    library = AddressLibrary()
    library.load_all(str(REPO / "addresslibrary"))
    source_db = getattr(library, _DBS[args.source_build])
    target_db = getattr(library, _DBS[args.target_build])

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang

    monitor = ConsoleTaskMonitor()
    names = {}
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()
        for role, path in (("source", args.source_program),
                           ("target", args.target_program)):
            domain_file = find_program(root, path)
            if domain_file is None:
                raise SystemExit("{} is not in the project".format(path))
            consumer = java.lang.Object()
            program = open_program(domain_file, consumer, monitor, write=False)
            try:
                names[role] = named_functions(program)
            finally:
                program.release(consumer)

    hits = find_hits(source_db, target_db, names["source"], names["target"])
    with open(args.out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "id", "source_rva", "target_rva",
                         "target_symbol_source"])
        for name, ident, source_rva, target_rva, origin in sorted(hits):
            writer.writerow([name, ident, "0x%X" % source_rva,
                             "0x%X" % target_rva, origin])

    shared = sum(1 for ident in source_db if ident in target_db)
    print("named functions: source={} target={}".format(
        len(names["source"]), len(names["target"])))
    print("IDs present in both databases: {}".format(shared))
    print("same-name-at-same-ID hits: {}".format(len(hits)))
    print("  by target symbol source: {}".format(dict(collections.Counter(
        origin for *_rest, origin in hits))))
    print("VERDICT: {}".format(
        "POLLUTED -- names were ported by ID across namespaces" if len(hits) > 50
        else "clean (no cross-namespace ID port signature)"))
    print("-> " + args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
