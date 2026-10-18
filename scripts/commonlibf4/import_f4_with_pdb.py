#!/usr/bin/env python3
r"""Import a Fallout 4 executable into Combined and analyze it WITH its PDB.

For builds that have a real compiler PDB (1.10.155 retail and Beta: 1.3M /
1.47M type records, ~500k publics), Ghidra's PDB Universal analyzer applies
the ground-truth types, prototypes, globals and locals during auto-analysis.
That program then serves as the exact source for byte-signature name ports
and data-type transfer to every other Fallout 4 build.

Fail-closed identity: the PDB's GUID/age must equal the PE's CodeView record
(checked natively, without llvm-pdbutil, which cannot read these 1 KiB-block
PDBs) before the file is attached to the program.  The program is bound to
the exact PE identity like every other Combined import, and the PDB's SHA-256
is recorded in the program options.

Stages (each saved, so an interrupted run resumes):
  import   -> identity-bound program, no analysis (stage ``imported-v1``)
  pdb      -> PDB file option attached + PDB identity recorded
  analyze  -> full auto-analysis incl. PDB Universal (stage ``generic-v2``)

Usage (Ghidra GUI closed; give the JVM room, the PDB is large)::

    python scripts/commonlibf4/import_f4_with_pdb.py all \
        --source "FO4 PDB/Fallout4.exe" --pdb "FO4 PDB/Fallout4.pdb" \
        --program-path /Fallout4/Fallout4_1_10_155.exe [--heap 10g]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parents[2]
CORE_DIR = REPO_DIR / "scripts" / "core"
SCRIPTS_DIR = REPO_DIR / "scripts"
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
for path in (CORE_DIR, SCRIPTS_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from binary_identity import inspect_pe, verify_ghidra_program  # noqa: E402
from ghidra_project import find_program, open_program, open_user_project  # noqa: E402
from pdb_identity import read_pe_codeview  # noqa: E402
from pdb_msf import read_pdb_identity_native  # noqa: E402
from pyghidra_result import end_outer_transaction  # noqa: E402

PDB_SHA_OPTION = "BGS PDB SHA256"
PDB_GUID_OPTION = "BGS PDB GUID/Age"


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pdb_matches_pe(pe_path, pdb_path):
    """Return the PDB identity, or raise when it is not this PE's PDB."""
    codeview = read_pe_codeview(str(pe_path))
    identity = read_pdb_identity_native(str(pdb_path))
    if (str(codeview["guid"]).upper() != str(identity["guid"]).upper()
            or int(codeview["age"]) != int(identity["age"])):
        raise RuntimeError(
            "PDB does not belong to this executable: PE CodeView {}/age {} vs "
            "PDB {}/age {}".format(codeview["guid"], codeview["age"],
                                   identity["guid"], identity["age"]))
    return identity


def _attach_pdb(project, program_path, expected, pdb_path, identity, monitor):
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from ghidra.program.model.listing import Program
    import java.io
    import java.lang

    domain_file = find_program(project.getProjectData().getRootFolder(), program_path)
    if domain_file is None:
        raise RuntimeError("{} is not present".format(program_path))
    consumer = java.lang.Object()
    program = open_program(domain_file, consumer, monitor, write=True)
    try:
        verify_ghidra_program(program, [expected])
        tx = program.startTransaction("Attach exact PDB")
        commit = False
        try:
            PdbUniversalAnalyzer.setPdbFileOption(
                program, java.io.File(str(Path(pdb_path).resolve())))
            # The PDB was not fetched from a symbol server; its identity was
            # verified above, so the analyzer may use it.
            PdbUniversalAnalyzer.setAllowUntrustedOption(program, True)
            info = program.getOptions(Program.PROGRAM_INFO)
            info.setString(PDB_SHA_OPTION, _sha256(pdb_path))
            info.setString(PDB_GUID_OPTION, "{}/{}".format(
                identity["guid"], identity["age"]))
            commit = True
        finally:
            end_outer_transaction(program, tx, commit, "PDB attach")
        program.save("attach exact PDB {}".format(Path(pdb_path).name), monitor)
        print("PDB attached: {} ({}/age {})".format(
            pdb_path, identity["guid"], identity["age"]))
    finally:
        program.release(consumer)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("import", "pdb", "analyze", "all"))
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--pdb", required=True, type=Path)
    ap.add_argument("--program-path", required=True)
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--heap", default="10g", help="JVM -Xmx (default 10g)")
    ap.add_argument("--force-reanalyze", action="store_true")
    args = ap.parse_args()

    source = args.source.resolve()
    pdb = args.pdb.resolve()
    if not source.is_file() or not pdb.is_file():
        ap.error("source and pdb must exist")
    expected = inspect_pe(str(source))
    identity = verify_pdb_matches_pe(source, pdb)
    print("PE {} sha256={} <-> PDB {} {}/age {}".format(
        source.name, expected["sha256"][:12], pdb.name, identity["guid"],
        identity["age"]))

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA_DIR)
    launcher.add_vmargs("-Xmx" + args.heap)
    launcher.start()
    from ghidra.util.task import ConsoleTaskMonitor
    import import_combined_runtime as runtime

    monitor = ConsoleTaskMonitor()
    with open_user_project(Path(args.project_dir), args.project_name) as project:
        if args.action in ("import", "all"):
            runtime._import(project, source, args.program_path, expected, monitor)
        if args.action in ("pdb", "all"):
            _attach_pdb(project, args.program_path, expected, pdb, identity, monitor)
        if args.action in ("analyze", "all"):
            runtime._analyze(project, args.program_path, expected, monitor,
                             force=args.force_reanalyze)
    return 0


if __name__ == "__main__":
    sys.exit(main())
