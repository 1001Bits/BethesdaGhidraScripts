"""Recover the exact executable a Ghidra Program was imported from.

A project routinely outlives its import path: the game is moved, or -- for a
Steam build -- the Steamless-unpacked .exe was a temporary file that nobody
kept.  The program is then orphaned: every downstream step that must attest
its identity (importer binding, symbol export, evidence sidecars) has nothing
to attest against, and no fresh unpack helps, because Steamless output is not
byte-reproducible across versions (a newer build may keep the dead ``.bind``
section that an older one stripped, changing the file's size and hash).

Ghidra, however, stores the original file's bytes inside the program database
-- that is what its "Original File" exporter re-emits.  So the exact import is
recoverable from the project itself.  This module exports those bytes and
keeps the result only when its SHA-256 equals the hash the Program recorded at
import time, so a recovered file is proof, not a guess.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional
from ghidra_project import open_user_project


class RecoveryError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def recover_original_exe(program, out_path: str | Path,
                         monitor=None) -> Optional[Path]:
    """Write the Program's original imported bytes to *out_path*.

    Returns the path on success.  Raises ``RecoveryError`` when the program
    carries no stored file bytes, no import-time SHA-256 to check against, or
    when the exported bytes do not hash to that SHA-256 -- in which case
    nothing is left behind.
    """
    out_path = Path(out_path)

    # Both refusals are decided before Ghidra is touched, so they are provable
    # without a JVM -- and so a hopeless recovery costs nothing.
    expected = str(program.getExecutableSHA256() or "").lower()
    if len(expected) != 64:
        raise RecoveryError(
            "the program records no import-time SHA-256, so a recovered file "
            "could not be proven to be the one it was imported from")

    file_bytes = list(program.getMemory().getAllFileBytes())
    if not file_bytes:
        raise RecoveryError(
            "the program database stores no original file bytes (imported by "
            "an old Ghidra, or added as a raw memory image)")

    from ghidra.app.util.exporter import OriginalFileExporter
    from ghidra.util.task import ConsoleTaskMonitor
    import java.io

    monitor = monitor or ConsoleTaskMonitor()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    exporter = OriginalFileExporter()
    if not exporter.export(java.io.File(str(out_path)), program, None, monitor):
        raise RecoveryError("Ghidra's original-file exporter failed")

    actual = _sha256(out_path)
    if actual != expected:
        os.unlink(out_path)
        raise RecoveryError(
            "recovered bytes hash to {} but the program was imported from {}; "
            "discarded".format(actual[:16], expected[:16]))
    return out_path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--program-path", required=True,
                        help="project path, e.g. /Skyrim/SkyrimVR_1_4_15.exe")
    parser.add_argument("--out", required=True,
                        help="where to write the recovered executable")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(repo / "tools" / "ghidra"))
    import pyghidra
    pyghidra.start(install_dir=repo / "tools" / "ghidra")
    import java.lang
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    with open_user_project(args.project_dir, args.project_name) as project:
        domain_file = project.getProjectData().getFile(args.program_path)
        if domain_file is None:
            print("ERROR: no such program: {}".format(args.program_path))
            return 1
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, True, monitor)
        try:
            recovered = recover_original_exe(program, args.out, monitor)
        except RecoveryError as exc:
            print("ERROR: cannot recover the original executable: {}".format(exc))
            return 1
        finally:
            program.release(consumer)

    print("Recovered {} ({} bytes), SHA-256 verified against the program.".format(
        recovered, recovered.stat().st_size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
