"""Find the executable that backs a Ghidra program, and prove it is the one.

A Ghidra project outlives the path its program was imported from, so the
recorded ``getExecutablePath()`` is often dead (or, worse, now holds a different
build).  Launchers therefore accept repeatable ``--target-pe`` candidates and
select the one whose SHA-256 equals the Program's import-time hash -- the same
rule ``symbol_export.py`` uses.  The verified path is handed to the in-Ghidra
drivers through ``BGS_TARGET_PE``; every consumer still runs
``verify_ghidra_program`` so a wrong file fails closed.  The selected manifest
is a ``binary_identity.TargetManifest`` that remembers its file, so that
verification accepts it even while the recorded path holds a different build.
"""

from __future__ import annotations

import os

ENV_TARGET_PE = "BGS_TARGET_PE"


class TargetPEError(RuntimeError):
    """No provable backing executable is available for the program."""


def _stored_sha256(program) -> str:
    try:
        return str(program.getExecutableSHA256() or "").strip().lower()
    except Exception:  # noqa: BLE001
        return ""


def select_target_pe(program, candidates=(), *, inspect=None, cache=None):
    """Return ``(path, manifest)`` for the file that backs ``program``.

    A ``candidates`` entry whose SHA-256 equals the Program's import hash wins
    (returned as a ``TargetManifest``); otherwise the recorded import path is
    used when it still exists.  Raises :class:`TargetPEError` with an
    actionable message when neither is usable.
    ``verify_ghidra_program`` is NOT run here -- callers must still do so.
    """
    from binary_identity import (TargetManifest, _program_executable_path,
                                 inspect_pe)

    inspect = inspect or inspect_pe
    cache = {} if cache is None else cache

    def manifest_of(path):
        key = os.path.normcase(os.path.abspath(path))
        if key not in cache:
            cache[key] = inspect(path)
        return cache[key]

    stored = _stored_sha256(program)
    rejected = []
    for candidate in candidates or ():
        candidate = str(candidate)
        if not os.path.isfile(candidate):
            rejected.append("{} (not a file)".format(candidate))
            continue
        try:
            manifest = manifest_of(candidate)
        except Exception as exc:  # noqa: BLE001
            rejected.append("{} ({})".format(candidate, exc))
            continue
        if stored and str(manifest.get("sha256", "")).lower() == stored:
            return candidate, TargetManifest(manifest, candidate)
        rejected.append("{} (SHA-256 differs)".format(candidate))

    recorded = _program_executable_path(program)
    if recorded and os.path.isfile(recorded):
        return recorded, manifest_of(recorded)

    lines = [
        "the executable this program was imported from is gone: {}".format(
            recorded or "<no path recorded>"),
        "Program import SHA-256: {}".format(stored or "unknown"),
    ]
    if rejected:
        lines.append("--target-pe candidates rejected: " + "; ".join(rejected))
    else:
        lines.append(
            "Pass --target-pe <path to the exact same executable> (repeatable); "
            "the candidate whose SHA-256 equals the import hash is used.")
    raise TargetPEError("\n    ".join(lines))


def driver_target_manifest(program, environ=None):
    """Manifest for an in-Ghidra driver: ``BGS_TARGET_PE`` when the launcher
    set it, else the recorded import path.  Always identity-verified."""
    from binary_identity import (TargetManifest, _program_executable_path,
                                 inspect_pe, verify_ghidra_program)

    environ = os.environ if environ is None else environ
    override = (environ.get(ENV_TARGET_PE) or "").strip()
    path = override or _program_executable_path(program)
    manifest = inspect_pe(path)
    if override:
        # Lets verification accept the launcher's file even when the recorded
        # path now holds another build (hash-exact, see TargetManifest).
        manifest = TargetManifest(manifest, override)
    verify_ghidra_program(program, [manifest])
    return manifest


def driver_target_path(program, environ=None) -> str:
    """The path ``driver_target_manifest`` would inspect (unverified)."""
    from binary_identity import _program_executable_path

    environ = os.environ if environ is None else environ
    return ((environ.get(ENV_TARGET_PE) or "").strip()
            or _program_executable_path(program) or "")
