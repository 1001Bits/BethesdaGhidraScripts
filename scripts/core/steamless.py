"""Shared Steamless wrapper.

Detect and strip SteamStub DRM via the Steamless CLI.  Returns an unpacked
copy when DRM was present, otherwise the original binary.  Cached output is
reused only when its identity sidecar records the exact SHA-256 and PE identity
of the current source binary.
On non-Windows hosts an image without a SteamStub marker is returned as-is;
marked images fail with an actionable error because Steamless cannot be run.
On Windows a missing CLI is always an error, preventing a direct generator
invocation from silently analyzing a packed target.

Used by:
  - scripts/run_headless.py            (before Ghidra import)
  - scripts/commonlibf4/run_bytesig_port.py  (before reading PE bytes)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from binary_identity import (
    artifact_is_fresh,
    inspect_pe,
    make_artifact_sidecar,
    read_manifest,
    write_manifest,
)


_POLICY_SCHEMA = 1
_ARGUMENTS = ("--quiet", "--keepbind")
_PINNED_CLI_SHA256 = (
    "70cd54354865ede605ec0fbfadf15f5302aa85a777394f28b0de6acfd243e795")


def _producer_metadata(steamless_cli: Path):
    identity = inspect_pe(str(steamless_cli))
    if (identity.get("sha256", "").lower() != _PINNED_CLI_SHA256 and
            not os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT")):
        raise RuntimeError(
            "Steamless CLI does not match the repository toolchain lock")
    return {
        "cache_policy": _POLICY_SCHEMA,
        "producer": {
            "name": "Steamless.CLI",
            "sha256": identity["sha256"],
            "file_size": identity["file_size"],
            "file_version": identity.get("file_version"),
        },
        "arguments": list(_ARGUMENTS),
    }


def _policy_matches(sidecar_path: str, expected) -> bool:
    try:
        return read_manifest(sidecar_path).get("metadata") == expected
    except (OSError, ValueError):
        return False


def _entry_point_rva(path: Path) -> int:
    with open(path, "rb") as fh:
        fh.seek(0x3C)
        pe_offset = int.from_bytes(fh.read(4), "little")
        fh.seek(pe_offset + 24 + 16)  # optional header, AddressOfEntryPoint
        return int.from_bytes(fh.read(4), "little")


def ensure_unpacked(binary: Path, steamless_cli: Path) -> Path:
    source_manifest = inspect_pe(str(binary))
    has_bind = any(str(section.get("name", "")).lower() in (".bind", "bind")
                   for section in source_manifest.get("sections", []))
    # A live SteamStub points the PE entry at its .bind stub.  An exe that
    # was unpacked in place keeps a dead .bind section but has its entry
    # restored to .text -- treat that as unpacked, not as packed.  Stay
    # conservative (keep has_bind) unless the entry point and the .bind
    # bounds are both readable and the entry provably lies outside .bind.
    if has_bind:
        try:
            entry = _entry_point_rva(binary)
        except OSError:
            entry = 0
        bind_bounds = [
            (int(section.get("rva", 0) or 0),
             max(int(section.get("virtual_size", 0) or 0),
                 int(section.get("raw_size", 0) or 0)))
            for section in source_manifest.get("sections", [])
            if str(section.get("name", "")).lower() in (".bind", "bind")]
        if (entry > 0 and bind_bounds and
                all(size > 0 for _, size in bind_bounds) and
                not any(rva <= entry < rva + size
                        for rva, size in bind_bounds)):
            has_bind = False

    def candidates():
        # Steamless versions vary: <stem>.unpacked.exe or <name>.unpacked[.exe]
        for c in sorted(binary.parent.glob(f"{binary.stem}*unpacked*")):
            if c == binary or not c.is_file():
                continue
            yield c

    def find_identity_bound_without_cli():
        """Reuse a complete exact-source artifact on hosts without Steamless."""
        for candidate in candidates():
            sidecar = str(candidate) + ".identity.json"
            if not artifact_is_fresh(str(binary), str(candidate), sidecar):
                continue
            try:
                metadata = read_manifest(sidecar).get("metadata", {})
            except (OSError, ValueError):
                continue
            producer = metadata.get("producer", {})
            if (producer.get("name") == "Steamless.CLI" and
                    producer.get("sha256", "").lower() == _PINNED_CLI_SHA256 and
                    metadata.get("arguments") == list(_ARGUMENTS)):
                return candidate
        return None

    if sys.platform != "win32":
        cached = find_identity_bound_without_cli()
        if cached is not None:
            print(f"Using identity-bound Steamless output: {cached.name}")
            return cached
        if has_bind:
            raise RuntimeError(
                "{} contains a SteamStub .bind section, but Steamless is a "
                "Windows tool; supply an exact unpacked artifact from a "
                "Windows preparation run".format(binary))
        return binary
    if not steamless_cli.is_file():
        cached = find_identity_bound_without_cli()
        if cached is not None:
            print(f"Using identity-bound Steamless output: {cached.name}")
            return cached
        raise FileNotFoundError(
            "Steamless CLI is required before preparing {} (run `python "
            "run.py setup`)".format(binary))
    producer_metadata = _producer_metadata(steamless_cli)

    def find_fresh():
        for c in candidates():
            sidecar = str(c) + ".identity.json"
            if (artifact_is_fresh(str(binary), str(c), sidecar) and
                    _policy_matches(sidecar, producer_metadata)):
                return c
        return None

    cached = find_fresh()
    if cached is not None:
        print(f"Using cached Steamless output: {cached.name}")
        return cached

    before = {str(c): (c.stat().st_mtime_ns, c.stat().st_size)
              for c in candidates()}
    started_ns = time.time_ns()
    # Steamless stays authoritative even when the PE shows no live stub: the
    # .bind heuristic cannot prove a binary is unpacked (older SteamStub
    # variants ship no such section).  Only its OUTPUT is quieted -- the tool
    # banner is noise on the unpacked path, so it is printed only when a real
    # failure needs diagnosing.
    if has_bind:
        print(f"Running Steamless on {binary.name} ...")
    try:
        result = subprocess.run(
            [str(steamless_cli), *_ARGUMENTS, str(binary)],
            capture_output=True, text=True, check=False,
            cwd=str(steamless_cli.parent),
        )
    except OSError as exc:
        raise RuntimeError("Steamless could not be launched: {}".format(exc)) from exc
    hard_failure = result.returncode != 0 and has_bind
    if hard_failure:
        if result.stdout.strip():
            print(result.stdout.rstrip())
        if result.stderr.strip():
            print(result.stderr.rstrip(), file=sys.stderr)
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            "Steamless failed for {} (exit {}): {}".format(
                binary, result.returncode, detail or "no diagnostic output"))
    if result.returncode != 0:
        # No live SteamStub entry stub -- Steamless rejecting a residual or
        # absent .bind section is not a failure.
        print(f"  {binary.name}: no SteamStub to remove; using original binary.")
        return binary

    # Only trust an output produced or changed by this invocation.  Legacy
    # mtime/size-only candidates are deliberately ignored because they may
    # have been derived from a different executable with the same filename.
    out = None
    for candidate in candidates():
        stat = candidate.stat()
        old = before.get(str(candidate))
        changed = old is None or old != (stat.st_mtime_ns, stat.st_size)
        if changed and stat.st_mtime_ns >= started_ns - 2_000_000_000:
            out = candidate
            break
    if out is not None:
        try:
            sidecar = make_artifact_sidecar(
                str(binary), str(out), **producer_metadata)
            sidecar_path = str(out) + ".identity.json"
            write_manifest(sidecar_path, sidecar)
            if not artifact_is_fresh(str(binary), str(out), sidecar_path):
                raise ValueError("written identity sidecar failed verification")
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                f"Steamless output failed PE identity validation: {exc}") from exc
        print(f"  SteamStub DRM removed -> {out.name}")
        return out
    if has_bind:
        raise RuntimeError(
            "Steamless returned success but produced no artifact for a PE "
            "with a SteamStub .bind section: {}".format(binary))
    print("  No SteamStub DRM detected; using original binary.")
    return binary
