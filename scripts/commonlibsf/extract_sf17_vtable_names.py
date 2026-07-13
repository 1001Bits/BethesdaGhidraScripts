#!/usr/bin/env python3
"""Extract semantic vtable-slot names from an exact analyzed Starfield build.

The address library and ``IDs_VTABLE.h`` enumerate every CommonLibSF vtable.
MSVC Complete Object Locators distinguish primary and secondary tables, and
the walk terminates at the containing memory-block boundary or the first
non-executable pointer.  Output is accompanied by an identity sidecar binding
the evidence to the Ghidra program, address library, and CommonLib manifest.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
GHIDRA_DIR = REPO_DIR / "tools" / "ghidra"
DEFAULT_IDS_VTABLE = (
    REPO_DIR / "extern" / "CommonLibSF" / "include" / "RE" /
    "IDs_VTABLE.h"
)
DEFAULT_OUT = SCRIPT_DIR / "refs" / "sf17_vtable_slot_names.csv"
SF17_VERSION = (1, 7, 36, 0)
_VERSIONLIB_RE = re.compile(
    r"^versionlib-(\d+)-(\d+)-(\d+)-(\d+)\.bin$", re.IGNORECASE
)
_PLACEHOLDER_RE = re.compile(r"^(?:Func|Method|VFunc)\d+$", re.IGNORECASE)


def _parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", required=True,
                        help="directory containing the Ghidra project")
    parser.add_argument("--project-name", required=True,
                        help="Ghidra project name")
    parser.add_argument("--program", required=True,
                        help="exact program pathname inside the project")
    parser.add_argument("--versionlib", required=True,
                        help="exact versionlib-X-Y-Z-W.bin for the target")
    parser.add_argument("--target-sha256", required=True,
                        help="expected executable SHA-256 persisted by Ghidra")
    parser.add_argument("--ids-vtable", default=str(DEFAULT_IDS_VTABLE),
                        help="CommonLibSF IDs_VTABLE.h path")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="destination CSV")
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _versionlib_version(path: Path):
    match = _VERSIONLIB_RE.match(path.name)
    if not match:
        raise ValueError(
            "version library must use versionlib-X-Y-Z-W.bin naming: {}".format(
                path
            )
        )
    return tuple(int(part) for part in match.groups())


def _semantic_name(function) -> str:
    """Return a qualified non-placeholder name, or an empty string."""
    leaf = function.getName()
    if (leaf.startswith(("FUN_", "thunk_FUN_", "sub_", "LAB_", "DAT_")) or
            _PLACEHOLDER_RE.match(leaf)):
        return ""
    try:
        if str(function.getSymbol().getSource()).upper() == "DEFAULT":
            return ""
    except Exception:
        # Older Ghidra versions do not expose the source through this bridge;
        # the conservative placeholder checks above still apply.
        pass
    return function.getName(True)


def _placeholder_slot(zero_based_slot: int) -> int:
    return zero_based_slot + 1


def _enumerate_vtables(program, labels):
    """Return stable ``(layout class, VA)`` pairs using MSVC COL offsets."""
    memory = program.getMemory()
    space = program.getAddressFactory().getDefaultAddressSpace()
    image_base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    raw = []
    seen_addresses = set()

    for item in labels:
        address = image_base + int(item["sf_off"])
        if address in seen_addresses:
            continue
        seen_addresses.add(address)
        vt_address = space.getAddress(address)
        if not memory.contains(vt_address):
            continue
        try:
            locator = memory.getLong(space.getAddress(address - 8)) & 0xFFFFFFFFFFFFFFFF
            locator_address = space.getAddress(locator)
            if not memory.contains(locator_address):
                continue
            subobject_offset = memory.getInt(
                space.getAddress(locator + 4)
            ) & 0xFFFFFFFF
        except Exception:
            continue
        class_name = item.get('vtable_class')
        if not class_name:
            continue
        raw.append((class_name, address, subobject_offset))

    identities = {}
    result = []
    for class_name, address, subobject_offset in raw:
        identity = "primary" if subobject_offset == 0 else "sub_{:X}".format(
            subobject_offset
        )
        duplicate = identities.get((class_name, identity), 0)
        identities[(class_name, identity)] = duplicate + 1
        if subobject_offset == 0:
            layout_class = (class_name if duplicate == 0 else
                            "{}__primary_{}".format(class_name, duplicate + 1))
        else:
            suffix = identity if duplicate == 0 else "{}_{}".format(
                identity, duplicate + 1
            )
            layout_class = "{}__{}".format(class_name, suffix)
        result.append((layout_class, address))
    return result


def _walk_slots(program, vtable_address):
    """Yield exact-entry functions until the vtable ceases to be valid."""
    memory = program.getMemory()
    space = program.getAddressFactory().getDefaultAddressSpace()
    manager = program.getFunctionManager()
    block = memory.getBlock(space.getAddress(vtable_address))
    if block is None:
        return
    block_end = block.getEnd().getOffset() + 1
    cursor = vtable_address
    slot = 0
    while cursor + 8 <= block_end:
        try:
            pointer = memory.getLong(space.getAddress(cursor)) & 0xFFFFFFFFFFFFFFFF
            if pointer == 0:
                break
            target = space.getAddress(pointer)
            target_block = memory.getBlock(target)
            if target_block is None or not target_block.isExecute():
                break
        except Exception:
            break
        # A pointer into the middle of an analyzed function is not evidence of
        # a new vtable-slot entry point.  Do not inherit the containing name.
        yield slot, manager.getFunctionAt(target)
        cursor += 8
        slot += 1


def main():
    args = _parse_args()
    versionlib = Path(args.versionlib).resolve()
    ids_vtable = Path(args.ids_vtable).resolve()
    output = Path(args.out).resolve()
    expected_sha = args.target_sha256.strip().lower()

    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise SystemExit("ERROR: --target-sha256 must contain 64 hexadecimal digits")
    for required, description in ((versionlib, "version library"),
                                  (ids_vtable, "IDs_VTABLE.h")):
        if not required.is_file():
            raise SystemExit("ERROR: {} not found: {}".format(description, required))
    target_version = _versionlib_version(versionlib)
    if target_version != SF17_VERSION:
        raise SystemExit(
            "ERROR: this SF17 evidence producer requires version 1.7.36.0; "
            "got {}".format(".".join(map(str, target_version)))
        )

    sys.path.insert(0, str(SCRIPT_DIR))
    from address_library import AddressLibrary
    from ids_parser import parse_vtable_h

    database = AddressLibrary().load_bin(
        str(versionlib), expected_version=target_version
    )
    if not database:
        raise SystemExit("ERROR: version library contains no mappings")
    view = type("AddressLibraryView", (), {"sf_db": database})()
    labels = parse_vtable_h(
        str(ids_vtable.parent), view, vtable_path=str(ids_vtable)
    )
    if not labels:
        raise SystemExit("ERROR: no resolvable CommonLibSF vtables found")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    import java.lang
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    rows = []
    program_path = ""
    with pyghidra.open_project(
            args.project_dir, args.project_name, create=False) as project:
        # The pathname is explicit; unlike the old script there is no name or
        # Steamless-prefix fallback that could select another Starfield build.
        domain_file = project.getProjectData().getFile(args.program)
        if domain_file is None:
            raise RuntimeError("program not found at exact project path: {}".format(
                args.program
            ))
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            actual_sha = (program.getExecutableSHA256() or "").lower()
            if not actual_sha:
                raise RuntimeError(
                    "Ghidra program lacks executable SHA-256 metadata; re-import it"
                )
            if actual_sha != expected_sha:
                raise RuntimeError(
                    "Ghidra program SHA-256 mismatch: {} != {}".format(
                        actual_sha, expected_sha
                    )
                )
            program_path = domain_file.getPathname()
            vtables = _enumerate_vtables(program, labels)
            if not vtables:
                raise RuntimeError("no mapped vtables passed COL validation")
            for class_name, address in vtables:
                for slot, function in _walk_slots(program, address):
                    if function is None:
                        continue
                    name = _semantic_name(function)
                    if name:
                        # Generated import placeholders are one-based (Func1
                        # is the first vtable entry), so persist that same
                        # convention at the producer boundary.
                        rows.append((class_name, _placeholder_slot(slot), name))
        finally:
            program.release(consumer)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["class", "slot", "name"])
        writer.writerows(rows)
    temporary.replace(output)

    sidecar = Path(str(output) + ".identity.json")
    metadata = {
        "schema_version": 1,
        "artifact": output.name,
        "artifact_sha256": _sha256(output),
        "slot_numbering": "one_based_FuncN",
        "row_count": len(rows),
        "target_sha256": expected_sha,
        "target_version": list(target_version),
        "source_program": program_path,
        "versionlib_sha256": _sha256(versionlib),
        "versionlib_path": str(versionlib),
        "ids_vtable_sha256": _sha256(ids_vtable),
        "ids_vtable_path": str(ids_vtable),
    }
    sidecar.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("Wrote {} semantic slot names to {}".format(len(rows), output))
    print("Identity: {}".format(sidecar))


if __name__ == "__main__":
    main()
