#!/usr/bin/env python3
"""Emit an address-library (id -> rva) file from byte-signature port results.

The cross-version byte-signature port resolves ``(name -> target_rva)`` pairs
for an under-covered binary by matching a well-covered source binary's named
functions.  Those pairs are normally applied as Ghidra renames and the
address-library ID is discarded.  This module re-attaches the ID (joining
``name -> id`` from the *source* binary's SYMBOLS array) and writes a
community-format ``id,offset`` CSV -- the same format our own loaders read
back (``commonlib{sse,f4}/address_library.py:load_csv``), so a round-trip
sanity check is free.

Pure stdlib; no Ghidra / pyghidra.  Importable and unit-testable on its own.

Correctness guards (the join is only as good as its inputs):
  * names that map to more than one distinct ID in the source are AMBIGUOUS
    and dropped (can't pick the right ID);
  * two names resolving to the SAME id at DIFFERENT rvas is a CONFLICT and
    both are dropped (one of the matches is wrong);
  * names with no ID in the source are dropped (nothing to key on).

Namespace caveat: the emitted IDs are in the SOURCE binary's ID namespace.
That is only meaningful for a target that SHARES that namespace (e.g. F4 OG,
which shares meh321's AE/NG/OG namespace).  For a disjoint-namespace target
(e.g. F4 VR), an AE-keyed file is semantically WRONG -- callers must refuse to
emit unless explicitly overridden.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Set, Tuple


def build_name_to_id(
    symbols: Iterable[dict],
    *,
    id_key: str = "id",
    name_key: str = "n",
    type_key: str = "t",
    func_type: str = "func",
) -> Tuple[Dict[str, int], Set[str]]:
    """From a generated-script SYMBOLS list, build (name->id, ambiguous_names).

    Only ``func``-typed entries with a non-zero ID are considered.  A name that
    appears with two or more distinct IDs is recorded as ambiguous and left out
    of the returned map.
    """
    name_ids: Dict[str, Set[int]] = {}
    for s in symbols:
        if type_key is not None and s.get(type_key) != func_type:
            continue
        name = s.get(name_key)
        sid = s.get(id_key)
        if not name or not sid:
            continue
        name_ids.setdefault(name, set()).add(int(sid))

    name_to_id: Dict[str, int] = {}
    ambiguous: Set[str] = set()
    for name, ids in name_ids.items():
        if len(ids) == 1:
            name_to_id[name] = next(iter(ids))
        else:
            ambiguous.add(name)
    return name_to_id, ambiguous


def join_ids(
    ported: Iterable[Tuple[str, int]],
    name_to_id: Dict[str, int],
    ambiguous: Optional[Set[str]] = None,
) -> Tuple[Dict[int, int], dict]:
    """Join byte-sig ``(name, target_rva)`` pairs against ``name -> id``.

    Returns ``(id_to_rva, stats)``.  ``stats`` carries counts for total,
    joined, dropped_no_id, dropped_ambiguous, and dropped_conflict.
    """
    ambiguous = ambiguous or set()
    id_to_rva: Dict[int, int] = {}
    conflict_ids: Set[int] = set()
    stats = {"total": 0, "joined": 0, "dropped_no_id": 0,
             "dropped_ambiguous": 0, "dropped_conflict": 0}

    for name, rva in ported:
        stats["total"] += 1
        if name in ambiguous:
            stats["dropped_ambiguous"] += 1
            continue
        sid = name_to_id.get(name)
        if not sid:
            stats["dropped_no_id"] += 1
            continue
        if sid in conflict_ids:
            continue
        prev = id_to_rva.get(sid)
        if prev is not None and prev != rva:
            # two names claim the same ID at different addresses -> unsafe
            del id_to_rva[sid]
            conflict_ids.add(sid)
            stats["dropped_conflict"] += 2
            stats["joined"] -= 1
            continue
        if prev is None:
            id_to_rva[sid] = rva
            stats["joined"] += 1
    return id_to_rva, stats


def write_addrlib_csv(
    path: str,
    id_to_rva: Dict[int, int],
    *,
    version_label: str,
    note: str = "",
) -> None:
    """Write the community ``id,offset`` CSV our loaders read back.

    Layout (matches ``load_csv`` in commonlib{sse,f4}/address_library.py):
        id,offset                     <- header
        <count>,<version_label>       <- metadata row (reader skips it)
        <id>,<hexoffset-without-0x>   <- one per entry, sorted by id
    Offsets are bare hex (no ``0x``) because the reader does ``int(off, 16)``.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    meta = version_label if not note else f"{version_label} {note}"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        fh.write("id,offset\n")
        fh.write(f"{len(id_to_rva)},{meta}\n")
        for sid in sorted(id_to_rva):
            fh.write(f"{sid},{id_to_rva[sid]:x}\n")


def load_for_roundtrip(path: str) -> Dict[int, int]:
    """Parse an emitted CSV back to {id: rva}, mirroring the loaders' rules.

    Skips the header line and the single ``count,version`` metadata row;
    parses each remaining ``id,offset`` with offset as hex (no ``0x``).
    """
    out: Dict[int, int] = {}
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    # lines[0] = "id,offset" header; lines[1] = "count,version" metadata
    for ln in lines[2:]:
        parts = ln.split(",")
        if len(parts) != 2:
            continue
        try:
            out[int(parts[0])] = int(parts[1], 16)
        except ValueError:
            continue
    return out


def emit_from_ported(
    out_path: str,
    ported: Iterable[Tuple[str, int]],
    source_symbols: Iterable[dict],
    *,
    version_label: str,
    note: str = "",
    verify_roundtrip: bool = True,
) -> dict:
    """Convenience: build name->id from source SYMBOLS, join, write, verify.

    Returns the join stats (plus ``written`` count and ``roundtrip_ok``).
    """
    name_to_id, ambiguous = build_name_to_id(source_symbols)
    id_to_rva, stats = join_ids(ported, name_to_id, ambiguous)
    write_addrlib_csv(out_path, id_to_rva, version_label=version_label, note=note)
    stats["written"] = len(id_to_rva)
    if verify_roundtrip:
        back = load_for_roundtrip(out_path)
        stats["roundtrip_ok"] = (back == id_to_rva)
    return stats
