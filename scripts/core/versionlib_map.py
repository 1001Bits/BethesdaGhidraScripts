"""Cross-version address translation via Address Library IDs.

A vtable slot holds a function pointer, and the same function lives at a
different address in every build.  Matching those slots across builds by
comparing the first 32 bytes of the function fails badly once the image moves:
between Starfield 1.16.236 and 1.16.244 only 255 of 818,361 shared IDs kept
their RVA, so nearly every embedded ``call rel32`` / RIP-relative displacement
changed and byte-identical prologues became the exception.

The address library already answers the question exactly.  It is a bijection
from a build-independent ID to that build's RVA, so a function's identity
survives the move::

    reference VA -> reference RVA -> ID -> target RVA -> target VA

This module builds that VA->VA translation.  It is deliberately conservative:
an ID whose RVA is not unique within a build, or that disappears in the target,
yields no translation at all rather than a guess.  Callers treat a missing
translation as "unmatched", never as "match something nearby".

Scope: this is safe only where IDs are version-stable, which for this
repository means Starfield.  Skyrim and Fallout 4 renumber between runtimes --
that is exactly why CommonLibSSE-NG carries ``REL::RelocationID(seID, aeID)``
-- so callers must opt in per game by supplying version libraries, never by
default.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, Optional, Tuple

# Every supported Starfield build loads at this base.  It is a default, not an
# assumption: ``verify_image_base`` re-derives the hit rate against real data
# and callers refuse to proceed when it does not hold.
DEFAULT_IMAGE_BASE = 0x140000000

_V5_HEADER_SIZE = 96


class VersionlibError(ValueError):
    pass


def read_versionlib(path: str) -> Dict[int, int]:
    """Read a meh321 V5 address library into ``{id: rva}``.

    V5 is the flat format Starfield uses::

        fmt        u32  (== 5)
        version[4] 4 x u32
        name       char[64]
        ptr_size   u64
        count      u32
        entries    u32[count]     indexed by id, value = rva

    A zero entry means "this ID has no address in this build" and is omitted,
    so ``id in db`` is a meaningful question.
    """
    with open(path, 'rb') as handle:
        data = handle.read()
    if len(data) < _V5_HEADER_SIZE:
        raise VersionlibError(
            '{}: truncated address-library header ({} bytes)'.format(
                path, len(data)))
    fmt = struct.unpack_from('<I', data, 0)[0]
    if fmt != 5:
        # V1/V2 are delta-encoded and belong to games whose IDs are not
        # version-stable, so ID translation would be unsound there anyway.
        raise VersionlibError(
            '{}: ID translation supports only the V5 format, got V{}'.format(
                path, fmt))
    pointer_size = struct.unpack_from('<Q', data, 84)[0]
    if pointer_size != 8:
        raise VersionlibError(
            '{}: expected a 64-bit address library, got pointer size {}'.format(
                path, pointer_size))
    count = struct.unpack_from('<I', data, 92)[0]
    end = _V5_HEADER_SIZE + count * 4
    if end > len(data):
        raise VersionlibError(
            '{}: truncated address table (need {} bytes, have {})'.format(
                path, end, len(data)))
    database: Dict[int, int] = {}
    for index in range(count):
        rva = struct.unpack_from('<I', data, _V5_HEADER_SIZE + index * 4)[0]
        if rva:
            database[index] = rva
    if not database:
        raise VersionlibError('{}: address library is empty'.format(path))
    return database


def _unique_rva_to_id(database: Dict[int, int]) -> Dict[int, int]:
    """Invert ``{id: rva}``, dropping any RVA claimed by more than one ID.

    Two IDs on one address cannot be told apart from an address alone, so
    neither is usable as evidence.
    """
    owners: Dict[int, Optional[int]] = {}
    for identifier, rva in database.items():
        if rva in owners:
            owners[rva] = None          # contested; poison it
        else:
            owners[rva] = identifier
    return {rva: owner for rva, owner in owners.items() if owner is not None}


def build_va_translation(reference: Dict[int, int], target: Dict[int, int],
                         reference_image_base: int = DEFAULT_IMAGE_BASE,
                         target_image_base: int = DEFAULT_IMAGE_BASE
                         ) -> Dict[int, int]:
    """Return ``{reference_va: target_va}`` for every unambiguously shared ID.

    Dropped, in both directions:
      * an RVA that several IDs share in either build -- the address does not
        identify one function;
      * an ID absent from the target -- the function was removed or inlined;
      * two reference addresses that would land on one target address -- an ID
        was retired and its address reused, so at most one edge is right and
        nothing here says which.
    """
    reference_by_rva = _unique_rva_to_id(reference)
    target_unique_rvas = set(_unique_rva_to_id(target))

    translation: Dict[int, int] = {}
    claimed: Dict[int, Optional[int]] = {}
    for reference_rva, identifier in reference_by_rva.items():
        target_rva = target.get(identifier)
        if target_rva is None or target_rva not in target_unique_rvas:
            continue
        reference_va = reference_image_base + reference_rva
        target_va = target_image_base + target_rva
        if target_va in claimed:
            claimed[target_va] = None
        else:
            claimed[target_va] = reference_va
        translation[reference_va] = target_va

    contested = {va for va, owner in claimed.items() if owner is None}
    if contested:
        translation = {reference_va: target_va
                       for reference_va, target_va in translation.items()
                       if target_va not in contested}
    return translation


def verify_image_base(addresses: Iterable[int], database: Dict[int, int],
                      image_base: int = DEFAULT_IMAGE_BASE,
                      minimum_hit_rate: float = 0.90) -> Tuple[float, bool]:
    """Check that ``address - image_base`` really lands on address-library RVAs.

    A wrong image base still produces plausible-looking integers, and every
    translation built from them would be confidently wrong.  Sampling real
    slot addresses against the library turns that into a checkable fact.

    Returns ``(hit_rate, ok)``.
    """
    known = set(database.values())
    total = 0
    hits = 0
    for address in addresses:
        rva = address - image_base
        if rva < 0:
            total += 1
            continue
        total += 1
        if rva in known:
            hits += 1
    if not total:
        return 0.0, False
    rate = hits / float(total)
    return rate, rate >= minimum_hit_rate
