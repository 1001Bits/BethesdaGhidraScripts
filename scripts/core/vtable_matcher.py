"""Cross-version vtable slot matcher.

Given a reference BinaryLayout (the canonical version whose slot indices
match CommonLib header comments) and a target BinaryLayout (some other
binary version), produces a "shift map" telling the build-time patcher
where each reference slot lives in the target binary.

Matching strategy, per class:

  1. **Exact name match** -- if the same function name appears at slot X
     in ref and slot Y in target, ref[X] -> target[Y].  Strongest signal
     and handles the common case where PDB symbols are available.

  2. **Fingerprint match** -- if a ref slot's function fingerprint matches
     a target slot's fingerprint (Ghidra-style masked byte pattern), pair
     them.  Catches slots that exist in both binaries but were renamed
     or never named in one of them.

  3. **Anything left in target with no ref match** -- emitted as a
     "target-only slot": the patcher will add a placeholder field like
     `__<version>_only_0xXX` so the struct overlay covers it.

  4. **Anything left in ref with no target match** -- "removed slot":
     the patcher will drop it from the per-version struct.

Output is a ``ClassShiftMap`` per class, packaged in a ``ShiftMap``.

The matcher is intentionally conservative: when fingerprints don't
uniquely identify a slot, prefer "unmatched" over a guess.  Anchor
verification (see ``anchor_verifier.py``) catches anything the matcher
misses.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from vtable_layout import BinaryLayout, ClassVtable, SlotEntry


@dataclass
class ClassShiftMap:
    """How one class's slots map from reference -> target binary."""
    class_name: str
    vtable_id: str = ''
    target_vtable_id: str = ''
    subobject_offset: int = 0
    is_primary: bool = True
    ref_to_target: Dict[int, int] = field(default_factory=dict)  # ref_slot -> target_slot
    unmatched_ref_slots: List[int] = field(default_factory=list)  # in ref, missing in target
    target_only_slots: List[Tuple[int, SlotEntry]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    match_evidence: Dict[int, dict] = field(default_factory=dict)
    ambiguous_matches: List[dict] = field(default_factory=list)


@dataclass
class ShiftMap:
    """Full shift map for one (reference, target) binary pair."""
    reference_label: str
    target_label: str
    classes: Dict[str, ClassShiftMap] = field(default_factory=dict)
    vtables: Dict[str, ClassShiftMap] = field(default_factory=dict)

    def to_json(self) -> dict:
        def encode(m):
            return {
                'class_name': m.class_name,
                'vtable_id': m.vtable_id,
                'target_vtable_id': m.target_vtable_id,
                'subobject_offset': '0x{:X}'.format(m.subobject_offset),
                'is_primary': m.is_primary,
                'reference_slot_count': (len(m.ref_to_target) +
                                         len(m.unmatched_ref_slots)),
                'target_slot_count': (len(m.ref_to_target) +
                                      len(m.target_only_slots)),
                'matched_ratio': (float(len(m.ref_to_target)) /
                                  max(1, len(m.ref_to_target) +
                                      len(m.unmatched_ref_slots))),
                'ref_to_target': {'0x{:X}'.format(k): '0x{:X}'.format(v)
                                  for k, v in m.ref_to_target.items()},
                'unmatched_ref_slots': [
                    '0x{:X}'.format(s) for s in m.unmatched_ref_slots],
                'target_only_slots': [
                    {'slot': '0x{:X}'.format(s), 'func_name': e.func_name,
                     'func_addr': '0x{:X}'.format(e.func_addr)}
                    for s, e in m.target_only_slots
                ],
                'match_evidence': {
                    '0x{:X}'.format(k): v
                    for k, v in sorted(m.match_evidence.items())
                },
                'ambiguous_matches': m.ambiguous_matches,
                'notes': m.notes,
            }
        return {
            'schema_version': 2,
            'reference': self.reference_label,
            'target': self.target_label,
            # ``classes`` remains the primary-table compatibility view.
            'classes': {cls: encode(m) for cls, m in sorted(self.classes.items())},
            'vtables': {identity: encode(m)
                        for identity, m in sorted(self.vtables.items())},
        }


def _normalize_fingerprint(fp: str) -> str:
    """Strip whitespace, uppercase hex, normalize question marks.

    Ghidra emits like '48 8B C4 ? ? ? ? 48'.  We compare as a single string
    so spaces aren't significant.
    """
    if not fp:
        return ''
    parts = fp.replace('\t', ' ').split()
    return ' '.join(p.upper() if p != '?' else '?' for p in parts)


def _fingerprints_match(a: str, b: str,
                          min_concrete_bytes: int = 16,
                          prefix_window: Optional[int] = None,
                          max_concrete_mismatches: int = 0) -> bool:
    """True if two function-prologue fingerprints are compatible.

    Every comparable concrete byte in the captured fingerprints must agree
    by default.  Comparing only an MSVC frame-setup prefix creates convincing
    false matches between unrelated functions, so callers must explicitly
    opt into a shorter window (and the production matcher does not).

    Args:
      a, b: normalized fingerprint strings (space-separated hex bytes
            or ``?`` wildcards).
      min_concrete_bytes:  minimum number of non-wildcard bytes that
            must match between the two prefixes for the pair to be
            considered a hit.  Below this the signal is too weak.
      prefix_window: optional explicit comparison limit.  ``None`` compares
            the complete common capture and is the safe production default.
      max_concrete_mismatches: allow this many concrete-vs-concrete
            differences within the prefix before declaring a mismatch.
            Set to 0 for strict, 1 to tolerate a single register/imm
            swap.
    """
    if not a or not b:
        return False
    pa = a.split()
    pb = b.split()
    if prefix_window is None and len(pa) != len(pb):
        # A shorter capture being a prefix of a longer function is not full
        # fingerprint agreement and can recreate the common-prologue bug.
        return False
    n = min(len(pa), len(pb))
    if prefix_window is not None:
        if prefix_window <= 0:
            return False
        n = min(n, prefix_window)
    if n == 0:
        return False
    concrete_matches = 0
    concrete_mismatches = 0
    for i in range(n):
        ai, bi = pa[i], pb[i]
        if ai == '?' or bi == '?':
            continue  # wildcard slot, ignore
        if ai != bi:
            concrete_mismatches += 1
            if concrete_mismatches > max_concrete_mismatches:
                return False
        else:
            concrete_matches += 1
    return concrete_matches >= min_concrete_bytes


def _slots_by_function(table: ClassVtable) -> Dict[int, List[int]]:
    """Group a table's slots by the function pointer they hold, in slot order.

    A quarter of Starfield's slots share a function with another slot in the
    same table -- identical folded stubs like ``xor eax,eax; ret`` -- so the
    unit that can be identified is the group, not the individual slot.
    """
    groups: Dict[int, List[int]] = {}
    for slot in sorted(table.slots):
        groups.setdefault(table.slots[slot].func_addr, []).append(slot)
    return groups


def _match_by_translated_address(ref: ClassVtable, tgt: ClassVtable,
                                 sm: ClassShiftMap,
                                 va_translation: Dict[int, int],
                                 used_target_slots: set) -> None:
    """Stage 0: pair slots whose functions share an Address Library ID.

    This is identity rather than resemblance, so it survives a rebuild that
    moves every function -- the case that defeats byte fingerprints entirely.
    Where a function appears several times in one table the group is paired by
    ordinal, but only when both sides have the same number of copies: if a
    build added or dropped one instance of a folded stub, ordinal pairing would
    silently shift every later duplicate by one.
    """
    ref_groups = _slots_by_function(ref)
    tgt_groups = _slots_by_function(tgt)

    # An ID that was retired and had its address reused would let two distinct
    # reference functions claim one target function.  At most one of those
    # edges is right and nothing here can say which, so drop both.
    arrivals: Dict[int, List[int]] = {}
    for ref_addr in ref_groups:
        target_addr = va_translation.get(ref_addr)
        if target_addr is not None:
            arrivals.setdefault(target_addr, []).append(ref_addr)

    for ref_addr, ref_slots in sorted(ref_groups.items()):
        target_addr = va_translation.get(ref_addr)
        if target_addr is None:
            continue
        if len(arrivals.get(target_addr, ())) != 1:
            sm.ambiguous_matches.append({
                'ref_slot': ref_slots[0], 'method': 'address_id_collision',
                'candidates': sorted(arrivals.get(target_addr, ())),
            })
            continue
        tgt_slots = tgt_groups.get(target_addr)
        if not tgt_slots:
            continue                    # function is not in this target table
        if len(tgt_slots) != len(ref_slots):
            sm.ambiguous_matches.append({
                'ref_slot': ref_slots[0], 'method': 'address_id_arity',
                'candidates': list(tgt_slots),
            })
            continue
        for ref_slot, target_slot in zip(ref_slots, tgt_slots):
            if target_slot in used_target_slots:
                continue
            evidence = {
                'target_slot': target_slot, 'method': 'address_library_id',
                'confidence': 'verified',
            }
            # The fingerprint is no longer the decision, but a disagreement is
            # worth surfacing: it is what an ID reused for an unrelated
            # function would look like.
            ref_fp = _normalize_fingerprint(ref.slots[ref_slot].fingerprint)
            tgt_fp = _normalize_fingerprint(tgt.slots[target_slot].fingerprint)
            if ref_fp and tgt_fp and ref_fp != tgt_fp:
                evidence['fingerprint_agrees'] = False
            sm.ref_to_target[ref_slot] = target_slot
            sm.match_evidence[ref_slot] = evidence
            used_target_slots.add(target_slot)


def _match_one_class(ref: ClassVtable, tgt: ClassVtable,
                     va_translation: Optional[Dict[int, int]] = None
                     ) -> ClassShiftMap:
    sm = ClassShiftMap(
        class_name=ref.class_name,
        vtable_id=ref.vtable_id,
        target_vtable_id=tgt.vtable_id,
        subobject_offset=ref.subobject_offset,
        is_primary=ref.is_primary)

    used_target_slots = set()

    # Stage 0: Address Library ID identity, when the caller supplied version
    # libraries for a game whose IDs are version-stable.
    if va_translation:
        _match_by_translated_address(
            ref, tgt, sm, va_translation, used_target_slots)

    # Stage 1: exact name match.  Both sides must be unique: distance is not
    # evidence that one overload/ICF duplicate owns a target slot.
    ref_by_name: Dict[str, List[int]] = {}
    for slot, e in ref.slots.items():
        if e.func_name:
            ref_by_name.setdefault(e.func_name, []).append(slot)
    target_by_name: Dict[str, List[int]] = {}
    for slot, e in tgt.slots.items():
        if e.func_name:
            target_by_name.setdefault(e.func_name, []).append(slot)

    for ref_slot in sorted(ref.slots):
        if ref_slot in sm.ref_to_target:
            continue
        re_ = ref.slots[ref_slot]
        if not re_.func_name:
            continue
        candidates = [slot for slot in target_by_name.get(re_.func_name, [])
                      if slot not in used_target_slots]
        if len(ref_by_name.get(re_.func_name, [])) == 1 and len(candidates) == 1:
            target_slot = candidates[0]
            sm.ref_to_target[ref_slot] = target_slot
            sm.match_evidence[ref_slot] = {
                'target_slot': target_slot, 'method': 'exact_unique_name',
                'confidence': 'verified', 'provenance': re_.func_name,
            }
            used_target_slots.add(target_slot)
        elif candidates:
            sm.ambiguous_matches.append({
                'ref_slot': ref_slot, 'method': 'name',
                'candidates': sorted(candidates), 'name': re_.func_name,
            })

    # Stage 2: exact masked fingerprint matching for ref slots not yet
    # matched.  Candidate uniqueness is evaluated across the *entire physical
    # table*.  A distance-first pass could hide an equally compatible slot
    # outside the first radius and incorrectly bless a common prologue.
    ref_candidates = {}
    target_candidates = {}
    target_fingerprints = {
        slot: _normalize_fingerprint(entry.fingerprint)
        for slot, entry in tgt.slots.items()
    }
    exact_target_by_fingerprint = {}
    wildcard_target_slots = []
    for slot, fingerprint in target_fingerprints.items():
        if not fingerprint:
            continue
        if '?' in fingerprint.split():
            wildcard_target_slots.append(slot)
        else:
            exact_target_by_fingerprint.setdefault(fingerprint, []).append(slot)
    for ref_slot in sorted(ref.slots):
        if ref_slot in sm.ref_to_target:
            continue
        ref_fp = _normalize_fingerprint(ref.slots[ref_slot].fingerprint)
        if not ref_fp:
            continue
        # Raw-byte dumps (the normal cross-version input) are indexed by the
        # complete capture, making reciprocal matching linear rather than
        # quadratic for very large physical tables.  Masked fingerprints use
        # the conservative compatibility scan.
        if '?' in ref_fp.split():
            candidate_pool = sorted(target_fingerprints)
        else:
            candidate_pool = sorted(set(
                exact_target_by_fingerprint.get(ref_fp, []) +
                wildcard_target_slots))
        candidates = []
        for cand in candidate_pool:
            if cand in used_target_slots:
                continue
            if _fingerprints_match(
                    ref_fp, target_fingerprints[cand]):
                candidates.append(cand)
                target_candidates.setdefault(cand, []).append(ref_slot)
        if candidates:
            ref_candidates[ref_slot] = candidates

    # Reciprocal uniqueness: the edge must be the only compatible choice in
    # both directions.  Slot distance is recorded as context, never evidence.
    for ref_slot, candidates in sorted(ref_candidates.items()):
        if len(candidates) != 1:
            sm.ambiguous_matches.append({
                'ref_slot': ref_slot, 'method': 'fingerprint',
                'candidates': candidates,
            })
            continue
        cand = candidates[0]
        if len(target_candidates.get(cand, [])) != 1:
            sm.ambiguous_matches.append({
                'ref_slot': ref_slot, 'method': 'fingerprint_reverse',
                'candidates': target_candidates.get(cand, []),
            })
            continue
        sm.ref_to_target[ref_slot] = cand
        sm.match_evidence[ref_slot] = {
            'target_slot': cand, 'method': 'reciprocal_fingerprint',
            'confidence': 'high', 'slot_distance': abs(cand - ref_slot),
        }
        used_target_slots.add(cand)

    # Stage 3: identify what's left
    sm.unmatched_ref_slots = [s for s in sorted(ref.slots) if s not in sm.ref_to_target]
    sm.target_only_slots = [
        (s, tgt.slots[s]) for s in sorted(tgt.slots) if s not in used_target_slots
    ]

    if sm.unmatched_ref_slots:
        sm.notes.append('{} ref slots have no target match'.format(len(sm.unmatched_ref_slots)))
    if sm.target_only_slots:
        sm.notes.append('{} target-only slots'.format(len(sm.target_only_slots)))
    if sm.ambiguous_matches:
        sm.notes.append('{} ambiguous candidates rejected'.format(len(sm.ambiguous_matches)))

    return sm


def build_shift_map(ref: BinaryLayout, tgt: BinaryLayout,
                    va_translation: Optional[Dict[int, int]] = None) -> ShiftMap:
    """Compute the full ShiftMap from reference binary -> target binary.

    ``va_translation`` maps a reference function address to the same function's
    address in the target, normally derived from the two builds' Address
    Library IDs (see ``versionlib_map``).  Supplying it enables identity-based
    slot matching; omitting it leaves the historical name/fingerprint matching
    untouched, which is what games with version-unstable IDs must use.
    """
    out = ShiftMap(reference_label=ref.binary_label, target_label=tgt.binary_label)
    ref_tables = ref.vtables or {
        vt.vtable_id or class_name: vt for class_name, vt in ref.classes.items()
    }
    tgt_tables = tgt.vtables or {
        vt.vtable_id or class_name: vt for class_name, vt in tgt.classes.items()
    }
    for identity, ref_vt in sorted(ref_tables.items()):
        semantic_candidates = [
            table for table in tgt_tables.values()
            if (table.class_name == ref_vt.class_name and
                table.is_primary == ref_vt.is_primary and
                table.subobject_offset == ref_vt.subobject_offset)
        ]
        exact = [table for table in semantic_candidates
                 if table.vtable_id == ref_vt.vtable_id]
        candidates = exact or semantic_candidates
        tgt_vt = candidates[0] if len(candidates) == 1 else None
        if tgt_vt is None:
            cm = ClassShiftMap(
                class_name=ref_vt.class_name,
                vtable_id=ref_vt.vtable_id or identity,
                subobject_offset=ref_vt.subobject_offset,
                is_primary=ref_vt.is_primary)
            cm.unmatched_ref_slots = sorted(ref_vt.slots.keys())
            cm.notes.append(
                'vtable missing or ambiguous in target binary ({} candidates)'.format(
                    len(candidates)))
        else:
            cm = _match_one_class(ref_vt, tgt_vt, va_translation)
        table_identity = ref_vt.vtable_id or identity
        out.vtables[table_identity] = cm
        if ref_vt.is_primary and ref_vt.class_name not in out.classes:
            out.classes[ref_vt.class_name] = cm
    return out


def save_json(sm: ShiftMap, path: str) -> None:
    """Write a shift map, compressing when the path asks for it.

    A full Starfield map carries per-slot evidence for ~233k slots and runs to
    ~111 MB as plain JSON -- past the size GitHub will store.  A ``.gz`` path
    writes the identical document through gzip (~3 MB); every other path is
    unchanged, so the maps other games already ship keep their format.
    """
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    if path.endswith('.gz'):
        import gzip
        payload = json.dumps(sm.to_json(), indent=2, sort_keys=True).encode('utf-8')
        with open(path, 'wb') as raw:
            # mtime=0: the artifact is hashed, so it must not differ run to run.
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                               mtime=0) as compressed:
                compressed.write(payload)
        return
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sm.to_json(), f, indent=2, sort_keys=True)


def load_json(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    if path.endswith('.gz'):
        import gzip
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            return json.load(f)
    with open(path, encoding='utf-8') as f:
        return json.load(f)
