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


def _match_one_class(ref: ClassVtable, tgt: ClassVtable) -> ClassShiftMap:
    sm = ClassShiftMap(
        class_name=ref.class_name,
        vtable_id=ref.vtable_id,
        target_vtable_id=tgt.vtable_id,
        subobject_offset=ref.subobject_offset,
        is_primary=ref.is_primary)

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

    used_target_slots = set()
    for ref_slot in sorted(ref.slots):
        re_ = ref.slots[ref_slot]
        if not re_.func_name:
            continue
        candidates = target_by_name.get(re_.func_name, [])
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


def build_shift_map(ref: BinaryLayout, tgt: BinaryLayout) -> ShiftMap:
    """Compute the full ShiftMap from reference binary -> target binary."""
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
            cm = _match_one_class(ref_vt, tgt_vt)
        table_identity = ref_vt.vtable_id or identity
        out.vtables[table_identity] = cm
        if ref_vt.is_primary and ref_vt.class_name not in out.classes:
            out.classes[ref_vt.class_name] = cm
    return out


def save_json(sm: ShiftMap, path: str) -> None:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sm.to_json(), f, indent=2, sort_keys=True)


def load_json(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)
