"""Build-time vtable struct patcher.

Applies a per-version shift map (from ``vtable_matcher.build_shift_map``)
to the ``vtable_structs`` dict produced by ``ghidra_import_gen.build_vtable_structs``.

For each class with a shift map entry:
  * Each slot in the header-shaped vtable struct gets its byte offset
    remapped to the version's actual binary slot.  Field name is unchanged.
  * Ref slots with no target match are dropped from the version's struct.
  * Target-only slots (new in this version) get placeholder fields
    ``__<version>_only_0xXX`` so the struct overlay is complete.

The caller is expected to run the anchor verifier *after* patching to
sanity-check the result against a hand-curated truth table.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple


def _candidate_struct_keys(class_name: str):
    yield class_name
    if '::' not in class_name:
        yield 'RE::' + class_name
    elif class_name.startswith('RE::'):
        yield class_name[len('RE::'):]


def _resolve_struct(vtable_structs: dict, class_name: str,
                    subobject_offset: int = 0,
                    is_primary: bool = True) -> Optional[Tuple[str, dict]]:
    if not is_primary:
        for class_key in _candidate_struct_keys(class_name):
            key = '{}|secondary|{}'.format(class_key, subobject_offset)
            st = vtable_structs.get(key)
            if st is not None:
                return key, st
        # Metadata is more reliable than a caller's namespace spelling.
        matches = [(key, st) for key, st in vtable_structs.items()
                   if (st.get('class_full_name') in tuple(_candidate_struct_keys(class_name))
                       and st.get('vtable_kind') == 'secondary'
                       and int(st.get('subobject_offset', -1)) == subobject_offset)]
        return matches[0] if len(matches) == 1 else None
    for key in _candidate_struct_keys(class_name):
        st = vtable_structs.get(key)
        if st is not None:
            return key, st
    return None


def patch_vtable_structs(vtable_structs: dict, shift_map_json: dict,
                          version_label: str, verbose: bool = True) -> dict:
    """Apply a shift map JSON (as returned by ShiftMap.to_json) to vtable_structs.

    Mutates and returns ``vtable_structs``.  Each class entry's ``slots``
    list (tuples of ``(byte_off, name, ret, params)``) is replaced.

    Classes without a shift-map entry are left untouched -- this is by
    design, so a partial shift map (covering just hot classes) still
    works; uncovered classes fall back to the header-shaped layout and
    the anchor verifier will catch any drift for those.
    """
    if not shift_map_json or not ({'classes', 'vtables'} & set(shift_map_json)):
        return vtable_structs

    # Schema v2 carries every physical table.  Legacy maps expose primaries
    # only through ``classes``.
    sm_classes = shift_map_json.get('vtables') or shift_map_json.get('classes', {})
    n_patched = 0
    n_unmatched_classes = 0
    n_low_coverage = 0
    resolved_entries = []

    for identity, sm_entry in sm_classes.items():
        cls_name = sm_entry.get('class_name') or identity
        primary_text = sm_entry.get('is_primary', True)
        is_primary = (primary_text if isinstance(primary_text, bool) else
                      str(primary_text).lower() not in ('0', 'false', 'no'))
        try:
            subobject_offset = int(str(sm_entry.get('subobject_offset', '0')), 0)
        except ValueError:
            n_unmatched_classes += 1
            continue
        resolved = _resolve_struct(vtable_structs, cls_name,
                                   subobject_offset, is_primary)
        if not resolved:
            n_unmatched_classes += 1
            continue
        struct_key, struct = resolved
        resolved_entries.append((struct_key, struct, sm_entry))

    # Never let two physical-table records race to rewrite one struct.  This
    # indicates an unresolved duplicate COL/subobject identity.
    counts = {}
    for struct_key, _struct, _entry in resolved_entries:
        counts[struct_key] = counts.get(struct_key, 0) + 1

    for struct_key, struct, sm_entry in resolved_entries:
        if counts[struct_key] != 1:
            n_unmatched_classes += 1
            continue
        ref_to_target = {
            int(k, 16): int(v, 16)
            for k, v in sm_entry.get('ref_to_target', {}).items()
        }
        target_only = sm_entry.get('target_only_slots', []) or []

        old_slots = struct.get('slots', [])
        try:
            declared_ref_count = int(sm_entry.get(
                'reference_slot_count',
                len(ref_to_target) + len(sm_entry.get('unmatched_ref_slots', []) or [])))
        except (TypeError, ValueError):
            declared_ref_count = 0
        denominator = max(declared_ref_count, len(old_slots), 1)
        # An unmatched slot is uncertainty, not proof of removal.  Sparse
        # maps used to erase nearly entire vtable structs.  Apply only when a
        # strong majority of the reference table is reciprocally aligned.
        if len(ref_to_target) / float(denominator) < 0.75:
            n_low_coverage += 1
            continue
        new_slots = []
        for slot in old_slots:
            # slot tuple: (byte_off, name, ret, params)
            byte_off, name, ret, params = slot[0], slot[1], slot[2], slot[3]
            ref_slot = byte_off // 8
            if ref_slot in ref_to_target:
                new_byte_off = ref_to_target[ref_slot] * 8
                new_slots.append((new_byte_off, name, ret, params))
            # else: drop -- this slot doesn't exist in target

        # Add target-only placeholder fields
        for entry in target_only:
            tgt_slot = int(entry['slot'], 16)
            label = entry.get('func_name') or '__{}_only_{}'.format(
                version_label, entry['slot'])
            # Sanitize: '__only_' fields shouldn't collide with real names
            new_slots.append((tgt_slot * 8, label, None, None))

        # Re-sort by byte offset and recompute size
        new_slots.sort(key=lambda t: t[0])
        max_off = new_slots[-1][0] if new_slots else 0
        struct['slots'] = new_slots
        struct['size'] = max_off + 8 if new_slots else struct.get('size', 0)
        n_patched += 1

    if verbose:
        print('  patched {} class vtable struct(s) via shift map [{}]'.format(
            n_patched, version_label))
        if n_unmatched_classes:
            print('  {} shift-map classes had no matching vtable_structs entry'.format(
                n_unmatched_classes))
        if n_low_coverage:
            print('  {} vtable shift(s) skipped: less than 75% matched coverage'.format(
                n_low_coverage))

    return vtable_structs
