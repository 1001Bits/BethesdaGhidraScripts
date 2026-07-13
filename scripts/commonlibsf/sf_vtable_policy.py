"""Fail-closed vtable overlay policy for non-anchor Starfield builds.

CommonLib headers describe one canonical build.  On another executable, a
header-shaped vtable must never survive merely because a layout diff did not
contain enough evidence to patch it.  This module keeps only physical tables
that resolve one-to-one and whose observed slot mapping covers both the binary
reference table and the header-derived structure.
"""
from __future__ import annotations


MIN_COVERAGE = 0.75


def _candidate_struct_keys(class_name):
    yield class_name
    if '::' not in class_name:
        yield 'RE::' + class_name
    elif class_name.startswith('RE::'):
        yield class_name[len('RE::'):]


def _resolve_struct(vtable_structs, class_name, subobject_offset, is_primary):
    candidates = tuple(_candidate_struct_keys(class_name))
    if is_primary:
        found = [(key, vtable_structs[key]) for key in candidates
                 if key in vtable_structs]
    else:
        found = []
        for class_key in candidates:
            key = '{}|secondary|{}'.format(class_key, subobject_offset)
            if key in vtable_structs:
                found.append((key, vtable_structs[key]))
        if not found:
            found = [
                (key, struct) for key, struct in vtable_structs.items()
                if (struct.get('class_full_name') in candidates and
                    struct.get('vtable_kind') == 'secondary' and
                    int(struct.get('subobject_offset', -1)) == subobject_offset)
            ]
    return found[0] if len(found) == 1 else None


def _slot_number(value):
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def strict_patch_vtable_structs(vtable_structs, shift_map_json,
                                version_label, verbose=True):
    """Patch and retain only strongly resolved physical vtable structures.

    Any absent, ambiguous, malformed, or low-coverage table is removed.  A
    pair of physical records resolving to the same header structure aborts the
    build because choosing either one would silently assign the wrong ABI.
    """
    physical = shift_map_json.get('vtables') if shift_map_json else None
    if not isinstance(physical, dict) or not physical:
        raise ValueError(
            'non-anchor SF vtable overlays require a full physical-table map')

    resolved = []
    resolution_counts = {}
    for identity, entry in physical.items():
        if not isinstance(entry, dict):
            raise ValueError('malformed SF physical vtable record {}'.format(identity))
        class_name = str(entry.get('class_name') or '').strip()
        if not class_name:
            raise ValueError('SF physical vtable record has no class identity')
        primary_text = entry.get('is_primary', True)
        is_primary = (primary_text if isinstance(primary_text, bool) else
                      str(primary_text).lower() not in ('0', 'false', 'no'))
        try:
            subobject_offset = _slot_number(entry.get('subobject_offset', 0))
        except (TypeError, ValueError) as exc:
            raise ValueError('invalid SF vtable subobject offset') from exc
        target = _resolve_struct(
            vtable_structs, class_name, subobject_offset, is_primary)
        if target is None:
            continue
        struct_key, struct = target
        resolution_counts[struct_key] = resolution_counts.get(struct_key, 0) + 1
        resolved.append((struct_key, struct, entry))

    races = sorted(key for key, count in resolution_counts.items() if count != 1)
    if races:
        raise ValueError(
            'multiple physical SF vtables resolve to header struct(s): {}'.format(
                ', '.join(races[:10])))

    safe = {}
    for struct_key, struct, entry in resolved:
        try:
            ref_to_target = {
                _slot_number(ref): _slot_number(target)
                for ref, target in (entry.get('ref_to_target') or {}).items()
            }
            unmatched = entry.get('unmatched_ref_slots') or []
            declared = int(entry.get(
                'reference_slot_count', len(ref_to_target) + len(unmatched)))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError('malformed SF slot mapping for {}'.format(struct_key)) from exc
        if (any(ref < 0 or target < 0 for ref, target in ref_to_target.items()) or
                len(set(ref_to_target.values())) != len(ref_to_target)):
            raise ValueError('non-bijective SF slot mapping for {}'.format(struct_key))

        old_slots = list(struct.get('slots') or [])
        old_indices = {int(slot[0]) // 8 for slot in old_slots}
        reference_denominator = max(declared, len(ref_to_target) + len(unmatched), 1)
        header_denominator = max(len(old_indices), 1)
        if (len(ref_to_target) / float(reference_denominator) < MIN_COVERAGE or
                len(old_indices & set(ref_to_target)) /
                float(header_denominator) < MIN_COVERAGE):
            continue

        new_slots = []
        occupied = set()
        for slot in old_slots:
            ref_slot = int(slot[0]) // 8
            if ref_slot not in ref_to_target:
                continue
            target_slot = ref_to_target[ref_slot]
            if target_slot in occupied:
                raise ValueError('colliding SF target slot for {}'.format(struct_key))
            occupied.add(target_slot)
            new_slots.append((target_slot * 8, slot[1], slot[2], slot[3]))

        for target_only in entry.get('target_only_slots') or []:
            try:
                target_slot = _slot_number(target_only['slot'])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    'malformed target-only SF slot for {}'.format(struct_key)) from exc
            if target_slot < 0 or target_slot in occupied:
                raise ValueError('colliding target-only SF slot for {}'.format(struct_key))
            occupied.add(target_slot)
            label = target_only.get('func_name') or '__{}_only_0x{:X}'.format(
                version_label, target_slot)
            new_slots.append((target_slot * 8, label, None, None))

        if not new_slots:
            continue
        new_slots.sort(key=lambda slot: slot[0])
        struct['slots'] = new_slots
        struct['size'] = new_slots[-1][0] + 8
        safe[struct_key] = struct

    original_count = len(vtable_structs)
    vtable_structs.clear()
    vtable_structs.update(safe)
    if verbose:
        print('  retained {} / {} non-anchor SF vtable struct(s); '
              'unresolved/ambiguous/low-coverage tables omitted'.format(
                  len(safe), original_count))
    return vtable_structs

