"""Pure (Ghidra-free) logic for the duplicate-type deduper.

Loading a program's MS PDB alongside the CommonLib import leaves DUPLICATE types per
name -- the Ghidra auto-conflict copies (`X.conflict`, `X.conflict1`) and the
`/SkyrimSE.pdb/X` vs `/types.h/X` twins. Signatures/struct-fields that reference a
duplicate don't benefit from RE on the canonical type (132 of ~2.5k AE typed
signatures pointed at `/SkyrimSE.pdb/*` twins). The fix is to MERGE each duplicate
into one keeper with `dtm.replaceDataType(dup, keeper)`, which rewires every
reference -- so signatures finally point at the populated canonical type.

This module decides, per name-group of variants, the keeper and which to merge --
but ONLY when it is unambiguous (all variants share one size). When sizes DIFFER it
refuses and flags the group for binary verification (the established rule: the
in-memory `Memory::Allocate` size is ground truth, not CommonLib or the PDB blindly).
Kept Ghidra-free so the keeper choice is unit-testable; the driver does replaceDataType.
"""


def base_name(name):
    """Strip Ghidra's `.conflictN` suffix to the real type name
    ('TESForm.conflict1' -> 'TESForm')."""
    i = name.find('.conflict')
    return name[:i] if i >= 0 else name


def _rank(v):
    # keeper preference (lower = better): a CLEAN (non-.conflict) name always beats a
    # .conflict copy -- we never want an ugly `.conflict` name to become canonical;
    # then the /types.h CommonLib type the pipeline treats as canonical; then, only as
    # a tiebreak, the most-populated variant.
    #
    # NOTE: ndefined is a TIEBREAK ONLY, never a gate. A properly-inherited CommonLib
    # type (e.g. TESBoundObject = `_base: TESObject` + boundData, 3 direct members) has
    # FEWER direct members than its PDB-FLATTENED `.conflict` twin (which inlines the
    # base class: vftable + FormID + flags + ... = 9 members) yet describes the SAME
    # 0x30 bytes and loses no RE -- the flattened members live inside `_base`. So we
    # must NOT refuse a same-size merge just because the clean keeper has fewer defined
    # components; that would strand references on the flattened `.conflict` copy.
    is_conf = '.conflict' in v.get('name', '')
    is_th = 'types.h' in v.get('category', '')
    return (1 if is_conf else 0, 0 if is_th else 1, -int(v.get('ndefined', 0)))


def plan_merge(variants):
    """Decide how to dedup one name-group. `variants` is a list of dicts with keys
    'key' (unique id), 'name', 'category', 'size', 'ndefined'.

    Returns (keeper_key, [merge_keys], conflict, reason):
      * conflict=True, keeper=None when the variants DISAGREE on size -- a real layout
        question routed to binary verification (the in-memory `Memory::Allocate` size
        is ground truth, not CommonLib or the PDB blindly).
      * otherwise keeper = the preferred same-size variant (clean /types.h canonical),
        merge_keys = the rest (replaceDataType them into the keeper). Same size means
        same byte extent, so the merge only rewires references at the canonical type --
        it never changes a layout.
    A single variant (no dup) returns (its key, [], False, 'no-dup')."""
    if not variants:
        return (None, [], False, 'empty')
    if len(variants) == 1:
        return (variants[0]['key'], [], False, 'no-dup')
    sizes = set(v['size'] for v in variants if v['size'] is not None and v['size'] >= 0)
    if len(sizes) > 1:
        return (None, [], True, 'size-conflict')
    ordered = sorted(variants, key=_rank)
    keeper, merges = ordered[0], ordered[1:]
    return (keeper['key'], [m['key'] for m in merges], False, 'same-size')
