"""Pure (Ghidra-free) aggregation for the CommonLib<->Ghidra discovery cycle.

The bootstrap (CommonLib types/sigs into Ghidra) lets Ghidra's decompiler dataflow
(FillOutStructureHelper) infer field types at offsets CommonLib still marks `unk`.
This module turns the per-function inferences into ranked, confidence-scored field
candidates to feed back to CommonLib -- which, re-imported, lets the next cycle
propagate one level deeper. Kept Ghidra-free so the ranking is unit-testable.
"""
import collections

# Types the decompiler emits when it knows the SIZE but not the semantic type --
# real but low-value (they only tell CommonLib "one 8-byte field, not padding").
GENERIC_TYPES = {
    'ulonglong', 'longlong', 'uint64', 'int64', 'undefined8', 'void *',
    'ulong', 'long', 'uint', 'int', 'pointer',
}


def _is_named(typename):
    """A concrete, semantically meaningful type (named struct or pointer-to-named),
    as opposed to a generic size-only inference."""
    return bool(typename) and typename not in GENERIC_TYPES


def aggregate_inferences(observations):
    """Aggregate (class, offset, typename) observations across functions.

    Returns {(class, offset): {'type', 'votes', 'total', 'named', 'confidence'}}:
      type       the chosen inferred type (a named type beats a generic one; ties
                 break on vote count)
      votes      how many functions agreed on `type`
      total      how many functions inferred ANY concrete type at this offset
      named      True if `type` is a semantic type (not size-only)
      confidence 'high' if a named type, or a generic agreed by >=2 functions;
                 else 'low'
    """
    by = collections.defaultdict(collections.Counter)
    for cls, off, typ in observations:
        if typ:
            by[(cls, off)][typ] += 1

    out = {}
    for key, counter in by.items():
        # prefer a named type, then higher vote count
        best = max(counter.items(), key=lambda kv: (_is_named(kv[0]), kv[1]))
        typ, votes = best
        total = sum(counter.values())
        named = _is_named(typ)
        confidence = 'high' if (named or total >= 2) else 'low'
        out[key] = {'type': typ, 'votes': votes, 'total': total,
                    'named': named, 'confidence': confidence}
    return out


def to_rows(aggregated, unk_name):
    """Flatten aggregated results to sortable rows for CSV output.

    unk_name(cls, off) -> the current CommonLib field name at that offset (e.g.
    'unk88'). Rows: (class, offset, current_name, inferred_type, confidence,
    votes, total), sorted named/high-confidence first, then class, then offset.
    """
    rows = []
    for (cls, off), info in aggregated.items():
        rows.append((cls, off, unk_name(cls, off), info['type'],
                     info['confidence'], info['votes'], info['total']))
    rows.sort(key=lambda r: (r[4] != 'high', r[0], r[1]))
    return rows
