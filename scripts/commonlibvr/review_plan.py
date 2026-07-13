"""Pure (Ghidra-free) logic for the optional LLM-review lever of the population cycle.

The automated cycle converges against rules it can express; what's left sits in skip
buckets -- chiefly `generic-size-only`: offsets where the decompiler is confident a
pointer-sized FIELD exists (many functions agree) but could only infer a size, not a
semantic type. That naming is exactly an LLM/human judgement call. This module decides:

  * is_review_worthy() -- which unresolved candidates are worth a human's time (strong
    consensus that a field exists, but no name), so the queue is a ranked worklist, not
    a dump of every undefined byte;
  * parse_decision() -- normalize the decision an LLM writes back (a concrete type, or
    an explicit pass), so the apply step is unambiguous.

The queue is emitted by commonlib_discover; the decisions are applied by apply_review
as SourceType.USER_DEFINED (authoritative -- outranks the cycle's ANALYSIS seeds and a
CommonLib re-import keeps a human's call). Each resolved field is a new anchor, so the
next automated cycle discovers MORE from it: review breaks the convergence plateau.
Kept Ghidra-free so both decisions are unit-testable.
"""

# Decision-cell values that mean "no action" (reviewer left it / explicitly passed).
_NOOP = ('', 'skip', '?', 'unknown', 'tbd', 'n/a', 'na', 'none')


def is_review_worthy(named, total, votes, min_total=2):
    """Should an unresolved candidate go on the review queue?

    Yes when the decompiler agrees a field EXISTS but could not name it:
      * `named` is False  -- a concrete type was auto-applied already, nothing to ask;
      * `total >= min_total` -- enough independent functions observed a field at this
        offset that it is real, not decompiler noise.
    A single-observation generic is too weak to spend a human on (left for more
    discovery first). Returns (worthy: bool, reason: str).
    """
    if named:
        return (False, 'auto-applied')
    if total < min_total:
        return (False, 'too-weak')
    return (True, 'size-only-consensus')


def review_rank(total, votes):
    """Sort key for the queue: strongest evidence first (most observers, then most
    agreement). Higher is reviewed first."""
    return (total, votes)


def parse_decision(cell):
    """Normalize an LLM/human decision cell into a type to apply, or None.

    '' / 'skip' / '?' / 'unknown' / 'tbd' / 'none' -> None (no action). Anything else
    is treated as a Ghidra type name (trimmed); the applier resolves and size-checks it.
    """
    if cell is None:
        return None
    t = cell.strip()
    if t.lower() in _NOOP:
        return None
    return t
