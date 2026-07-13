"""Pure (Ghidra-free) logic for the in-Ghidra population cycle orchestrator.

The cycle drives Ghidra to a fixpoint WITHOUT leaving Ghidra: each pass widens the
typed surface (thiscall), propagates concrete param/return types, then infers and
APPLIES struct-field types -- and the newly-typed fields become anchors the next
pass propagates from. This module holds the two rule-expressible decisions:

  * should_apply_field() -- whether a discovered field is safe to write into a
    /types.h struct (fill an unknown slot with a concrete same-size type; never
    clobber existing RE, never write a size-only generic);
  * coverage_delta()/is_converged() -- turn before/after coverage snapshots into a
    per-cycle progress number and decide when the cycle has reached a fixpoint.

Kept Ghidra-free so both are unit-testable; the drivers supply the live numbers.
"""

# Size-only inferences (the decompiler knew the width, not the semantics). Writing
# these into a struct just replaces an honest `unkNN` with an equally-opaque
# `longlong` -- the same net-negative the propagation filter avoids -- so the
# applier skips them and keeps only concrete named types.
_GENERIC_TYPES = {
    'ulonglong', 'longlong', 'uint64', 'int64', 'undefined8', 'void *', 'void*',
    'ulong', 'long', 'uint', 'int', 'pointer', 'undefined', 'undefined4',
    'undefined2', 'undefined1', 'byte', 'char', 'bool', 'short', 'ushort',
}


def _is_unknown_field(name, typename):
    """True if a struct slot carries no RE yet (so filling it is additive, not a
    clobber): an unk*/pad* name OR an undefined/empty type."""
    n = (name or '').lower()
    t = (typename or '')
    return n.startswith(('unk', 'pad', 'off_')) or t == '' or 'undefined' in t


def is_generic_type(typename):
    """True if a type is a size-only generic (no semantic content). Strips pointer
    and width decoration first so `void *64`, `undefined8 *`, `longlong` all read as
    generic (a bare `void *` carries no more RE than the `unkNN` it would replace)."""
    if not typename:
        return True
    t = typename.replace(' ', '')
    # a decorated bare-void/undefined pointer is still generic
    base = t
    while base.endswith('*') or base.endswith('64'):
        base = base[:-2] if base.endswith('64') else base[:-1]
    low = base.lower()
    if low == '' or low.startswith('undefined') or low == 'void':
        return True
    return t in _GENERIC_TYPES or low in {
        'ulonglong', 'longlong', 'uint64', 'int64', 'ulong', 'long', 'uint', 'int',
        'pointer', 'byte', 'char', 'bool', 'short', 'ushort', 'word', 'dword', 'qword',
    }


def should_apply_field(cur_name, cur_type, inferred_type, inferred_len, slot_len,
                       confidence):
    """Decide whether to write a discovered field into a /types.h struct.

    Apply ONLY when it is a strict, no-risk gain:
      * the current slot is unknown (unk*/pad* name or undefined type) -- nothing
        real to lose;
      * the inferred type is a concrete named type (not a size-only generic);
      * the discovery is high-confidence (named consensus);
      * the inferred type's size matches the slot exactly (no field shifting /
        overlap into the next member).
    Returns (apply: bool, reason: str).
    """
    if not _is_unknown_field(cur_name, cur_type):
        return (False, 'slot-already-typed')
    if confidence != 'high':
        return (False, 'low-confidence')
    if is_generic_type(inferred_type):
        return (False, 'generic-size-only')
    if inferred_len != slot_len:
        return (False, 'size-mismatch')
    return (True, 'ok')


# Coverage metrics that should monotonically improve until the cycle converges.
# Field coverage is measured in BYTES, not component count: carving a typed field
# out of a larger `undefined` region fragments the remainder into more components,
# so a component COUNT can rise even when real RE was added -- a false regression.
# Bytes are conserved (a 12-byte field typed = 12 fewer unknown bytes, always), so
# unk_field_bytes shrinks monotonically. thiscall/typed_params go UP; unk_field_bytes
# goes DOWN; named_field_bytes is reported but NOT scored (it mirrors unk_field_bytes,
# so scoring both would double-count a single resolved field).
COVERAGE_KEYS = ('thiscall', 'named_field_bytes', 'unk_field_bytes', 'typed_params')


def coverage_delta(before, after):
    """Per-key (after - before) for a coverage snapshot dict."""
    return {k: after.get(k, 0) - before.get(k, 0) for k in COVERAGE_KEYS}


def progress(delta):
    """Single scalar of forward progress in a cycle: more thiscall members and
    typed params, fewer unknown struct bytes (a negative unk_field_bytes delta is
    positive progress)."""
    return (delta.get('thiscall', 0)
            + delta.get('typed_params', 0)
            - delta.get('unk_field_bytes', 0))


def is_struct_change_safe(before, after):
    """Improve-or-nop guard for a single struct apply. `before`/`after` are
    (length, protected_bytes) snapshots of the struct (protected_bytes = bytes in
    real, non-unk*/pad*, non-undefined fields). The change is safe ONLY if the struct
    did not grow OR shrink AND lost no protected RE -- a good apply just turns an
    unknown slot into a named field at the same size. The drivers compute these on a
    DETACHED struct.copy() and apply to the live struct only when this returns True,
    so an apply can never grow a struct (the MapMenu 0x30560->0x60880 corruption) or
    clobber existing RE -- it can only improve the struct or be skipped."""
    return after[0] == before[0] and after[1] >= before[1]


def is_regression(delta):
    """Negative net progress -- a pass made the program WORSE by the metrics. Never
    a fixpoint; a signal that the apply did something destructive and the loop
    should stop and be inspected, not declare success."""
    return progress(delta) < 0


def is_converged(delta, min_gain=5):
    """The cycle has reached a (practical) fixpoint when a pass yields between 0 and
    `min_gain` net improvements -- diminishing returns, no regression. A regression
    (progress < 0) is NOT convergence (see is_regression)."""
    return 0 <= progress(delta) < min_gain
