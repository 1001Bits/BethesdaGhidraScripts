"""Pure (Ghidra-free) logic for cross-version field propagation (SE <-> AE <-> VR).

The three runtimes share CommonLib's class layout but at DIFFERENT Ghidra offsets (VR
structs are larger, fields shift). What is stable across them is the CommonLib offset
encoded in an unk*/pad*/fld* field NAME ('fld30580' -> 0x30580) -- CommonLib names
unknown members `unkNN` by their offset, and the population apply renames a resolved
field `fldNN` keeping those digits. So a field resolved in one runtime can be carried
to the SAME field in another by NAME, not raw offset.

This module decides what to export from a runtime (a field a runtime resolved) and
what a target runtime can receive (a still-unknown field at the same CommonLib
offset), plus how to reconcile types when runtimes disagree. The driver does the
Ghidra I/O; the apply reuses the improve-or-nop guarantee (validate on a copy, never
grow/clobber). Kept Ghidra-free so the keying + reconciliation are unit-testable.
"""
import collections
import re

# unk/pad/fld/off_ + hex digits -> the CommonLib offset, the cross-version key.
_KEY = re.compile(r'^(?:unk|pad|fld|off_)([0-9A-Fa-f]+)$')

# Size-only generics (no semantic content): not worth propagating, and a target slot
# carrying one is still "unknown" enough to receive a real type.
_GENERIC = {
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'void', 'longlong', 'ulonglong', 'long', 'ulong', 'int', 'uint', 'short',
    'ushort', 'char', 'uchar', 'byte', 'sbyte', 'bool', 'float', 'double',
    'word', 'dword', 'qword', 'pointer', 'code',
}


def field_key(name):
    """The cross-version-stable CommonLib offset encoded in a field name
    ('fld30580'/'unk30580'/'pad30580' -> 0x30580), or None for a semantic name
    (e.g. 'worldSpace' -- already named in every runtime, nothing to propagate)."""
    if not name:
        return None
    m = _KEY.match(name.strip())
    return int(m.group(1), 16) if m else None


def _strip(typename):
    t = (typename or '').replace(' ', '')
    while t.endswith('*') or t.endswith('64'):
        t = t[:-2] if t.endswith('64') else t[:-1]
    return t


def is_concrete(typename):
    """A real named type (struct/class/enum), not a size-only generic."""
    t = _strip(typename)
    if not t:
        return False
    low = t.lower()
    return not low.startswith('undefined') and low not in _GENERIC


def is_resolved(name, typename):
    """Field worth EXPORTING as cross-version knowledge: an offset-keyed name AND a
    concrete type -- a runtime figured this field out."""
    return field_key(name) is not None and is_concrete(typename)


def is_unknown_target(name, typename):
    """Field that can RECEIVE knowledge: an offset-keyed name AND still unknown
    (no concrete type yet)."""
    return field_key(name) is not None and not is_concrete(typename)


def pick_best_type(typenames):
    """Reconcile the type when runtimes disagree for one (class, offset). Returns
    (best, conflict): the most-agreed type (tie-break: longer/more-specific name, then
    lexical for determinism); conflict=True if runtimes proposed different concrete
    types. Generic proposals are ignored when any concrete one exists."""
    concrete = [t for t in typenames if is_concrete(t)]
    pool = concrete or list(typenames)
    if not pool:
        return (None, False)
    counts = collections.Counter(pool)
    best = max(counts, key=lambda t: (counts[t], len(t), t))
    conflict = len(set(concrete)) > 1
    return (best, conflict)
