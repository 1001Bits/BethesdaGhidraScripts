"""Shared Ghidra-runtime helpers for the CommonLibVR import pipeline.

These were copy-pasted verbatim across the apply drivers (crossver.py,
apply_review.py, commonlib_discover.py, populate_cycle.py): the same
`_struct_metrics`, `_resolve_type`, `/types.h`-struct iteration and name index.
Consolidated here so there is ONE definition to fix.

Deliberately Ghidra-import-free: every function is duck-typed against the Ghidra
DataType / DataTypeManager / Structure API (s.getNumComponents(), dtm.getPointer,
dt.getCategoryPath, ...), so the module loads in plain CPython too and the logic is
unit-testable with light fakes. Drivers load it the same way they load the *_plan
modules (importlib.spec_from_file_location against SCRIPT_DIR).
"""


def struct_metrics(s):
    """(length, protected_bytes) for a Ghidra Structure. protected_bytes = bytes of
    components carrying RE we must not lose: a real (non-unk*/pad*) field name AND a
    non-undefined type. The improve-or-nop invariant for an apply is: length UNCHANGED
    and protected_bytes NOT DECREASED (see populate_plan.is_struct_change_safe). A good
    apply (unk slot -> named concrete field, same size) raises protected_bytes; a
    struct-growth changes length; a clobber of a real field drops protected_bytes."""
    pb = 0
    for i in range(s.getNumComponents()):
        c = s.getComponent(i)
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if not fn.startswith(('unk', 'pad')) and 'undefined' not in tn:
            pb += c.getLength()
    return s.getLength(), pb


def resolve_type(dtm, by_name, name):
    """Resolve a type string (e.g. `Actor *`, `NavMeshInfoMap *64`, `TESForm`) to a
    live DataType. Strips Ghidra pointer/`*64` width decoration to a base name, looks
    it up in `by_name` (build it with build_by_name, which prefers /types.h), and
    re-applies the pointer depth. None if the base name is absent (reported for fixup)."""
    t = name.strip()
    ptr = 0
    while True:
        t = t.strip()
        if t.endswith('64') and t[:-2].rstrip().endswith('*'):
            t = t[:-2]
        elif t.endswith('*'):
            t = t[:-1]
            ptr += 1
        else:
            break
    base = by_name.get(t.strip())
    if base is None:
        return None
    dt = base
    for _ in range(ptr):
        dt = dtm.getPointer(dt, 8)
    return dt


def types_structs(dtm):
    """Iterate the live /types.h StructureDB types (the CommonLib-canonical structs the
    pipeline populates)."""
    for dt in dtm.getAllDataTypes():
        if (dt.getClass().getSimpleName() == 'StructureDB'
                and 'types.h' in str(dt.getCategoryPath())):
            yield dt


def build_by_name(dtm):
    """type name -> a live DataType, preferring the /types.h definition when a name has
    duplicates. The lookup table resolve_type consumes."""
    by_name = {}
    for dt in dtm.getAllDataTypes():
        nm = dt.getName()
        if nm not in by_name or 'types.h' in str(dt.getCategoryPath()):
            by_name[nm] = dt
    return by_name


def unk_offsets(dt):
    """Pointer-sized offsets a /types.h struct still leaves unknown (unk/pad field name
    or undefined type) -- the harvest surface for field discovery. {offset: cur_name}."""
    offs = {}
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if c.getLength() >= 8 and (fn.startswith(('unk', 'pad')) or 'undefined' in tn):
            offs[c.getOffset()] = fn or ('off_%X' % c.getOffset())
    return offs


def useful_typename(tn):
    """A decompiler-inferred type worth recording: not undefined, not an array, not a
    bare scalar/void (those carry no class RE)."""
    if not tn or 'undefined' in tn or '[' in tn:
        return False
    return tn not in ('char', 'byte', 'bool', 'void')


def param0_class_name(func):
    """Base type name of a function's param-0 (`this`), stripped of pointer/`*64`
    decoration -- '' if the function has no parameters. The key for grouping a class's
    own methods (used by the discovery/ctor miners)."""
    ps = func.getParameters()
    if not ps:
        return ''
    return ps[0].getDataType().getName().rstrip('64').rstrip(' *')
