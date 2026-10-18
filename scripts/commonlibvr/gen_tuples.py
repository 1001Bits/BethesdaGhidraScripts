"""One place that knows the tuple shapes a generated CommonLibImport_*.py emits.

``core/ghidra_import_gen.py`` grew its records:

    STRUCTS  (name, full_name, record_kind, size, category, fields, bases, has_vtable)
    ENUMS    (name, full_name, size, category, values)
    VTABLES  (vname, class_full_name, vtbl_size, category, slots,
              vtable_kind, subobject_offset)

while ``apply_enrich.py`` / ``conflict_report.py`` / ``apply_plan.py`` still
index the older 6/4/5-tuples -- positionally, so ``st[1]`` silently became the
C++ full name instead of the size, and every explicit unpack raised
``ValueError: too many values to unpack`` on the first struct.

Consumers normalise at the LOAD boundary through this module and keep their
existing (legacy) indexing.  Both generations are accepted; an unknown arity is
an error, never a guess.
"""

from __future__ import annotations

LEGACY_STRUCT = ('name', 'size', 'category', 'fields', 'bases', 'has_vtable')
LEGACY_ENUM = ('name', 'size', 'category', 'values')
LEGACY_VTABLE = ('vname', 'class_full_name', 'vtbl_size', 'category', 'slots')

# apply_enrich lays members out sequentially by offset.  A union's members all
# sit at offset 0 and a 'namespace' pseudo-record owns free functions, not
# storage; neither can be expressed by that code, and a wrong layout is worse
# than none, so they are left to the generated importer itself.
LAYOUT_KINDS = ('struct', 'class')


def legacy_struct(record):
    """6-tuple for a struct/class record, or None for a union/namespace."""
    record = tuple(record)
    if len(record) == 8:
        (name, _full_name, record_kind, size, category, fields, bases,
         has_vtable) = record
        if record_kind not in LAYOUT_KINDS:
            return None
        return (name, size, category, fields, bases, has_vtable)
    if len(record) == 6:
        return record
    raise ValueError('unsupported STRUCTS record with {} fields: {!r}'.format(
        len(record), record[:2]))


def legacy_enum(record):
    record = tuple(record)
    if len(record) == 5:
        name, _full_name, size, category, values = record
        return (name, size, category, values)
    if len(record) == 4:
        return record
    raise ValueError('unsupported ENUMS record with {} fields: {!r}'.format(
        len(record), record[:2]))


def legacy_vtable(record):
    record = tuple(record)
    if len(record) in (5, 7):
        return record[:5]
    raise ValueError('unsupported VTABLES record with {} fields: {!r}'.format(
        len(record), record[:2]))


def legacy_structs(records):
    out = []
    for record in records:
        converted = legacy_struct(record)
        if converted is not None:
            out.append(converted)
    return out


def normalize_namespace(namespace):
    """Rewrite STRUCTS/ENUMS/VTABLES of an exec'd generated importer in place.

    Returns the number of union/namespace records left out of STRUCTS.
    """
    structs = list(namespace['STRUCTS'])
    namespace['STRUCTS'] = legacy_structs(structs)
    namespace['ENUMS'] = [legacy_enum(record) for record in namespace['ENUMS']]
    namespace['VTABLES'] = [legacy_vtable(record)
                            for record in namespace['VTABLES']]
    return len(structs) - len(namespace['STRUCTS'])


def extract_list(text, var):
    """Return the python source of ``VAR = [ ... ]`` (bracket-balanced)."""
    start = text.find(var + ' = [')
    if start < 0:
        return None
    i = text.find('[', start)
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None
