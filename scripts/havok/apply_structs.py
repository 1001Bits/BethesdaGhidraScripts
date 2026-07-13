#!/usr/bin/env python3
"""Import SDK-derived Havok struct layouts (build/havok/havok_layouts.json)
into a Ghidra program's Data Type Manager as proper structs with named
fields at authoritative MSVC-ABI offsets, under category /Havok.

Two passes: (1) create every struct empty-but-sized so members/pointers can
cross-reference; (2) place each field -- scalars and pointers get real
Ghidra types (pointers typed to the referenced havok struct when known),
embedded class/array members get the referenced struct or an undefined blob
sized from the layout.  Gaps stay undefined (compiler padding).

Also reports how many imported classes have a matching RTTI/VTABLE_ symbol
in the program (i.e. are actually present and now typable).

Run via apply_enrichment_to_user_project-style pyghidra, or standalone:
  python scripts/havok/apply_structs.py
     --project-dir <project-dir> --project-name F4VR
     --program-path /Fallout4.exe [--dry-run]
The layout document is architecture/version/target tagged and is rejected when
it does not match the open program.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = REPO / "tools" / "ghidra"
LAYOUTS = Path(__file__).resolve().parent / "refs" / "havok_layouts.json"

from layout_schema import load_document, validate_program

SCALAR = {
    'hkBool': 1, 'hkChar': 1, 'hkInt8': 1, 'hkUint8': 1, 'char': 1,
    'signed char': 1, 'unsigned char': 1, 'bool': 1, '_Bool': 1,
    'hkInt16': 2, 'hkUint16': 2, 'hkHalf': 2, 'hkFloat16': 2, 'short': 2,
    'unsigned short': 2, 'hkObjectIndex': 2,
    'hkInt32': 4, 'hkUint32': 4, 'hkReal': 4, 'float': 4, 'int': 4,
    'unsigned int': 4, 'unsigned': 4, 'hkResult': 4, 'hkSingle': 4,
    'long': 4, 'unsigned long': 4,
    'hkInt64': 8, 'hkUint64': 8, 'hkUlong': 8, 'hkLong': 8, 'double': 8,
    'long long': 8, 'unsigned long long': 8, 'hk_size_t': 8, 'hkPadSpu': 8,
}

_ARRAY_DECL_RE = re.compile(r'^(.*?)((?:\s*\[\s*\d+\s*\]\s*)+)$')


def normalize_legacy_field(field):
    """Return a field with C array extents moved from its name to its type.

    Some pre-schema PDB/Clang dumps encode ``unsigned int u[4]`` as
    ``name='u[4]', type='unsigned int'``.  Ghidra rejects the bracketed field
    name and, before this normalization, the importer silently lost the
    member.  Preserve every dimension in the type and keep a legal bare name.
    """
    normalized = dict(field)
    name = str(normalized.get('name') or '').strip()
    match = _ARRAY_DECL_RE.match(name)
    if match is None:
        return normalized
    bare_name = match.group(1).strip()
    if not bare_name:
        raise ValueError('Havok array field has no base name: {!r}'.format(name))
    dimensions = ''.join(
        '[{}]'.format(value)
        for value in re.findall(r'\[\s*(\d+)\s*\]', match.group(2)))
    if not dimensions:
        return normalized
    type_name = str(normalized.get('type') or '').strip()
    if not type_name:
        raise ValueError('Havok array field {} has no element type'.format(name))
    # A newer producer may already have moved the dimensions while retaining
    # the legacy declarator in ``name``.  Strip the name without multiplying
    # the array dimensions a second time.
    compact_type = re.sub(r'\s+', '', type_name)
    compact_dimensions = re.sub(r'\s+', '', dimensions)
    normalized['name'] = bare_name
    normalized['type'] = (type_name if compact_type.endswith(compact_dimensions)
                          else type_name + dimensions)
    return normalized


def prepare_field_groups(fields, record_size):
    """Normalize and group structure fields by offset.

    Each returned item is ``(offset, span, members)``.  ``span`` is bounded by
    the next *distinct* field offset (or the record size), which gives an
    overlapping group a safe maximum size for an anonymous union.
    """
    size = int(record_size)
    if size <= 0:
        raise ValueError('Havok record size must be positive')
    by_offset = {}
    for order, raw in enumerate(fields):
        field = normalize_legacy_field(raw)
        try:
            offset = int(field['offset'])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError('Havok field has an invalid offset') from exc
        if offset < 0 or offset >= size:
            raise ValueError(
                'Havok field offset 0x{:X} is outside size 0x{:X}'.format(
                    offset, size))
        by_offset.setdefault(offset, []).append((order, field))
    offsets = sorted(by_offset)
    groups = []
    for index, offset in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else size
        span = end - offset
        if span <= 0:
            raise ValueError('Havok field group has no storage span')
        members = [field for _order, field in sorted(by_offset[offset])]
        groups.append((offset, span, members))
    return groups


def anonymous_union_name(record_name, offset):
    """Return a deterministic, legal, collision-resistant storage name."""
    original = str(record_name)
    stem = re.sub(r'[^A-Za-z0-9_]', '_', original).strip('_') or 'record'
    stem = stem[:64]
    digest = hashlib.sha1(original.encode('utf-8')).hexdigest()[:10]
    return '{}__anon_{:X}_{}'.format(stem, int(offset), digest)


def checked_place(operation, record_name, offset, description):
    """Run one Ghidra placement and turn any failure into an atomic abort."""
    try:
        return operation()
    except Exception as exc:
        raise RuntimeError(
            'failed to place {} in {} at +0x{:X}: {}'.format(
                description, record_name, int(offset), exc)) from exc


def unique_component_name(raw_name, used):
    """Return a deterministic component name not already present in *used*.

    Flattened SDK layouts occasionally contain a base member and a derived
    member with the same spelling at different offsets.  Ghidra requires
    component names to be unique within one structure/union, so retain both
    by suffixing the later declaration rather than dropping it or aborting the
    complete atomic import.
    """
    base = str(raw_name or '').strip() or 'member'
    candidate = base
    serial = 2
    while candidate in used:
        candidate = '{}_{}'.format(base, serial)
        serial += 1
    used.add(candidate)
    return candidate


def base_name(t):
    """Strip qualifiers/template args/ref to a bare type name."""
    t = t.strip()
    t = re.sub(r'\bconst\b', '', t)
    t = re.sub(r'\bvolatile\b', '', t)
    for kw in ('class ', 'struct ', 'union ', 'enum '):
        t = t.replace(kw, '')
    t = t.split('<', 1)[0]              # drop template args
    t = t.replace('*', ' ').replace('&', ' ')   # drop pointer/ref tokens
    return t.strip()


def run(program, records, dry_run, monitor, metadata=None):
    from ghidra.program.model.data import (
        StructureDataType, UnionDataType, CategoryPath, DataTypeConflictHandler,
        Undefined, PointerDataType, UnsignedIntegerDataType,
        UnsignedShortDataType, UnsignedCharDataType, IntegerDataType,
        ShortDataType, CharDataType, FloatDataType, DoubleDataType,
        UnsignedLongLongDataType, LongLongDataType, ByteDataType,
        ArrayDataType, Undefined1DataType)
    if metadata is None:
        raise ValueError('Havok layout metadata is required')
    validate_program(program, metadata)
    dtm = program.getDataTypeManager()
    cat = CategoryPath("/Havok")
    KEEP = DataTypeConflictHandler.REPLACE_HANDLER

    gh_scalar = {
        1: UnsignedCharDataType.dataType, 2: UnsignedShortDataType.dataType,
        4: UnsignedIntegerDataType.dataType, 8: UnsignedLongLongDataType.dataType}
    gh_signed = {
        1: ByteDataType.dataType, 2: ShortDataType.dataType,
        4: IntegerDataType.dataType, 8: LongLongDataType.dataType}
    named = {
        'hkReal': FloatDataType.dataType, 'float': FloatDataType.dataType,
        'hkSingle': FloatDataType.dataType, 'double': DoubleDataType.dataType,
        'hkInt8': ByteDataType.dataType, 'char': CharDataType.dataType,
        'hkInt16': ShortDataType.dataType, 'hkInt32': IntegerDataType.dataType,
        'hkInt64': LongLongDataType.dataType,
    }

    # pass 1: create sized empty structs
    structs = {}
    record_kinds = {}
    for name, rec in records.items():
        size = rec['size'] or 1
        kind = str(rec.get('kind', 'struct')).lower()
        record_kinds[name] = kind
        sdt = (UnionDataType(cat, name) if kind == 'union'
               else StructureDataType(cat, name, size))
        structs[name] = sdt
    had_parent_transaction = (
        not dry_run and program.getCurrentTransactionInfo() is not None)
    tx = None
    if not dry_run:
        tx = program.startTransaction("havok: import layouts")
        try:
            for name in records:
                structs[name] = dtm.addDataType(structs[name], KEEP)
        except Exception:
            # Struct creation and field placement are one atomic import.  A
            # later fatal field error must not leave a half-populated type
            # archive behind.
            program.endTransaction(tx, False)
            tx = None
            raise

    try:
        PTR = program.getDefaultPointerSize()  # 8 (x64) or 4 (x86/FNV)
    except Exception:
        if tx is not None:
            program.endTransaction(tx, False)
        raise

    def split_template(t):
        start = t.find('<')
        if start < 0 or not t.rstrip().endswith('>'):
            return '', []
        head = t[:start].strip().split()[-1]
        body = t[start + 1:t.rfind('>')]
        args, depth, mark = [], 0, 0
        for i, ch in enumerate(body):
            if ch == '<': depth += 1
            elif ch == '>': depth -= 1
            elif ch == ',' and depth == 0:
                args.append(body[mark:i].strip()); mark = i + 1
        args.append(body[mark:].strip())
        return head, args

    container_cache = {}

    def field_type_and_size(ftype, available=None):
        ftype = ftype.strip()
        am = _ARRAY_DECL_RE.match(ftype)
        if am:
            elem = am.group(1).strip()
            dimensions = [int(value) for value in
                          re.findall(r'\[\s*(\d+)\s*\]', am.group(2))]
            edt, esz = field_type_and_size(elem)
            if edt is not None and esz and dimensions and all(
                    count > 0 for count in dimensions):
                # C's ``T a[4][2]`` is an array of four arrays of two T.
                # Build from the innermost (rightmost) extent outward.
                for count in reversed(dimensions):
                    edt = ArrayDataType(edt, count, esz)
                    esz *= count
                return edt, esz
        bn = base_name(ftype)
        if ftype.rstrip().endswith(('*', '&')):
            tgt = structs.get(bn)
            return (PointerDataType(tgt) if tgt else PointerDataType()), PTR
        template, args = split_template(ftype)
        if template in ('hkRefPtr', 'hkViewPtr', 'hkScopedPtr', 'hkUniquePtr'):
            target = base_name(args[0]) if args else ''
            tgt = structs.get(target)
            return (PointerDataType(tgt) if tgt else PointerDataType()), PTR
        if template in ('hkArray', 'hkSmallArray') and args:
            expected = PTR + (8 if template == 'hkArray' else 4)
            if available is not None and available != expected:
                return None, None
            key = (template, args[0], expected)
            if key not in container_cache:
                safe = re.sub(r'[^A-Za-z0-9_]', '_', '%s_%s' %
                              (template, args[0])).strip('_')
                cdt = StructureDataType(CategoryPath('/Havok/Containers'),
                                        safe, expected)
                elem = structs.get(base_name(args[0]))
                pdt = PointerDataType(elem) if elem else PointerDataType()
                cdt.replaceAtOffset(0, pdt, PTR, 'data', None)
                if template == 'hkArray':
                    cdt.replaceAtOffset(PTR, IntegerDataType.dataType, 4,
                                        'size', None)
                    cdt.replaceAtOffset(PTR + 4, IntegerDataType.dataType, 4,
                                        'capacityAndFlags', None)
                else:
                    cdt.replaceAtOffset(PTR, ShortDataType.dataType, 2,
                                        'size', None)
                    cdt.replaceAtOffset(PTR + 2, ShortDataType.dataType, 2,
                                        'capacityAndFlags', None)
                if not dry_run:
                    cdt = dtm.addDataType(cdt, KEEP)
                container_cache[key] = cdt
            return container_cache[key], expected
        if bn in ('hkUlong', 'hk_size_t'):   # unsigned pointer-sized
            return gh_scalar[PTR], PTR
        if bn == 'hkLong':
            return gh_signed[PTR], PTR
        if ftype in SCALAR:
            sz = SCALAR[ftype]
            return named.get(ftype, gh_scalar[sz]), sz
        if bn in SCALAR:
            sz = SCALAR[bn]
            return named.get(bn, gh_scalar[sz]), sz
        if bn in structs and not ftype.startswith(('hkArray', 'class hkArray',
                                                   'hkSmallArray', 'class hkSmallArray')):
            dt = structs[bn]
            return dt, dt.getLength()
        return None, None                 # composite/unknown -> size by delta

    def bounded_field_type(field, span):
        """Resolve one field without allowing it to cross its storage span."""
        declared = field.get('size')
        try:
            declared = int(declared) if declared is not None else 0
        except (TypeError, ValueError) as exc:
            raise ValueError(
                'invalid declared Havok field size {!r}'.format(declared)) from exc
        available = min(span, declared) if declared > 0 else span
        if available <= 0:
            raise ValueError('Havok field has no available storage')
        dt, dsz = field_type_and_size(str(field.get('type') or ''), available)
        if dt is None or dsz is None or dsz <= 0 or dsz > available:
            dsz = available
            dt = (Undefined.getUndefinedDataType(dsz) if dsz <= 8 else
                  ArrayDataType(Undefined1DataType.dataType, dsz, 1))
        return dt, dsz

    # pass 2: place fields.  Equal-offset members in a structure describe an
    # anonymous union in the legacy corpora; never overwrite one alternative
    # with another.
    placed = total_fields = 0
    commit = False
    try:
        for name, rec in records.items():
            sdt = structs[name]
            size = int(rec['size'])
            groups = prepare_field_groups(rec.get('fields') or [], size)
            total_fields += sum(len(members) for _off, _span, members in groups)
            is_union = record_kinds[name] == 'union'

            if is_union:
                used_names = set()
                for off, span, members in groups:
                    if off != 0:
                        raise ValueError(
                            'union {} has a member at nonzero offset 0x{:X}'.format(
                                name, off))
                    for field in members:
                        dt, dsz = bounded_field_type(field, span)
                        field_name = unique_component_name(
                            field.get('name'), used_names)
                        if not dry_run:
                            checked_place(
                                lambda dt=dt, dsz=dsz, field_name=field_name:
                                sdt.add(dt, dsz, field_name, None),
                                name, off, 'union member ' + field_name)
                        placed += 1
                continue

            used_names = set()
            for off, span, members in groups:
                if len(members) == 1:
                    field = members[0]
                    dt, dsz = bounded_field_type(field, span)
                    field_name = unique_component_name(
                        field.get('name'), used_names)
                    if not dry_run:
                        checked_place(
                            lambda dt=dt, dsz=dsz, field_name=field_name:
                            sdt.replaceAtOffset(
                                off, dt, dsz, field_name, None),
                            name, off, 'field ' + (field_name or '<unnamed>'))
                    placed += 1
                    continue

                anon = UnionDataType(
                    CategoryPath('/Havok/Anonymous'),
                    anonymous_union_name(name, off))
                union_names = set()
                member_names = []
                for field in members:
                    dt, dsz = bounded_field_type(field, span)
                    member_name = unique_component_name(
                        field.get('name'), union_names)
                    checked_place(
                        lambda dt=dt, dsz=dsz, member_name=member_name:
                        anon.add(dt, dsz, member_name, None),
                        name, off, 'anonymous-union member ' + member_name)
                    member_names.append(member_name)
                if anon.getLength() <= 0 or anon.getLength() > span:
                    raise ValueError(
                        'anonymous union in {} at +0x{:X} has size {} outside '
                        'bounded span {}'.format(name, off, anon.getLength(), span))
                if not dry_run:
                    anon = checked_place(
                        lambda anon=anon: dtm.addDataType(anon, KEEP),
                        name, off, 'anonymous-union datatype')
                    checked_place(
                        lambda anon=anon: sdt.replaceAtOffset(
                            off, anon, anon.getLength(), None,
                            'anonymous union: ' + ' | '.join(member_names)),
                        name, off, 'anonymous union')
                placed += len(members)
        commit = True
    finally:
        if not dry_run:
            committed = bool(program.endTransaction(tx, commit))
            if commit and not had_parent_transaction and not committed:
                raise RuntimeError('Havok layout transaction did not commit')

    # coverage report: which imported classes exist in the binary (by symbol)
    st = program.getSymbolTable()
    present = 0
    sample = []
    for name in list(records)[:0]:
        pass
    allnames = set(records)
    seen = set()
    si = st.getSymbolIterator()
    pat = re.compile(r'\b(hk[A-Za-z0-9_]+|bhk[A-Za-z0-9_]+)')
    for sym in st.getAllSymbols(False):
        nm = sym.getName()
        if 'hk' not in nm:
            continue
        for cand in pat.findall(nm):
            if cand in allnames and cand not in seen:
                seen.add(cand)
    present = len(seen)
    print("havok-structs (%s): %d structs, %d/%d fields placed%s"
          % (program.getName(), len(records), placed, total_fields,
             ' [DRY-RUN]' if dry_run else ''))
    print("  classes also present in binary (by symbol): %d/%d"
          % (present, len(records)))
    if not dry_run:
        program.save("havok structs imported", monitor)
        print("  saved.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program-path', required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--layouts', default=str(LAYOUTS))
    args = ap.parse_args()

    records, metadata = load_document(args.layouts)
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()
    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]
    with pyghidra.open_project(pdir, pname, create=False) as project:
        root = project.getProjectData().getRootFolder()
        match = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                if prefix + "/" + f.getName() == args.program_path:
                    match.append(f)
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())
        walk(root)
        if not match:
            print("not found:", args.program_path)
            return
        consumer = java.lang.Object()
        program = match[0].getDomainObject(consumer, not args.dry_run, False, monitor)
        try:
            ps = program.getDefaultPointerSize()
            print("program pointer size: %d-bit (layout must match)" % (ps * 8))
            print("layout: Havok %s %s, targets=%s" %
                  (metadata['havok_version'], metadata['architecture'],
                   ','.join(metadata['targets'])))
            run(program, records, args.dry_run, monitor, metadata)
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
