#!/usr/bin/env python3
"""Convert Fallout_Debug_types.json (parsed PDB pretty dump) into the
struct dict shape that ghidra_import_gen.generate_script consumes.

Source: ``parse_pdb_pretty.py`` produced
``{class_name: {size, fields: [{off, size, type, name}, ...]}}``.

Target shape (per struct entry):
    {
      'name':       str,
      'full_name':  str,
      'size':       int,
      'category':   '/xNVSE/PDB',     # bucket PDB-derived types separately
      'fields':     [
        {'name': str, 'offset': int, 'size': int, 'type': str_pipeline},
        ...
      ],
      'bases':      [],               # PDB pretty dump doesn't surface
      'pdb_bases':  [],               # base classes cleanly
      'has_vtable': False,
      'vmethods':   {},
      'methods':    {},
      '_overload_aliases': {},
    }

Type string conversion (PDB -> pipeline):
    unsigned char/char/UCHAR    -> u8/i8
    unsigned short/short        -> u16/i16
    unsigned long/long/int/UINT -> u32/i32
    unsigned __int64/__int64    -> u64/i64
    float                       -> f32
    double                      -> f64
    bool                        -> bool
    <anything>*                 -> ptr  (32-bit pointers in FNV)
    <type>[N]                   -> arr:<type>:N
    <known struct name>         -> struct:<name>  (if matches another entry)
    <unknown>                   -> bytes:<size>   (raw padding fallback)

Public API:
    convert_pdb_types(json_path) -> dict   # structs dict, ready to merge
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Set


# Primitive PDB type names (normalized to lowercase) -> pipeline type
_PRIMITIVES = {
    'bool':                'bool',
    'char':                'i8',
    'signed char':         'i8',
    'unsigned char':       'u8',
    'uchar':               'u8',
    'short':               'i16',
    'short int':           'i16',
    'unsigned short':      'u16',
    'unsigned short int':  'u16',
    'ushort':              'u16',
    'wchar_t':             'u16',
    'int':                 'i32',
    'long':                'i32',
    'long int':            'i32',
    'unsigned int':        'u32',
    'unsigned long':       'u32',
    'unsigned long int':   'u32',
    'uint':                'u32',
    'ulong':               'u32',
    'dword':               'u32',
    'long long':           'i64',
    '__int64':             'i64',
    'unsigned long long':  'u64',
    'unsigned __int64':    'u64',
    'qword':               'u64',
    'float':               'f32',
    'double':              'f64',
    'long double':         'f64',
    'void':                'void',
    # Common Windows typedefs
    'BYTE':  'u8',
    'WORD':  'u16',
    'DWORD': 'u32',
    'HANDLE': 'ptr',
    'HRESULT': 'i32',
    'BOOL':  'i32',
    'LONG':  'i32',
    'ULONG': 'u32',
    'INT':   'i32',
    'UINT':  'u32',
    'SHORT': 'i16',
    'USHORT': 'u16',
    'CHAR': 'i8',
    'UCHAR': 'u8',
    'PVOID': 'ptr',
    'LPVOID': 'ptr',
    'LPCSTR': 'ptr',
    'LPSTR': 'ptr',
    'LPCWSTR': 'ptr',
    'LPWSTR': 'ptr',
    'SIZE_T': 'u32',
    'INT_PTR': 'i32',
    'UINT_PTR': 'u32',
    'LONG_PTR': 'i32',
    'ULONG_PTR': 'u32',
}


def normalize_struct_name(cls: str) -> str:
    """Public helper: mirror the nested _normalize_name in convert_pdb_types
    so callers outside the function can produce matching keys."""
    s = cls.replace('::', '_')
    s = s.replace('<', '_').replace('>', '_')
    s = s.replace('-', '_')
    while '__' in s:
        s = s.replace('__', '_')
    return s.strip('_')


# Sizes for primitives, used when emitting bytes:N fallback
_PRIMITIVE_SIZES = {
    'bool': 1, 'i8': 1, 'u8': 1,
    'i16': 2, 'u16': 2,
    'i32': 4, 'u32': 4, 'f32': 4,
    'i64': 8, 'u64': 8, 'f64': 8,
    'ptr': 4,  # 32-bit FNV
    'void': 0,
}


_ARRAY_RE = re.compile(r'^(.*?)\[(\d+)\]\s*$')


def _strip_qualifiers(t: str) -> str:
    t = t.strip()
    for q in ('const ', 'volatile ', '__unaligned ', '__restrict '):
        while t.startswith(q):
            t = t[len(q):]
    return t.strip()


def _convert_one(type_str: str, field_size: int, known_structs: Set[str],
                  known_enums: Set[str] = None,
                  typedefs: Dict[str, str] = None,
                  _depth: int = 0) -> str:
    """Convert a single PDB type string to pipeline format.

    ``typedefs`` is an optional ``{alias: target}`` map -- when a type
    doesn't match anything else, we follow up to 4 typedef hops to
    find a resolvable form.  Prevents the converter from emitting
    ``bytes:N`` for fields whose PDB type is just a typedef alias of
    a known struct/enum (``STFC_STATS`` -> ``_STFC_STATS``).
    """
    if known_enums is None:
        known_enums = set()
    if typedefs is None:
        typedefs = {}
    t = _strip_qualifiers(type_str)
    # PDB often prefixes class/struct/enum on field types
    for prefix in ('enum ', 'class ', 'struct ', 'union '):
        if t.startswith(prefix):
            t = t[len(prefix):].strip()
            break
    if not t:
        return f'bytes:{field_size}' if field_size > 0 else 'u8'

    # Pointer / reference -> ptr (always 4 bytes in 32-bit FNV)
    if t.endswith('*') or t.endswith('&'):
        return 'ptr'

    # Function-pointer-ish: ``T (*)(args)``, ``T (__cdecl *name)(args)``,
    # ``T (__thiscall *)(args)``, etc.  Any ``(`` followed by an optional
    # calling-conv keyword + a ``*`` is a function pointer signature.
    if re.search(r'\(\s*(?:__\w+\s+)?\*\s*\w*\)?\s*\(', t):
        return 'ptr'

    # Array: ``<inner>[N]``
    m = _ARRAY_RE.match(t)
    if m:
        inner = m.group(1).rstrip()
        count = int(m.group(2))
        elem_size = field_size // count if count > 0 else 0
        inner_pipeline = _convert_one(inner, elem_size, known_structs, known_enums, typedefs)
        # ghidra_import_gen.resolve_type uses rfind(':') to split off the
        # count, so ``arr:struct:Foo<Bar>:N`` works.  Only fall back when
        # the inner type ITSELF is already a bytes:N / arr:... form, OR
        # when it's ``void`` (Ghidra rejects ArrayDataType(VoidDataType,
        # N, 0) -- "Data type may not report a length less than 1").
        if (inner_pipeline.startswith('bytes:')
                or inner_pipeline.startswith('arr:')
                or inner_pipeline == 'void'):
            return f'bytes:{field_size}' if field_size > 0 else 'u8'
        return f'arr:{inner_pipeline}:{count}'

    # Primitive match (case-sensitive first, then lowered)
    if t in _PRIMITIVES:
        return _PRIMITIVES[t]
    lowered = t.lower()
    if lowered in _PRIMITIVES:
        return _PRIMITIVES[lowered]

    # Bitfield (PDB pretty dump emits ``unsigned long Foo : 32``);
    # handled in caller; here treat as the underlying primitive.

    # Anonymous/nested type -> raw bytes
    if '<unnamed' in t or '<anonymous' in t or '::<unnamed-' in t:
        return f'bytes:{field_size}' if field_size > 0 else 'u8'

    # Known enum reference?
    if t in known_enums:
        return f'enum:{t.replace("::", "_")}'

    # Known struct reference?  Use the FULL name only when an entry with
    # that exact name exists -- emitting ``struct:Foo<X>`` when only ``Foo``
    # is defined creates a dangling ref that Ghidra resolves to nothing.
    # For templated lookups, fall back to bytes:size (preserves layout).
    if t in known_structs:
        return f'struct:{normalize_struct_name(t)}'
    base = t.split('<', 1)[0].rstrip()
    if base in known_structs and '<' not in t:
        return f'struct:{normalize_struct_name(base)}'

    # Typedef alias fallback: follow the chain (capped) and retry.
    if _depth < 4 and t in typedefs:
        target = typedefs[t]
        if target and target != t:
            return _convert_one(target, field_size, known_structs,
                                known_enums, typedefs, _depth + 1)

    # Templated instantiation we don't have a layout for, OR unknown
    # type entirely.  Raw bytes preserve the field's declared size.
    return f'bytes:{field_size}' if field_size > 0 else 'u8'


def _type_specificity(t: str) -> int:
    """Higher = more informative.  Used to break ties in same-offset
    same-size dedup so we never silently downgrade a named type to
    a raw byte buffer."""
    if t.startswith('struct:'): return 4
    if t.startswith('enum:'):   return 3
    if t.startswith('arr:'):    return 2
    if t.startswith('bytes:'):  return 0
    if t in ('u8', 'i8', 'u16', 'i16', 'u32', 'i32', 'u64', 'i64',
              'f32', 'f64', 'bool', 'ptr'):
        return 1
    return 1  # unknown -- treat as primitive-ish


def _dedup_field_ranges(fields):
    """Drop fields whose byte range is strictly contained in another field's
    range (nested-struct expansions slipped past the indent filter).
    For same-offset+same-size pairs (anonymous unions / typedef aliases),
    keep the entry whose type is most specific (struct > enum > primitive
    > bytes) so we never silently downgrade to raw bytes.
    """
    if not fields:
        return fields
    # Sort: by offset ascending, then size DESCENDING so larger parent comes
    # before its inner expansion (which we'll then drop as "contained"),
    # then by type-specificity descending so the more informative type wins
    # the same-range tie.
    sorted_f = sorted(fields, key=lambda f: (f['offset'], -f['size'],
                                              -_type_specificity(f['type'])))
    kept = []
    for f in sorted_f:
        f_end = f['offset'] + f['size']
        absorbed = False
        for k in kept:
            k_end = k['offset'] + k['size']
            if k['offset'] > f['offset'] or k_end < f_end:
                continue
            if k['offset'] == f['offset'] and k['size'] == f['size']:
                # Same range -- swap if f is more specific.
                if _type_specificity(f['type']) > _type_specificity(k['type']):
                    kept[kept.index(k)] = f
                absorbed = True
                break
            absorbed = True
            break
        if not absorbed:
            kept.append(f)
    return kept


def convert_pdb_types(json_path: Path, enums_json_path: Path = None,
                       typedefs_json_path: Path = None,
                       category: str = '/xNVSE/PDB') -> Dict[str, dict]:
    """Convert a parsed pretty-dump types JSON to a structs dict ready to
    merge with the clang-AST-derived structs in parse_commonlib_types.py.

    Skips entries with size==0 or no fields, and entries whose names
    look like compiler-internal anonymous tags (``<unnamed-tag>``).

    ``category`` selects the Ghidra DTM bucket for emitted structs.
    Defaults to ``/xNVSE/PDB`` for the FNV pipeline; pass
    ``/CommonLibSSE/PDB`` for Skyrim, etc.
    """
    data = json.loads(json_path.read_text(encoding='utf-8'))

    # Optional enum index -- when present, field types matching an enum
    # name are emitted as ``enum:Name`` instead of falling to bytes:N.
    known_enums: Set[str] = set()
    if enums_json_path and enums_json_path.is_file():
        en_data = json.loads(enums_json_path.read_text(encoding='utf-8'))
        for cls in en_data:
            known_enums.add(cls)
            known_enums.add(cls.replace('::', '_'))

    # Optional typedef alias map -- catches fields whose PDB type is a
    # typedef of a known struct/enum (8,400+ Bethesda/Win/Xbox typedefs).
    typedefs: Dict[str, str] = {}
    if typedefs_json_path and typedefs_json_path.is_file():
        typedefs = json.loads(typedefs_json_path.read_text(encoding='utf-8'))

    def _normalize_name(cls: str) -> str:
        """``Class::Inner`` -> ``Class_Inner`` so Ghidra DTM gets a single
        unique key (otherwise nested types from many parents collapse to
        the same short name and refs go dangling).

        Also sanitize ``<unnamed-tag>``-style PDB-internal labels to
        plain identifiers so they survive Ghidra's struct-name validator.
        """
        s = cls.replace('::', '_')
        s = s.replace('<', '_').replace('>', '_')
        s = s.replace('-', '_')
        # Collapse double-underscores
        while '__' in s:
            s = s.replace('__', '_')
        return s.strip('_')

    # First pass: collect names of structs we'll emit, so type strings can
    # reference them via ``struct:Name``.  We register BOTH the original
    # ``Class::Inner`` form (which the field strings use) AND the
    # normalized form, so the converter can rewrite refs at emit time.
    known_structs: Set[str] = set()
    for cls, entry in data.items():
        if entry.get('size', 0) == 0:
            continue
        if not entry.get('fields'):
            continue
        # Anonymous types keep their full ``<unnamed-tag>`` PDB name as
        # the JSON key (so field refs that use that string can still
        # find them), but the EMITTED struct definition uses the
        # normalized synthetic name (Ghidra rejects ``<>`` in names).
        known_structs.add(cls)
        known_structs.add(_normalize_name(cls))
        # Also expose the bare class name (no template args) for matching
        bare = cls.split('<', 1)[0].rstrip()
        known_structs.add(bare)

    structs: Dict[str, dict] = {}
    n_fields_total = 0
    n_skipped = 0
    for cls, entry in data.items():
        if entry.get('size', 0) == 0 or not entry.get('fields'):
            n_skipped += 1
            continue
        size = entry['size']
        out_fields = []
        for fld in entry['fields']:
            fname = fld['name']
            fsize = fld.get('size', 0)
            # PDB pretty dump emits arrays as ``unsigned char Data4[8]``
            # i.e. the [N] dimension is in the NAME, not the type.  Detect
            # and rewrap so we emit `arr:T:N` instead of `T` with [N] in
            # the field name.
            am = re.match(r'^(\w+)\[(\d+)\]$', fname)
            if am:
                base_name = am.group(1)
                count = int(am.group(2))
                inner_type = _convert_one(fld['type'],
                                          fsize // count if count > 0 else 0,
                                          known_structs, known_enums, typedefs)
                if (count > 0 and not inner_type.startswith('bytes:')
                        and not inner_type.startswith('arr:')
                        and inner_type != 'void'):
                    ftype = f'arr:{inner_type}:{count}'
                else:
                    ftype = f'bytes:{fsize}' if fsize > 0 else 'u8'
                fname = base_name
            else:
                ftype = _convert_one(fld['type'], fsize, known_structs, known_enums, typedefs)
            out_fields.append({
                'name':   fname,
                'offset': fld['off'],
                'size':   fsize,
                'type':   ftype,
            })
            n_fields_total += 1
        # Dedup nested-struct expansions + same-offset union members
        out_fields = _dedup_field_ranges(out_fields)
        # Use NORMALIZED name (`::` -> `_`) so the entry surfaces in
        # Ghidra DTM under the same key that field refs use.
        norm = _normalize_name(cls)
        # parse_pdb_pretty emits bases as ``[[name, offset], ...]`` after
        # the inheritance + base-line capture. Both forms are accepted:
        # newer ``[name, off]`` lists and older bare-name strings.
        raw_bases = entry.get('bases', []) or []
        pdb_bases = []
        bases_names = []
        for b in raw_bases:
            if isinstance(b, (list, tuple)) and len(b) >= 2:
                pdb_bases.append((b[0], int(b[1])))
                bases_names.append(b[0])
            elif isinstance(b, str):
                pdb_bases.append((b, 0))
                bases_names.append(b)
        structs[cls] = {
            'name':              norm,
            'full_name':         cls,
            'size':              size,
            'category':          category,
            'fields':            out_fields,
            'bases':             bases_names,
            'pdb_bases':         pdb_bases,
            'has_vtable':        False,
            'vmethods':          {},
            'methods':           {},
            '_overload_aliases': {},
        }
    return structs, n_skipped, n_fields_total


if __name__ == '__main__':
    import sys
    from paths import artifact
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        artifact('Fallout_Debug_types.json')
    structs, skipped, n_fields = convert_pdb_types(p)
    print(f'  Converted PDB structs: {len(structs):,}')
    print(f'  Total fields:          {n_fields:,}')
    print(f'  Skipped (empty/anon):  {skipped:,}')
