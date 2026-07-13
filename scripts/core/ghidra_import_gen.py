"""Ghidra import script generator.

Takes processed C++ type data (enums, structs, vtable info) and symbol tables,
then generates a self-contained Jython script that imports everything into Ghidra's
Data Type Manager and Symbol Table.

The generated script handles:
  - Enum, struct, and vtable type creation in Ghidra's DTM
  - Function symbol labeling and disassembly at known addresses
  - Signature application via structured pipeline types (FunctionDefinitionDataType)
    or C prototype parsing (CParserUtils) with type simplification fallback
  - Virtual function naming by walking VTABLE label addresses
  - Fallback symbol application (PDB / AE rename / IDA NAME script) for
    unnamed functions

This module is game/project-agnostic. All project-specific logic (source parsing,
address libraries, fallback-name loading, relocation scanning) lives in the
caller.

Public API:
  build_vtable_structs()         - build primary + secondary vtable descriptors
                                   from the virtual class hierarchy
  inject_vtable_fields()         - prepend __vftable pointers to virtual structs
  flatten_structs()              - expand base class fields into derived structs
  apply_secondary_vtable_typing() - retype non-zero-offset __vftable_<base>
                                    fields to per-class secondary vtable structs
                                    (multi-inheritance)
  generate_script()              - emit the Ghidra import script
"""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Type-string utilities
# ---------------------------------------------------------------------------

def _type_str_size(type_str: str) -> int:
    """Estimate byte size from a pipeline type descriptor string."""
    sizes = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': 8, 'void': 0,
    }
    if type_str in sizes:
        return sizes[type_str]
    if type_str.startswith('bytes:'):
        return int(type_str[6:])
    if type_str.startswith('arr:'):
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem_size = _type_str_size(rest[:last])
            return elem_size * count
        return 0
    if type_str.startswith('enum:'):
        return 4
    if type_str.startswith('struct:'):
        return 8
    return 0


# ---------------------------------------------------------------------------
# Base-class name resolution
# ---------------------------------------------------------------------------

def _build_type_index(structs: dict) -> dict:
    """Build an exact-name index plus *unique* leaf-name aliases.

    A last-writer-wins ``Actor`` alias is unsafe once two namespaces contain an
    Actor.  Ambiguous leaves are deliberately omitted so callers keep an opaque
    type instead of silently attaching the wrong layout.
    """
    result = {}
    leaves = {}
    for st in structs.values():
        full = st['full_name']
        result[full] = st
        leaves.setdefault(st['name'], []).append(st)
        leaf = full.split('::')[-1]
        leaves.setdefault(leaf, []).append(st)
    for leaf, candidates in leaves.items():
        unique = {id(item): item for item in candidates}
        if len(unique) == 1 and leaf not in result:
            result[leaf] = next(iter(unique.values()))
    return result


def _resolve_base(by_name: dict, name: str):
    """Look up a base class without guessing between ambiguous leaf names."""
    return by_name.get(name)


# ---------------------------------------------------------------------------
# Vtable struct building
# ---------------------------------------------------------------------------

def build_vtable_structs(structs: dict) -> dict:
    """Build vtable type descriptors from virtual class hierarchies.

    Returns dict: full_name -> vtable descriptor dict.
    """
    by_name = _build_type_index(structs)

    memo = {}
    sig_memo = {}

    def _primary_base_st(st):
        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            primary_name, primary_off = pdb_bases[0]
            if primary_off == 0:
                return _resolve_base(by_name, primary_name)
        else:
            for base_ref in st.get('bases', []):
                return _resolve_base(by_name, base_ref)
        return None

    def get_slots(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = {}
            return {}
        memo[full_name] = {}
        slots = {}
        bst = _primary_base_st(st)
        if bst:
            slots.update(get_slots(bst['full_name'], depth + 1))
        for mname, vbaseoff in st.get('vfuncs', []):
            if vbaseoff >= 0 and mname:
                slots[vbaseoff] = mname
        memo[full_name] = slots
        return slots

    def get_sigs(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in sig_memo:
            return sig_memo[full_name]
        st = by_name.get(full_name)
        if not st:
            sig_memo[full_name] = {}
            return {}
        sig_memo[full_name] = {}
        sigs = {}
        bst = _primary_base_st(st)
        if bst:
            sigs.update(get_sigs(bst['full_name'], depth + 1))
        sigs.update(st.get('vmethods', {}))
        sig_memo[full_name] = sigs
        return sigs

    vtable_structs = {}
    secondary_count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        named = get_slots(st['full_name'])
        if not named:
            continue
        max_off = max(named.keys())
        vtbl_size = max_off + 8
        all_slots = dict(named)
        if vtbl_size <= 0x4000:
            for off in range(0, vtbl_size, 8):
                if off not in all_slots:
                    all_slots[off] = 'fn_{:03X}'.format(off)
        sigs = get_sigs(st['full_name'])
        sorted_slots = []
        for off, name in sorted(all_slots.items()):
            sig = sigs.get(name)
            sorted_slots.append((off, name, sig[0] if sig else None, sig[1] if sig else None))
        vname = st['name'] + '_vtbl'
        vtable_structs[st['full_name']] = {
            'name': vname,
            'class_full_name': st['full_name'],
            'category': st['category'],
            'slots': sorted_slots,
            'size': vtbl_size,
            'vtable_kind': 'primary',
            'subobject_offset': 0,
        }

        # --- Secondary vtables from clang -fdump-vtable-layouts (multi-inheritance) ---
        secondaries = st.get('secondary_vtables') or {}
        if secondaries:
            sec_names = {}  # offset -> generated struct name
            for offset, slot_list in secondaries.items():
                if not slot_list:
                    continue
                sec_named = {sidx * 8: mname for sidx, mname in slot_list}
                sec_max = max(sec_named.keys())
                sec_size = sec_max + 8
                sec_all = dict(sec_named)
                if sec_size <= 0x4000:
                    for off in range(0, sec_size, 8):
                        if off not in sec_all:
                            sec_all[off] = 'fn_{:03X}'.format(off)
                sec_sorted = []
                for off, sname in sorted(sec_all.items()):
                    sig = sigs.get(sname)
                    sec_sorted.append((off, sname,
                                       sig[0] if sig else None,
                                       sig[1] if sig else None))
                sec_struct_name = '{}_vtbl_{}'.format(st['name'], offset)
                key = '{}|secondary|{}'.format(st['full_name'], offset)
                vtable_structs[key] = {
                    'name': sec_struct_name,
                    'class_full_name': st['full_name'],
                    'category': st['category'],
                    'slots': sec_sorted,
                    'size': sec_size,
                    'vtable_kind': 'secondary',
                    'subobject_offset': offset,
                }
                sec_names[offset] = sec_struct_name
                secondary_count += 1
            if sec_names:
                st['secondary_struct_names'] = sec_names

    if secondary_count:
        print('Built {} vtable structs ({} secondary)'.format(
            len(vtable_structs), secondary_count))
    else:
        print('Built {} vtable structs'.format(len(vtable_structs)))
    return vtable_structs


def apply_secondary_vtable_typing(structs: dict) -> int:
    """Rewrite each class's flattened ``__vftable_<base>`` field types so they
    point at the per-class secondary vtable struct generated for that subobject
    offset, instead of inheriting the base class's primary vtable struct type.

    Must be called AFTER ``flatten_structs`` so the secondary ``__vftable_<base>``
    fields exist at their absolute offsets.  Each struct must already have
    ``secondary_struct_names = {offset: struct_name}`` populated (done by
    ``build_vtable_structs`` from clang ``-fdump-vtable-layouts`` data).
    """
    rewrites = 0
    for st in structs.values():
        sec_map = st.get('secondary_struct_names') or {}
        if not sec_map:
            continue
        for f in st.get('fields', []):
            if not f.get('name', '').startswith('__vftable'):
                continue
            offset = f.get('offset', 0)
            if offset == 0:
                continue
            sec_name = sec_map.get(offset)
            if sec_name:
                f['type'] = 'vtblptr:' + sec_name
                rewrites += 1
    if rewrites:
        print('Retyped {} secondary vtable pointer fields'.format(rewrites))
    return rewrites


def inject_vtable_fields(structs: dict, vtable_structs: dict,
                         pointer_size: int = 8) -> None:
    """Prepend __vftable pointer fields to virtual structs missing offset-0 fields."""
    count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        st_pointer_size = int(st.get('pointer_size', pointer_size))
        if st_pointer_size not in (4, 8):
            raise ValueError('unsupported pointer size {}'.format(st_pointer_size))
        if st['size'] < st_pointer_size:
            continue
        if any(f['offset'] == 0 for f in st['fields']):
            continue
        vt = vtable_structs.get(st['full_name'])
        vtbl_type = ('vtblptr:' + vt['name']) if vt else 'ptr'
        st['fields'].insert(0, {
            'name': '__vftable',
            'type': vtbl_type,
            'offset': 0,
            'size': st_pointer_size,
        })
        count += 1
    print('Injected vtable pointer fields into {} structs'.format(count))


def flatten_structs(structs: dict) -> None:
    """Expand base class fields into derived structs.

    Uses pdb_bases ([(base_name, base_offset)]) when available for accurate
    multi-base placement; falls back to assuming first base starts at offset 0.
    """
    by_name = _build_type_index(structs)

    memo = {}

    def get_flat(full_name, depth=0):
        if depth > 20:
            return []
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = []
            return []
        memo[full_name] = []
        # Union members intentionally overlap.  Flattening/shrinking them as
        # structure fields destroys every member except the last one.
        if st.get('record_kind') == 'union':
            memo[full_name] = [dict(f) for f in st.get('fields', [])]
            return memo[full_name]
        combined = {}

        def _field_key(f, offset=None):
            off = offset if offset is not None else f['offset']
            if f['type'].startswith('bf:'):
                return ('bf', off, f['type'])
            return off

        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            for base_name, base_off in pdb_bases:
                base_st = _resolve_base(by_name, base_name)
                if not base_st:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    abs_off = base_off + f['offset']
                    key = _field_key(f, abs_off)
                    if key not in combined:
                        field_copy = dict(f, offset=abs_off)
                        if f['name'] == '__vftable' and base_off > 0:
                            field_copy['name'] = '__vftable_' + base_st['name']
                        combined[key] = field_copy
        else:
            for base_ref in st.get('bases', []):
                base_st = _resolve_base(by_name, base_ref)
                if not base_st or base_st['size'] <= 1:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    key = _field_key(f)
                    if key not in combined:
                        combined[key] = f
                break

        for f in st['fields']:
            combined[_field_key(f)] = f
        flat = sorted((dict(f) for f in combined.values()),
                      key=lambda f: (f['offset'], f['type']))
        for i in range(len(flat) - 1):
            end = flat[i]['offset'] + flat[i]['size']
            if end > flat[i + 1]['offset']:
                flat[i] = dict(flat[i], size=flat[i + 1]['offset'] - flat[i]['offset'])
        memo[full_name] = flat
        return flat

    for st in structs.values():
        st['fields'] = get_flat(st['full_name'])

    gained = sum(1 for st in structs.values() if len(st['fields']) > 0)
    print('Flattening: {} structs have field data after inheritance expansion'.format(gained))

# Standard BSTArray<T> embeds RE::BSTArrayHeapAllocator (a type-erased ``void* _data``)
# + RE::BSTArrayBase. Small-array (BSTSmallArrayHeapAllocator<N>) and scrap variants
# have a different allocator base and an inline buffer / union, so they are excluded.
_BSTARRAY_HEAP_BASES = ['RE::BSTArrayHeapAllocator', 'RE::BSTArrayBase']


def retype_bstarray_data_pointers(structs: dict, root_ns: str = 'RE') -> int:
    """RE-navigability override: give each standard ``BSTArray<T>`` a typed
    ``T* _data`` instead of the type-erased ``void*`` it inherits from the shared
    ``BSTArrayHeapAllocator``.

    CommonLib's allocator is genuinely ``void*`` (type erased), so the element type
    cannot be recovered by typing the shared base. Instead we flatten the standard
    24-byte heap form into explicit fields and point ``_data`` at the element type
    parsed from the template name. NiT* arrays already carry a typed ``_data`` (their
    pointer is a real ``T*``/``T**`` in CommonLib) and are left untouched; only the
    plain heap form (bases == BSTArrayHeapAllocator + BSTArrayBase, size 24) is
    rewritten, so inline small-array / union variants are never corrupted.
    """
    from clang_types import _record_type_to_pipeline, _tmpl_args_of  # noqa: E402

    n = 0
    for st in structs.values():
        if not st.get('name', '').startswith('BSTArray<'):
            continue
        if st.get('size') != 24 or st.get('bases') != _BSTARRAY_HEAP_BASES:
            continue
        args = _tmpl_args_of(st['full_name'])
        if not args:
            continue
        elem_desc = _record_type_to_pipeline(args[0].strip(), root_ns)
        data_desc = 'ptr:' + elem_desc if elem_desc and elem_desc != 'ptr' else 'ptr'
        st['fields'] = [
            {'name': '_data',     'type': data_desc, 'offset': 0,  'size': 8},
            {'name': '_capacity', 'type': 'u32',     'offset': 8,  'size': 4},
            {'name': 'pad0C',     'type': 'u32',     'offset': 12, 'size': 4},
            {'name': '_size',     'type': 'u32',     'offset': 16, 'size': 4},
            {'name': 'pad14',     'type': 'u32',     'offset': 20, 'size': 4},
        ]
        st['bases'] = []
        st['pdb_bases'] = []
        n += 1
    if n:
        print('Retyped _data on {} BSTArray<T> instantiations (typed element pointer)'.format(n))
    return n


def embed_structs(structs: dict) -> None:
    """Additive alternative to flatten_structs: represent inheritance by EMBEDDING
    each base as a struct member at its pdb_bases offset (compositional), instead of
    inlining all base fields into every derived.

    When MSVC reuses a base's tail padding (a sibling base or an own field starts
    before base_off + base.size), embed a trimmed (data-size) variant of the base so
    Ghidra does not reject the overlap -- a full-size embedded member is atomic and
    placing anything inside its footprint silently clears it (verified empirically).
    The trim length is derived from the span to the next subobject, so no extra clang
    data is needed.

    Robustness: if any base cannot be cleanly resolved/embedded, that single struct
    falls back to a flattened layout (byte-accurate, never loses field data). The
    primary base at offset 0 carries the shared vtable, so the derived's injected
    __vftable@0 is dropped (it is 'covered' by the base member).

    Used by the CommonLibVR path (set base._flatten_structs = embed_structs). Other
    runtimes keep flatten_structs unchanged.
    """
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    # Snapshot original (pre-embed) own-fields so the flat helper stays correct even
    # as we mutate st['fields'] during the embed pass.
    orig = {st['full_name']: list(st['fields']) for st in structs.values()}

    flat_memo = {}

    def get_flat(full_name, depth=0):
        if depth > 20:
            return []
        if full_name in flat_memo:
            return flat_memo[full_name]
        st = by_name.get(full_name)
        if not st:
            flat_memo[full_name] = []
            return []
        flat_memo[full_name] = []
        combined = {}

        def key(f, off=None):
            o = off if off is not None else f['offset']
            return ('bf', o, f['type']) if f['type'].startswith('bf:') else o

        for bn, bo in st.get('pdb_bases', []):
            bst = _resolve_base(by_name, bn)
            if not bst:
                continue
            for f in get_flat(bst['full_name'], depth + 1):
                ao = bo + f['offset']
                k = key(f, ao)
                if k not in combined:
                    fc = dict(f, offset=ao)
                    if f['name'] == '__vftable' and bo > 0:
                        fc['name'] = '__vftable_' + bst['name']
                    combined[k] = fc
        for f in orig.get(st['full_name'], []):
            combined[key(f)] = f
        flat = sorted(combined.values(), key=lambda f: (f['offset'], f['type']))
        for i in range(len(flat) - 1):
            end = flat[i]['offset'] + flat[i]['size']
            if end > flat[i + 1]['offset']:
                flat[i] = dict(flat[i], size=flat[i + 1]['offset'] - flat[i]['offset'])
        flat_memo[full_name] = flat
        return flat

    trimmed = {}

    def make_trimmed(base_st, embed_size):
        tfull = '{}__embed_{:X}'.format(base_st['full_name'], embed_size)
        if tfull in trimmed or tfull in by_name:
            return tfull
        ff = [dict(f) for f in get_flat(base_st['full_name']) if f['offset'] < embed_size]
        for f in ff:
            if f['offset'] + f['size'] > embed_size:
                f['size'] = embed_size - f['offset']
        trimmed[tfull] = {
            'name': '{}__embed_{:X}'.format(base_st['name'], embed_size),
            'full_name': tfull, 'size': embed_size,
            'category': base_st.get('category', '/CommonLibSSE/RE'),
            'fields': ff, 'bases': [], 'pdb_bases': [], 'has_vtable': False,
        }
        return tfull

    import os as _os
    _watch = set(filter(None, _os.environ.get('CLVR_EMBED_DEBUG', '').split(',')))
    _reasons = {}

    def _fb(reason, name):
        _reasons[reason] = _reasons.get(reason, 0) + 1
        if name in _watch or _watch == {'*'}:
            print('  EMBED fallback [{}]: {}'.format(reason, name))

    n_embedded = n_fallback = 0
    for st in list(structs.values()):
        pdb_bases = st.get('pdb_bases', [])
        if not pdb_bases:
            continue
        # st['fields'] already holds ALL fields (own + inherited); pdb_bases lists the
        # full nested base chain. Reduce to DIRECT bases: clang prints the layout tree
        # outer-first, so the FIRST base at each offset is the direct one (deeper bases
        # at the same offset are its ancestors).
        all_fields = orig.get(st['full_name'], [])
        direct = []
        seen_off = set()
        for bn, bo in pdb_bases:           # document order = outer-first
            if bo in seen_off:
                continue
            seen_off.add(bo)
            direct.append((bn, bo))
        direct.sort(key=lambda x: x[1])
        if st['full_name'] in _watch or _watch == {'*'}:
            print('  EMBED watch {}: size={} direct={} pdb_bases={}'.format(
                st['full_name'], st['size'], direct, pdb_bases))
        members = []
        ok = True
        for i, (bn, bo) in enumerate(direct):
            bst = _resolve_base(by_name, bn)
            if not bst:
                _fb('unresolved_base:' + str(bn), st['full_name'])
                ok = False
                break
            bsize = bst['size']
            if bsize <= 0:
                continue   # empty base (EBO) contributes nothing
            # base occupies [bo, next_subobject) where next_subobject is the next
            # direct base or the first OWN field after bo (fields are own-only here),
            # else struct end. Anything before bo+bsize => MSVC reused this base's tail
            # padding => embed a trimmed (data-size) variant.
            cands = [st['size']]
            if i + 1 < len(direct):
                cands.append(direct[i + 1][1])
            cands += [f['offset'] for f in all_fields if f['offset'] > bo]
            span = min(cands) - bo
            if span <= 0:
                _fb('span<=0', st['full_name'])
                ok = False
                break
            if bsize <= span:
                embed_size = bsize
                tref = bst['full_name']
            else:
                embed_size = span
                bdsize = bst.get('dsize', bsize)
                if embed_size < bdsize:
                    # sibling overlaps the base's real data -> inconsistent; flatten.
                    _fb('trim_cuts_data', st['full_name'])
                    ok = False
                    break
                tref = make_trimmed(bst, embed_size)
            members.append({
                'name': '_base' if bo == 0 else '_base_' + bst['name'],
                'type': 'struct:' + tref, 'offset': bo, 'size': embed_size,
            })
        if not ok or not members:
            st['fields'] = get_flat(st['full_name'])
            n_fallback += 1
            continue

        def covered(o, _members=members):
            return any(m['offset'] <= o < m['offset'] + m['size'] for m in _members)

        own_kept = [f for f in all_fields if not covered(f['offset'])]
        st['fields'] = sorted(members + own_kept,
                              key=lambda f: (f['offset'], f.get('type', '')))
        n_embedded += 1

    structs.update(trimmed)
    print('Embedding: {} structs embed bases, {} flattened (fallback), '
          '{} trimmed base variants'.format(n_embedded, n_fallback, len(trimmed)))
    if _reasons:
        top = sorted(_reasons.items(), key=lambda kv: -kv[1])
        print('  fallback reasons: ' + ', '.join('{}={}'.format(k, v) for k, v in top[:12]))

    retype_bstarray_data_pointers(structs)


# ---------------------------------------------------------------------------
# Ghidra script template (embedded Jython)
# ---------------------------------------------------------------------------
#
# These are triple-quoted strings written verbatim into the generated .py file.
# Single backslashes (e.g. \b, \s, \w) are regex escapes in the OUTPUT script,
# not in this Python source — the triple-quote preserves them as-is.
#

GHIDRA_SCRIPT_HEADER = '''\
# Ghidra import script: C++ types + symbols
# Generated by ghidra_import_gen.py
# Run in Ghidra via Script Manager
#
# @category Import
# @description Import C++ type definitions and symbol names

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import (
    StructureDataType, UnionDataType, EnumDataType, ArrayDataType, PointerDataType,
    CategoryPath, DataTypeConflictHandler,
    ByteDataType, WordDataType, DWordDataType, QWordDataType,
    CharDataType, BooleanDataType, VoidDataType,
    FloatDataType, DoubleDataType,
    ShortDataType, IntegerDataType, LongLongDataType,
    UnsignedShortDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    FunctionDefinitionDataType, ParameterDefinitionImpl,
)
import re
import struct
import hashlib
import os

dtm = currentProgram.getDataTypeManager()
CONFLICT = DataTypeConflictHandler.REPLACE_HANDLER

created = {}  # full_name -> DataType
_created_by_leaf = {}  # leaf -> [DataType]; ambiguous leaves never auto-resolve


def _find_existing_elsewhere(name, category):
    """A same-named data type already living in a DIFFERENT category.

    Re-running this generator against an already-enriched program otherwise
    re-creates a second, competing copy of a common type (BSFixedString,
    TESForm, ...) under THIS run's category instead of reusing the one already
    registered by a prior /types.h import, a PDB-derived type, or a Demangler
    stub.  This is a deliberately cheap, name-only guard against that blind
    duplicate; it does not attempt full layout reconciliation.  Callers only
    reuse when the sizes also agree, so a real layout difference still falls
    through to the normal create path.  Returns the first match or None.
    """
    import java.util.ArrayList as _ArrayList
    results = _ArrayList()
    dtm.findDataTypes(name, results)
    for dt in results:
        if str(dt.getCategoryPath()) != category:
            return dt
    return None


_VOID  = VoidDataType()
_BYTE  = ByteDataType()
_PTR   = PointerDataType()
_BOOL  = BooleanDataType()
_I16   = ShortDataType()
_U16   = UnsignedShortDataType()
_I32   = IntegerDataType()
_U32   = UnsignedIntegerDataType()
_I64   = LongLongDataType()
_U64   = UnsignedLongLongDataType()
_F32   = FloatDataType()
_F64   = DoubleDataType()
_PSIZE = currentProgram.getDefaultPointerSize()
_USIZE = _U32 if _PSIZE == 4 else _U64
_ISIZE = _I32 if _PSIZE == 4 else _I64

SOURCE_VERIFIED = SourceType.IMPORTED
SOURCE_HEURISTIC = SourceType.ANALYSIS
_ACTIVE_TARGET = None
_LINKER_FUNCTION_STARTS = set()

def _register_type(full_name, leaf_name, dt, category=None):
    created[full_name] = dt
    if category:
        created[category + '/' + leaf_name] = dt
    leaf = leaf_name.split('::')[-1]
    items = _created_by_leaf.setdefault(leaf, [])
    if dt not in items:
        items.append(dt)

def _lookup_type(name):
    dt = created.get(name)
    if dt:
        return dt
    items = _created_by_leaf.get(name.split('::')[-1], [])
    return items[0] if len(items) == 1 else None

def get_builtin(type_str):
    if type_str == 'void': return _VOID
    if type_str == 'bool': return _BOOL
    if type_str == 'i8':   return _BYTE
    if type_str == 'u8':   return _BYTE
    if type_str == 'i16':  return _I16
    if type_str == 'u16':  return _U16
    if type_str == 'i32':  return _I32
    if type_str == 'u32':  return _U32
    if type_str == 'i64':  return _I64
    if type_str == 'u64':  return _U64
    if type_str == 'usize': return _USIZE
    if type_str == 'isize': return _ISIZE
    if type_str == 'f32':  return _F32
    if type_str == 'f64':  return _F64
    if type_str == 'ptr':  return _PTR
    return None

def _resolve_struct_name(name):
    """Look up a struct/class name in 'created', handling template instantiations."""
    if '<' in name:
        # Strip only the OUTER namespace prefix -- the part before the first '<' --
        # so 'RE::BSTEventSink<RE::MenuOpenCloseEvent>' becomes
        # 'BSTEventSink<RE::MenuOpenCloseEvent>', matching how the live template
        # instantiation is named.  A full split('::')[-1] would split on the '::'
        # INSIDE the template argument and mangle the lookup, so the argument's own
        # qualification is left untouched.
        lt = name.index('<')
        stripped = name[:lt].split('::')[-1] + name[lt:]
        # Fall through every candidate rather than early-returning: TEMPLATE_TYPE_MAP
        # can map a name to itself, a degenerate alias that resolves nowhere and must
        # not short-circuit past the candidates that do resolve.
        for candidate in (TEMPLATE_TYPE_MAP.get(name), name, stripped):
            if candidate:
                hit = created.get(candidate)
                if hit:
                    return hit
        return None
    return _lookup_type(name)

def resolve_type(type_str):
    b = get_builtin(type_str)
    if b: return b
    if type_str.startswith('ptr:struct:'):
        name = type_str[11:]
        inner = _resolve_struct_name(name)
        return dtm.getPointer(inner, _PSIZE) if inner else _PTR
    if type_str.startswith('ptr:enum:'):
        name = type_str[9:]
        inner = _lookup_type(name)
        return dtm.getPointer(inner, _PSIZE) if inner else _PTR
    if type_str.startswith('ptr:'):
        inner = get_builtin(type_str[4:]) or resolve_type(type_str[4:])
        if inner: return dtm.getPointer(inner, _PSIZE)
    if type_str.startswith('ptr'): return _PTR
    if type_str.startswith('bytes:'):
        n = int(type_str[6:])
        if n == 1: return _BYTE
        return ArrayDataType(_BYTE, n, 1) if n > 1 else _BYTE
    if type_str.startswith('arr:'):
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem = resolve_type(rest[:last])
            if elem and count > 0:
                return ArrayDataType(elem, count, elem.getLength())
        return None
    if type_str.startswith('enum:'):
        name = type_str[5:]
        return _lookup_type(name)
    if type_str.startswith('struct:'):
        name = type_str[7:]
        return _resolve_struct_name(name)
    if type_str.startswith('vtblptr:'):
        name = type_str[8:]
        vtbl_dt = created.get('vtbl:' + name)
        if vtbl_dt:
            return dtm.getPointer(vtbl_dt, _PSIZE)
        return _PTR
    return None

def make_padding(size):
    if size == 1: return _BYTE
    return ArrayDataType(_BYTE, size, 1)


def apply_structured_sig(sd, func_name, addr, fm, source_type=SOURCE_VERIFIED):
    """Apply a structured signature using FunctionDefinitionDataType.

    sd is [ret_type, [[pname, ptype], ...], is_static] with pipeline type
    descriptors that resolve_type() understands.  Bypasses CParserUtils
    entirely — no C parsing errors.
    """
    ret_pipeline, params_list, is_static = sd
    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name
    fdef = FunctionDefinitionDataType(CategoryPath('/'), simple_name, dtm)
    is_member = '::' in func_name and not is_static
    if _PSIZE == 4 and is_member:
        try:
            fdef.setCallingConvention('__thiscall')
        except Exception:
            pass
    ret_dt = resolve_type(ret_pipeline)
    if ret_dt:
        fdef.setReturnType(ret_dt)
    param_defs = []
    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0]
        this_dt = _lookup_type(class_name)
        this_ptr = dtm.getPointer(this_dt, _PSIZE) if this_dt else _PTR
        param_defs.append(ParameterDefinitionImpl('this', this_ptr, ''))
    for pname, ptype in params_list:
        pdt = resolve_type(ptype) or _PTR
        param_defs.append(ParameterDefinitionImpl(pname, pdt, ''))
    if param_defs:
        fdef.setArguments(param_defs)
    cmd = ApplyFunctionSignatureCmd(addr, fdef, source_type, True, False)
    cmd.applyTo(currentProgram)
    if _PSIZE == 4 and is_member:
        f = fm.getFunctionAt(addr)
        if f:
            try:
                f.setCallingConvention('__thiscall')
            except Exception:
                pass
    return True


def convert_sig_to_ghidra(sig, func_name):
    """Convert a C++ signature to a Ghidra-compatible C prototype."""
    if not sig or sig == 'func_t':
        return None

    if 'RELOCATION_ID' in sig or 'func_t>' in sig or 'decltype' in sig:
        return None
    if ')(' in sig:
        return None
    if ':(' in sig:
        return None

    is_static = bool(re.search(r'\\bstatic\\b', sig))

    sig = ' '.join(sig.split())

    while True:
        _m_td = re.match(r'\\s*typedef\\s+[^;]+;\\s*', sig)
        if not _m_td: break
        sig = sig[_m_td.end():]

    sig = re.sub(r'^//\\s*[0-9A-Fa-f]+\\s*', '', sig)
    sig = re.sub(r'^//\\s*', '', sig)
    sig = re.sub(r'\\s*//[^\\n]*', '', sig)
    sig = re.sub(r'#\\w+\\b[^\\n]*', '', sig)
    sig = re.sub(r'\\b(?:public|private|protected)\\s*:\\s*', '', sig)
    sig = re.sub(r'\\boverride\\s+\\w+\\s*\\([^)]*\\)\\s*', '', sig)
    sig = re.sub(r'\\bRUNTIME_DATA_CONTENT\\b', '', sig)
    sig = re.sub(r'!\\w+\\([^)]*\\)\\s+', '', sig)

    sig = sig.replace('[[nodiscard]]', '')
    sig = re.sub(r'\\bstatic\\b', '', sig)
    sig = re.sub(r'\\bvirtual\\b', '', sig)
    sig = sig.strip()

    candidates = []
    depth = 0
    for i, c in enumerate(sig):
        if c == '<': depth += 1
        elif c == '>': depth -= 1
        elif c == '(' and depth == 0:
            candidates.append(i)

    if not candidates:
        return None

    paren_idx = None
    for idx in reversed(candidates):
        before = sig[:idx].rstrip()
        if before and re.search(r'[\\w*&]\\s*$', before):
            stripped_ret = before.strip()
            if stripped_ret and not re.match(
                r'^(if|for|while|switch|return|override|namespace|class|struct)\\b',
                stripped_ret.split()[-1] if stripped_ret.split() else ''
            ):
                paren_idx = idx
                break

    if paren_idx is None or paren_idx == 0:
        return None

    ret_type_raw = sig[:paren_idx].strip()
    params = sig[paren_idx:]

    ret_type = ret_type_raw
    for pat in [r'.*\\b(?:public|private|protected)\\s*:\\s*',
                r'.*\\b(?:override)\\s+\\w+\\s*\\([^)]*\\)\\s*',
                r'.*//[^/]*\\s+',
                r'.*#\\w+[^(]*\\s+',
                r'.*!\\w+\\([^)]*\\)\\s+',
                r'.*\\bnamespace\\s+\\w+\\s*\\{\\s*',
                r'.*\\bmembers\\b\\s*']:
        m = re.match(pat, ret_type, re.DOTALL)
        if m: ret_type = ret_type[m.end():]

    ret_type = ret_type.strip()
    if not ret_type:
        return None

    def simplify_type(t, is_return=False):
        size_t_name = 'uint' if _PSIZE == 4 else 'ulonglong'
        ptrdiff_name = 'int' if _PSIZE == 4 else 'longlong'
        t = re.sub(r'\\s*=\\s*[^,)]*$', '', t)
        t = t.replace('std::uint64_t', 'ulonglong')
        t = t.replace('std::int64_t', 'longlong')
        t = t.replace('std::uint32_t', 'uint')
        t = t.replace('std::int32_t', 'int')
        t = t.replace('std::uint16_t', 'ushort')
        t = t.replace('std::int16_t', 'short')
        t = t.replace('std::uint8_t', 'uchar')
        t = t.replace('std::int8_t', 'char')
        t = t.replace('std::size_t', size_t_name)
        t = t.replace('std::ptrdiff_t', ptrdiff_name)
        t = re.sub(r'\\buint64_t\\b', 'ulonglong', t)
        t = re.sub(r'\\bint64_t\\b', 'longlong', t)
        t = re.sub(r'\\buint32_t\\b', 'uint', t)
        t = re.sub(r'\\bint32_t\\b', 'int', t)
        t = re.sub(r'\\buint16_t\\b', 'ushort', t)
        t = re.sub(r'\\bint16_t\\b', 'short', t)
        t = re.sub(r'\\buint8_t\\b', 'uchar', t)
        t = re.sub(r'\\bint8_t\\b', 'char', t)
        t = re.sub(r'\\bsize_t\\b', size_t_name, t)
        t = re.sub(r'\\bptrdiff_t\\b', ptrdiff_name, t)
        t = re.sub(r'\\bresult\\b', 'int', t)
        t = re.sub(r'\\bhours\\b', 'longlong', t)
        t = re.sub(r'\\bminutes\\b', 'longlong', t)
        t = re.sub(r'\\bseconds\\b', 'longlong', t)
        t = re.sub(r'\\bErrorCode\\b', 'uint', t)
        t = re.sub(r'\\bmbstate_t\\b', 'void', t)
        t = re.sub(r'\\bva_list\\b', 'void *', t)
        t = re.sub(r'\\bchar16_t\\b', 'ushort', t)
        t = re.sub(r'\\bchar32_t\\b', 'uint', t)
        t = re.sub(r'\\bwchar_t\\b', 'ushort', t)
        t = re.sub(r'\\bconst\\b\\s*', '', t)
        t = re.sub(r'(\\w[\\w:<>]*)\\s*&', r'\\1 *', t)
        for _ in range(5):
            prev = t
            t = re.sub(r'\\w[\\w:]*<[^<>]*>\\s*\\*', 'void *', t)
            t = re.sub(r'\\w[\\w:]*<[^<>]*>', 'void', t)
            if t == prev: break
        t = re.sub(r'Args\\s*\\.\\.\\..*', '', t)
        if not is_return:
            t = re.sub(r'\\[.*?\\]', '', t)
        t = re.sub(r'\\w+::', '', t)
        return t.strip()

    ret_type = simplify_type(ret_type, is_return=True)
    if not ret_type:
        return None
    parts = ret_type.split()
    if len(parts) > 1 and parts[-1] not in ('*',) and not parts[-1].endswith('*'):
        ret_type = ' '.join(parts[:-1])

    params_inner = params[1:-1].strip() if params.endswith(')') else params[1:].rstrip(')').strip()

    if params_inner == '' or params_inner == 'void':
        ghidra_params = 'void'
    else:
        param_list = []
        current = ''; depth = 0
        for c in params_inner:
            if c == '<': depth += 1
            elif c == '>': depth -= 1
            elif c == ',' and depth == 0:
                param_list.append(current.strip()); current = ''; continue
            current += c
        if current.strip(): param_list.append(current.strip())

        ghidra_params_list = []
        for p in param_list:
            p = simplify_type(p)
            if not p: continue
            tokens = p.split()
            if len(tokens) == 2 and tokens[0] == 'void' and '*' not in tokens[1]:
                p = 'void * ' + tokens[1]
            if tokens:
                last = tokens[-1].rstrip('*')
                if last in ('int','uint','float','double','bool','void','char',
                            'short','long','uchar','ushort','ulonglong','longlong') or last.endswith('*'):
                    p = p + ' param' + str(len(ghidra_params_list))
            ghidra_params_list.append(p)

        ghidra_params = ', '.join(ghidra_params_list) if ghidra_params_list else 'void'

    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name

    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0]
        class_name_simple = class_name.split('::')[-1] if '::' in class_name else class_name
        if class_name and _lookup_type(class_name):
            this_type = class_name_simple
        else:
            this_type = 'void'
        this_param = this_type + ' * this'
        if ghidra_params == 'void':
            ghidra_params = this_param
        else:
            ghidra_params = this_param + ', ' + ghidra_params

    return ret_type + ' ' + simple_name + '(' + ghidra_params + ')'


_SAFE_TYPES = {
    'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double',
    'uchar', 'ushort', 'uint', 'ulong', 'longlong', 'ulonglong',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'byte', 'word', 'dword', 'qword', 'pointer', 'unsigned', 'signed',
}

def sanitize_unknown_types(proto):
    """Replace unknown types with void* for Ghidra parse fallback."""
    m = re.match(r'(.*?)\\s+(\\w+)\\s*\\((.*)\\)$', proto)
    if not m: return proto
    ret, name, params = m.group(1), m.group(2), m.group(3)

    def sanitize_token(t):
        t = t.strip()
        if not t or t == 'void': return t
        parts = t.split()
        base = parts[0].rstrip('*')
        if base.lower() in _SAFE_TYPES: return t
        is_ptr = '*' in t
        if is_ptr:
            star_count = t.count('*')
            stars = ' ' + '*' * star_count
            param_name = ''
            if len(parts) > 1 and '*' not in parts[-1]:
                param_name = ' ' + parts[-1]
            return 'void' + stars + param_name
        else:
            if len(parts) > 1 and parts[-1].isidentifier():
                return 'void * ' + parts[-1]
            return 'void *'

    ret_base = ret.rstrip('*').rstrip().split()[-1] if ret.split() else ret
    if ret_base.lower() not in _SAFE_TYPES:
        if '*' in ret: ret = 'void ' + '*' * ret.count('*')
        else: ret = 'void *'

    if params.strip() == 'void':
        safe_params = 'void'
    else:
        safe_params = ', '.join(sanitize_token(p.strip()) for p in params.split(','))

    return ret + ' ' + name + '(' + safe_params + ')'


def _sha256_file(path):
    h = hashlib.sha256()
    f = open(path, 'rb')
    try:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    finally:
        f.close()
    return h.hexdigest()


def _valid_sha256(value):
    value = str(value or '').strip().lower()
    return len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _is_windows_host():
    if os.name == 'nt':
        return True
    try:
        from java.lang import System as JavaSystem
        return str(JavaSystem.getProperty('os.name', '')).lower().startswith('windows')
    except Exception:
        return False


def _program_executable_path():
    path = str(currentProgram.getExecutablePath() or '')
    # Ghidra commonly renders Windows paths as /C:/path.  Jython otherwise
    # treats that form as a different path, potentially hiding a replacement.
    if (_is_windows_host() and len(path) >= 4 and path[0] == '/'
            and path[1].isalpha() and path[2] == ':' and path[3] in '/\\\\'):
        path = os.path.normpath(path[1:])
    return path


def _preflight_target():
    """Fail before transactions unless this is the exact generated-for PE."""
    global _ACTIVE_TARGET, _LINKER_FUNCTION_STARTS
    candidates = TARGET_MANIFESTS
    if not candidates:
        raise RuntimeError(
            'This importer is unbound. Regenerate it with target_manifest/target_binary_path.')
    for candidate in candidates:
        if (not _valid_sha256(candidate.get('sha256'))
                or not candidate.get('file_size')
                or int(candidate.get('pointer_size', 0)) not in (4, 8)):
            raise RuntimeError('Generated target manifest is incomplete')

    # Read immutable import metadata before selecting the allowed manifest.  A
    # truly missing temporary backing path may select only by this exact hash.
    program_hash = None
    try:
        program_hash = currentProgram.getExecutableSHA256()
    except Exception:
        pass
    try:
        from ghidra.program.model.listing import Program
        options = currentProgram.getOptions(Program.PROGRAM_INFO)
        if not program_hash:
            program_hash = options.getString('Executable SHA256', None)
        if not program_hash:
            program_hash = options.getString('BGS Target SHA256', None)
        recorded_image_size = -1
        for key in ('Image Size', 'PE Image Size', 'SizeOfImage'):
            value = options.getLong(key, -1)
            if value > 0:
                recorded_image_size = value
                break
    except Exception:
        recorded_image_size = -1
    if program_hash:
        program_hash = str(program_hash).strip().lower()

    executable_path = _program_executable_path()
    backing_file = bool(executable_path and os.path.isfile(executable_path))
    if (not backing_file and executable_path
            and os.path.lexists(executable_path)):
        raise RuntimeError(
            'Backing executable exists but is not a regular file; no changes were made')

    expected = None
    missing_backing = not backing_file
    if backing_file:
        # An extant backing file is authoritative.  Its replacement or drift
        # must never be bypassed using stale Program metadata.
        actual_size = os.path.getsize(executable_path)
        actual_hash = _sha256_file(executable_path)
        for candidate in candidates:
            if (int(candidate.get('file_size', -1)) == actual_size
                    and str(candidate.get('sha256')).lower() == actual_hash.lower()):
                expected = candidate
                break
        if expected is None:
            raise RuntimeError('Executable SHA-256 mismatch; no changes were made')
    else:
        if not _valid_sha256(program_hash):
            raise RuntimeError(
                'Missing backing executable requires an exact import-time SHA-256')
        for candidate in candidates:
            if str(candidate.get('sha256')).lower() == program_hash:
                expected = candidate
                break
        if expected is None:
            raise RuntimeError(
                'Missing backing executable import-time SHA-256 is not allowed')

    if int(expected.get('pointer_size', 0)) != _PSIZE:
        raise RuntimeError('Pointer width mismatch: expected {}, loaded {}'.format(
            expected.get('pointer_size'), _PSIZE))

    expected_base = int(expected.get('image_base', 0))
    loaded_base = currentProgram.getImageBase().getOffset()
    if expected_base <= 0:
        raise RuntimeError('Target manifest lacks PE image base')
    if loaded_base != expected_base:
        raise RuntimeError('Image-base mismatch: expected 0x{:X}, loaded 0x{:X}'.format(
            expected_base, loaded_base))

    if program_hash:
        if str(program_hash).lower() != str(expected.get('sha256')).lower():
            raise RuntimeError('Loaded Program hash is stale/different; no changes were made')
    elif not expected.get('anchors'):
        raise RuntimeError('Program has no import-time hash and manifest has no memory anchors')
    expected_image_size = int(expected.get('image_size', 0))
    if expected_image_size <= 0:
        raise RuntimeError('Target manifest lacks PE SizeOfImage')
    if recorded_image_size > 0 and recorded_image_size != expected_image_size:
        raise RuntimeError('Loaded Program SizeOfImage mismatch')

    # Independently validate every expected PE section against mapped Program
    # blocks; this is stronger than a min/max address envelope.
    memory = currentProgram.getMemory()
    base = currentProgram.getImageBase()
    verified_sections = 0
    for section in expected.get('sections', []):
        span = max(int(section.get('virtual_size', 0)), int(section.get('raw_size', 0)))
        if span <= 0:
            continue
        first = base.add(int(section['rva']))
        last = first.add(span - 1)
        if memory.getBlock(first) is None or memory.getBlock(last) is None:
            raise RuntimeError('Loaded Program section is missing/truncated: ' + section.get('name', ''))
        verified_sections += 1
    if missing_backing and verified_sections == 0:
        raise RuntimeError('Missing backing executable requires mapped PE sections')

    # Anchors are mandatory without a backing file and always checked when
    # present, even with a stored hash, to attest the live Program memory.
    anchors = expected.get('anchors', [])
    if missing_backing and not anchors:
        raise RuntimeError('Missing backing executable requires memory anchors')
    for anchor in anchors:
        rva = int(anchor['rva'])
        wanted = str(anchor['bytes']).replace(' ', '').lower()
        got = []
        for i in range(len(wanted) // 2):
            got.append('{:02x}'.format(memory.getByte(base.add(rva + i)) & 0xff))
        if ''.join(got) != wanted:
            raise RuntimeError('Loaded-memory anchor mismatch at RVA 0x{:X}'.format(rva))

    _ACTIVE_TARGET = expected
    _LINKER_FUNCTION_STARTS = set(int(value)
                                  for value in expected.get('function_starts', []))


def _checked_rva(rva, kind='label'):
    """Return a mapped address with permissions appropriate for *kind*."""
    try:
        rva = int(rva)
    except Exception:
        return None
    if _ACTIVE_TARGET is None:
        return None
    image_size = int(_ACTIVE_TARGET.get('image_size', 0))
    if rva < 0 or (image_size and rva >= image_size):
        return None
    try:
        addr = currentProgram.getImageBase().add(rva)
        block = currentProgram.getMemory().getBlock(addr)
        if block is None or not block.isInitialized():
            return None
        if kind == 'func' and not block.isExecute():
            return None
        if kind == 'data' and block.isExecute():
            return None
        return addr
    except Exception:
        return None


def _checked_absolute(value, kind='label'):
    try:
        rva = int(value) - currentProgram.getImageBase().getOffset()
    except Exception:
        return None
    return _checked_rva(rva, kind)


def _symbol_assertion(symbol, field, version_key):
    value = symbol.get(field)
    if isinstance(value, dict):
        return value.get(version_key)
    return value


def _manifest_section_name(rva):
    if _ACTIVE_TARGET is None:
        return None
    for section in _ACTIVE_TARGET.get('sections', []):
        start = int(section.get('rva', 0))
        span = max(int(section.get('virtual_size', 0)),
                   int(section.get('raw_size', 0)))
        if start <= int(rva) < start + span:
            return section.get('name')
    return None


def _symbol_evidence_matches_target(symbol, version_key, rva):
    """Validate per-symbol provenance in addition to the global importer bind."""
    asserted_sha = _symbol_assertion(symbol, 'target_sha256', version_key)
    if (asserted_sha and _ACTIVE_TARGET and
            str(asserted_sha).lower() !=
            str(_ACTIVE_TARGET.get('sha256', '')).lower()):
        return False
    asserted_section = _symbol_assertion(symbol, 'sections', version_key)
    if asserted_section:
        actual_section = _manifest_section_name(rva)
        if str(asserted_section) != str(actual_section):
            return False
    return True


def _ensure_function(addr, suggested_name=None, verified_entry=False):
    """Create only at executable, non-interior function entry addresses."""
    if addr is None:
        return None
    block = currentProgram.getMemory().getBlock(addr)
    if block is None or not block.isExecute():
        return None
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(addr)
    if f:
        return f
    containing = fm.getFunctionContaining(addr)
    if containing is not None:
        return None
    rva = addr.getOffset() - currentProgram.getImageBase().getOffset()
    if _PSIZE == 8:
        if rva not in _LINKER_FUNCTION_STARTS:
            return None
    elif not verified_entry:
        # PE32 has no .pdata function table.  Only sources that explicitly
        # attest an entry boundary (e.g. a real vtable pointer/PDB procedure)
        # may promote bytes to a function.
        return None
    if not DisassembleCommand(addr, None, True).applyTo(currentProgram):
        return None
    try:
        return createFunction(addr, suggested_name)
    except Exception:
        return fm.getFunctionAt(addr)


def _merge_plate_comment(addr, parts):
    """Append unique evidence lines without erasing analyst comments."""
    if not parts:
        return
    listing = currentProgram.getListing()
    cu = listing.getCodeUnitAt(addr) or listing.getCodeUnitContaining(addr)
    if not cu:
        return
    existing = cu.getComment(0) or ''
    lines = existing.splitlines() if existing else []
    for part in parts:
        if part and part not in lines:
            lines.append(part)
    cu.setComment(0, '\\n'.join(lines))


def _source_for_symbol(symbol, fallback=False):
    """Map evidence confidence to a Ghidra source priority."""
    confidence = str(symbol.get('confidence', '')).lower()
    provenance = str(symbol.get('src', '')).lower()
    if confidence in ('verified', 'exact'):
        return SOURCE_VERIFIED
    if not fallback and confidence not in ('low', 'medium', 'heuristic'):
        return SOURCE_VERIFIED
    if fallback and ('pdb' in provenance or 'dia' in provenance) \
            and confidence in ('high', 'verified', 'exact'):
        return SOURCE_VERIFIED
    return SOURCE_HEURISTIC

'''

GHIDRA_SCRIPT_FOOTER = '''\

def run():
    _preflight_target()
    # A generated script can be launched directly from Ghidra, without one of
    # our PyGhidra wrappers.  Keep a program-level parent transaction open so
    # a later symbol failure also rolls back the earlier datatype subtransaction.
    # DomainObject.endTransaction() returns False while a caller-owned parent
    # transaction is still active, even when this nested transaction voted to
    # commit successfully.  Only the owner of the outermost transaction can
    # interpret its return value as the final commit result.
    had_parent_transaction = currentProgram.getCurrentTransactionInfo() is not None
    tx_all = currentProgram.startTransaction('Atomic CommonLib import')
    commit_all = False
    try:
        tx_types = dtm.startTransaction('Import types')
        commit_types = False
        try:
            _import_types()
            commit_types = True
        finally:
            dtm.endTransaction(tx_types, commit_types)

        tx_syms = currentProgram.startTransaction('Symbol import')
        commit_syms = False
        try:
            _import_symbols()
            _import_fallback_symbols()
            _import_vtable_names()
            commit_syms = True
        finally:
            currentProgram.endTransaction(tx_syms, commit_syms)
        commit_all = True
    finally:
        all_committed = bool(currentProgram.endTransaction(
            tx_all, commit_all))
        if commit_all and not had_parent_transaction and not all_committed:
            raise RuntimeError('CommonLib import transaction did not commit')

    print('All passes complete.')


def _import_types():
    monitor.setMessage('Creating enums...')
    enums_reused = 0
    for en in ENUMS:
        name, full_name, size, category, values = en
        existing = _find_existing_elsewhere(name, category)
        if existing is not None and existing.getLength() == size:
            dt = existing
            enums_reused += 1
        else:
            e = EnumDataType(CategoryPath(category), name, size)
            for vname, vval in values:
                try:
                    e.add(vname, vval)
                except Exception:
                    e.add(vname + '_', vval)
            dt = dtm.addDataType(e, CONFLICT)
        _register_type(full_name, name, dt, category)
    print('Created {} enums ({} reused existing)'.format(
        len(ENUMS) - enums_reused, enums_reused))

    # Shells must exist before vtable function definitions so return/parameter
    # descriptors resolve to the exact class type instead of degrading to void*.
    monitor.setMessage('Creating struct shells...')
    shells_reused = 0
    for st in STRUCTS:
        name, full_name, record_kind, size, category, fields, bases, has_vtable = st
        existing = _find_existing_elsewhere(name, category)
        if existing is not None and existing.getLength() == size:
            # Reuse the type that is already registered rather than adding a
            # competing copy.  Nothing lands under this run's category, so the
            # field-filling pass below skips it -- its getDataType() lookup misses.
            dt = existing
            shells_reused += 1
        else:
            if record_kind == 'union':
                s = UnionDataType(CategoryPath(category), name)
                if size > 0:
                    s.add(make_padding(size), size, '__storage', 'Exact union storage size')
            else:
                s = StructureDataType(CategoryPath(category), name, size)
            dt = dtm.addDataType(s, CONFLICT)
        _register_type(full_name, name, dt, category)
    print('Created {} record shells ({} reused existing)'.format(
        len(STRUCTS) - shells_reused, shells_reused))

    monitor.setMessage('Creating vtable structs...')
    # Slot offsets are emitted at 8-byte (x64) stride by the generator.
    # Rescale to the loaded program's pointer size so 32-bit targets
    # (FNV) get correct 4-byte-stride layouts instead of every-other-slot.
    _vt_psize = currentProgram.getDefaultPointerSize()
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots, vt_kind, subobject_offset = vt
        scaled_size = (vtbl_size // 8) * _vt_psize if _vt_psize != 8 else vtbl_size
        s = StructureDataType(CategoryPath(category), vname, scaled_size)
        for slot_off, slot_name, slot_ret, slot_params in slots:
            field_name = slot_name.replace('~', '_dtor_') if slot_name.startswith('~') else slot_name
            real_off = (slot_off // 8) * _vt_psize
            if real_off + _vt_psize <= scaled_size:
                try:
                    if slot_ret is not None and slot_params is not None:
                        fdef = FunctionDefinitionDataType(CategoryPath(category), field_name + '_t', dtm)
                        if _vt_psize == 4:
                            try:
                                fdef.setCallingConvention('__thiscall')
                            except Exception:
                                pass
                        ret_dt = resolve_type(slot_ret)
                        if ret_dt:
                            fdef.setReturnType(ret_dt)
                        this_dt = _lookup_type(class_full_name)
                        this_ptr = dtm.getPointer(this_dt, _vt_psize) if this_dt else _PTR
                        param_defs = [ParameterDefinitionImpl('this', this_ptr, '')]
                        for pname, ptype in slot_params:
                            pdt = resolve_type(ptype) or _PTR
                            param_defs.append(ParameterDefinitionImpl(pname, pdt, ''))
                        fdef.setArguments(param_defs)
                        fptr = dtm.getPointer(dtm.addDataType(fdef, CONFLICT), _vt_psize)
                        s.replaceAtOffset(real_off, fptr, _vt_psize, field_name, '')
                    else:
                        s.replaceAtOffset(real_off, _PTR, _vt_psize, field_name, '')
                except Exception:
                    pass
        dt = dtm.addDataType(s, CONFLICT)
        created['vtbl:' + vname] = dt
    print('Created {} vtable structs'.format(len(VTABLES)))

    monitor.setMessage('Filling struct fields...')
    filled = 0
    for st in STRUCTS:
        name, full_name, record_kind, size, category, fields, bases, has_vtable = st
        s = dtm.getDataType(CategoryPath(category), name)
        if not s:
            continue
        for field in fields:
            fname, ftype_str, foffset, fsize = field
            if ftype_str.startswith('bf:'):
                parts = ftype_str.split(':')
                bf_bit_offset = int(parts[1])
                bf_width = int(parts[2])
                bf_bw = 4
                bf_base = _U32
                for _bw, _bd in [(1, _BYTE), (2, _U16), (4, _U32), (8, _U64)]:
                    _bits = _bw * 8
                    _sb = (bf_bit_offset // _bits) * _bw
                    if bf_bit_offset % _bits + bf_width <= _bits and _sb + _bw <= size:
                        bf_bw = _bw
                        bf_base = _bd
                        break
                storage_byte = (bf_bit_offset // (bf_bw * 8)) * bf_bw
                bit_in_storage = bf_bit_offset % (bf_bw * 8)
                try:
                    if record_kind == 'union':
                        s.addBitField(bf_base, bf_width, fname, '')
                    else:
                        s.insertBitFieldAt(storage_byte, bf_bw, bit_in_storage,
                                           bf_base, bf_width, fname, '')
                except Exception:
                    pass
                continue
            if fsize <= 0 or foffset + fsize > size:
                continue
            dt_field = resolve_type(ftype_str)
            if dt_field and dt_field.getLength() == fsize:
                use_dt = dt_field
                use_name = fname
            else:
                use_dt = make_padding(fsize)
                use_name = fname + '_raw'
            try:
                if record_kind == 'union':
                    s.add(use_dt, fsize, use_name, '')
                else:
                    s.replaceAtOffset(foffset, use_dt, fsize, use_name, '')
            except Exception:
                pass
        filled += 1
    print('Filled {} structs'.format(filled))


def _import_symbols():
    # Per-version offset key embedded in the SYMBOLS array.  F4 OG/VR
    # use ID namespaces disjoint from CommonLibF4's NG/AE-keyed IDs, so
    # no per-symbol offset exists for them; type/vtable/enum application
    # still runs but no function symbols get applied (use byte-signature
    # porting from AE as a separate post-pass).
    version_key = {
        'se': 's', 'ae': 'a', 'svr': 'v',
        'f4_og': 'og', 'f4_ng': 'ng', 'f4_ae': 'a', 'f4_vr': 'v',
        'f4_221': '221',
        'sf': 'sf',
        'fnv': 'fnv',
    }.get(VERSION, 'a')
    symbol_table = currentProgram.getSymbolTable()
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()

    print('Target version: ' + VERSION.upper())
    print('Applying ' + str(len(SYMBOLS)) + ' symbols...')

    count_sym = 0; count_func = 0; count_sig = 0; count_sig_fail = 0; count_invalid = 0
    used_names_at_addr = {}
    name_occurrence_count = {}

    for i, s in enumerate(SYMBOLS):
        off = s.get(version_key)
        if off is None: continue
        off = int(off)

        if not _symbol_evidence_matches_target(s, version_key, off):
            count_invalid += 1
            continue

        symbol_kind = s.get('t', 'label')
        checked_kind = ('func' if symbol_kind == 'func' else
                        ('data' if symbol_kind == 'data' else 'label'))
        addr = _checked_rva(off, checked_kind)
        if addr is None:
            count_invalid += 1
            continue
        sname = s['n']
        source_type = _source_for_symbol(s, False)

        if addr not in used_names_at_addr:
            used_names_at_addr[addr] = set()
        if sname in used_names_at_addr[addr]:
            continue

        if sname in name_occurrence_count:
            name_occurrence_count[sname] += 1
            final_name = sname + '_' + str(name_occurrence_count[sname])
        else:
            name_occurrence_count[sname] = 0
            final_name = sname

        try:
            symbol_table.createLabel(addr, final_name, source_type)
            used_names_at_addr[addr].add(sname)
            count_sym += 1
            if s['t'] == 'label':
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu:
                    parts = []
                    se_id = s.get('si')
                    ae_id = s.get('ai')
                    if se_id and ae_id:
                        parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                    elif se_id:
                        parts.append('REL::ID(' + str(se_id) + ')')
                    elif ae_id:
                        parts.append('REL::ID(' + str(ae_id) + ')')
                    if final_name.startswith('RTTI_'):
                        parts.append('Source: ' + PROJECT_NAME + ' (Offsets_RTTI.h)')
                    elif final_name.startswith('VTABLE_'):
                        parts.append('Source: ' + PROJECT_NAME + ' (Offsets_VTABLE.h)')
                    elif s.get('src'):
                        parts.append('Source: ' + s['src'])
                    if parts:
                        _merge_plate_comment(addr, parts)
        except: pass

        if s['t'] == 'func':
            try:
                f = _ensure_function(addr, final_name, bool(s.get('verified_entry')))

                if f:
                    curr_name = f.getName()
                    if curr_name.startswith('FUN_') or curr_name.startswith('sub_'):
                        f.setName(final_name, source_type)

                    comment_parts = []
                    se_id = s.get('si')
                    ae_id = s.get('ai')
                    if se_id and ae_id:
                        comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                    elif se_id:
                        comment_parts.append('REL::ID(' + str(se_id) + ')')
                    elif ae_id:
                        comment_parts.append('REL::ID(' + str(ae_id) + ')')
                    src = s.get('src', '')
                    if src == PROJECT_NAME:
                        comment_parts.append('Source: ' + PROJECT_NAME + ' headers')
                    elif src == 'skyrimae.rename':
                        comment_parts.append('Source: AE rename database (fallback)')
                    elif src:
                        comment_parts.append('Source: ' + src)
                    if comment_parts:
                        _merge_plate_comment(addr, comment_parts)

                    sd = s.get('sd')
                    sig = s.get('sig', '')
                    if sd:
                        try:
                            apply_structured_sig(sd, final_name, addr, fm, source_type)
                            count_sig += 1
                        except:
                            count_sig_fail += 1
                    elif sig:
                        proto = convert_sig_to_ghidra(sig, final_name)
                        if proto:
                            applied = False
                            try:
                                func_def = CParserUtils.parseSignature(None, currentProgram, proto, True)
                                if func_def:
                                    cmd = ApplyFunctionSignatureCmd(addr, func_def, source_type, True, False)
                                    cmd.applyTo(currentProgram)
                                    applied = True
                            except: pass
                            if not applied:
                                proto_safe = sanitize_unknown_types(proto)
                                if proto_safe != proto:
                                    try:
                                        func_def = CParserUtils.parseSignature(None, currentProgram, proto_safe, True)
                                        if func_def:
                                            cmd = ApplyFunctionSignatureCmd(addr, func_def, source_type, True, False)
                                            cmd.applyTo(currentProgram)
                                            applied = True
                                    except: pass
                            if applied:
                                count_sig += 1
                            else:
                                count_sig_fail += 1
                                if count_sig_fail <= 20:
                                    print('SIG FAIL: ' + proto[:120])
                    count_func += 1
            except: pass

        if i % 5000 == 0 and i > 0:
            print('Progress: ' + str(i) + ' symbols processed...')

    print('Labels: ' + str(count_sym) + ', Functions: ' + str(count_func))
    print('Rejected invalid/unmapped/section-mismatched symbols: ' + str(count_invalid))
    print('Signatures applied: ' + str(count_sig) + ', failed: ' + str(count_sig_fail))


def _build_rva_to_id():
    import base64 as _b64
    rva_to_id = {}
    if _ADDRLIB_B64:
        blob = _b64.b64decode(_ADDRLIB_B64)
        for i in range(0, len(blob), 8):
            rva, rid = struct.unpack_from('<II', blob, i)
            rva_to_id[rva] = rid
    else:
        version_key = 's' if VERSION == 'se' else 'a'
        id_key = 'si' if VERSION == 'se' else 'ai'
        for s in SYMBOLS:
            rva = s.get(version_key)
            rid = s.get(id_key)
            if rva and rid:
                rva_to_id[rva] = rid
        if FALLBACK_SYMBOLS:
            for s in FALLBACK_SYMBOLS:
                rva = s.get(version_key)
                rid = s.get(id_key)
                if rva and rid and rva not in rva_to_id:
                    rva_to_id[rva] = rid
    return rva_to_id


def _format_id_comment(rva, rva_to_id):
    rid = rva_to_id.get(rva)
    if rid is None:
        return None
    return 'REL::ID(' + str(rid) + ')'


def _import_vtable_names():
    monitor.setMessage('Naming virtual functions from vtable addresses...')
    fm = currentProgram.getFunctionManager()
    sym_table = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    ptr_size = currentProgram.getDefaultPointerSize()
    base_addr = currentProgram.getImageBase()
    rva_to_id = _build_rva_to_id()
    named_vfuncs = 0
    vtbl_not_found = 0
    vtbl_found = 0
    read_fail = 0
    no_func = 0
    already_named = 0
    id_comments_added = 0
    shared_conflicts = 0

    def _read_vfunc(vtbl_addr, slot_off):
        ptr_addr = vtbl_addr.add((slot_off // 8) * ptr_size)
        if ptr_size == 8:
            raw = memory.getLong(ptr_addr)
            if raw < 0:
                raw += (1 << 64)
        else:
            raw = memory.getInt(ptr_addr) & 0xFFFFFFFF
        return _checked_absolute(raw, 'func')

    # Resolve ownership before renaming.  A base implementation or ICF-folded
    # body can be referenced by several classes; first-writer-wins would give
    # it an arbitrary derived-class name.
    vfunc_claims = {}
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots, vt_kind, subobject_offset = vt
        if vt_kind != 'primary':
            continue
        class_short = class_full_name.split('::')[-1]
        syms = list(sym_table.getSymbols('VTABLE_' + class_short))
        if len(syms) != 1:
            continue
        for slot_off, slot_name, slot_ret, slot_params in slots:
            if slot_name.startswith('fn_'):
                continue
            try:
                claim_addr = _read_vfunc(syms[0].getAddress(), slot_off)
                if claim_addr is not None:
                    key = claim_addr.getOffset()
                    vfunc_claims.setdefault(key, []).append(
                        (class_full_name, slot_name, slot_ret, slot_params, slot_off))
            except Exception:
                pass

    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots, vt_kind, subobject_offset = vt
        # Secondary tables need an exact COL/subobject-address identity.  They
        # must never be walked through the primary VTABLE_Class label.
        if vt_kind != 'primary':
            continue
        class_short = class_full_name.split('::')[-1]
        vtbl_label = 'VTABLE_' + class_short
        vtbl_syms = list(sym_table.getSymbols(vtbl_label))
        if len(vtbl_syms) != 1:
            vtbl_not_found += 1
            continue
        vtbl_found += 1
        vtbl_addr = vtbl_syms[0].getAddress()
        for slot_off, slot_name, slot_ret, slot_params in slots:
            if slot_name.startswith('fn_'):
                continue
            try:
                # slot_off is emitted at 8-byte stride; rescale for the
                # loaded program's pointer width (4 on 32-bit FNV).
                func_addr = _read_vfunc(vtbl_addr, slot_off)
                func = _ensure_function(func_addr, None, True)
                if not func:
                    no_func += 1
                    continue
                curr = func.getName()
                was_named = not (curr.startswith('FUN_') or curr.startswith('sub_'))
                func_rva = func_addr.getOffset() - base_addr.getOffset()
                if was_named:
                    already_named += 1
                    cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                    if cu:
                        existing = cu.getComment(0) or ''
                        if 'REL::ID' not in existing and 'RELOCATION_ID' not in existing:
                            id_str = _format_id_comment(func_rva, rva_to_id)
                            if id_str:
                                new_comment = id_str + '\\n' + existing if existing else id_str
                                _merge_plate_comment(func_addr, [id_str])
                                id_comments_added += 1
                else:
                    comment_parts = []
                    id_str = _format_id_comment(func_rva, rva_to_id)
                    if id_str:
                        comment_parts.append(id_str)
                        id_comments_added += 1
                    comment_parts.append('VTABLE ' + class_full_name + '::' + slot_name)
                    comment_parts.append('Slot offset: +0x{:X}'.format(slot_off))
                    comment_parts.append('Source: ' + PROJECT_NAME + ' vtable walk')
                    claims = vfunc_claims.get(func_addr.getOffset(), [])
                    claim_names = set(c[0] + '::' + c[1] for c in claims)
                    if len(claim_names) == 1:
                        func.setName(class_short + '::' + slot_name, SOURCE_VERIFIED)
                        named_vfuncs += 1
                    else:
                        shared_conflicts += 1
                        comment_parts.append('Shared vfunc claims: ' + ' | '.join(sorted(claim_names)))
                    _merge_plate_comment(func_addr, comment_parts)
                claims = vfunc_claims.get(func_addr.getOffset(), [])
                claim_sigs = set(repr((c[2], c[3])) for c in claims if c[2] is not None and c[3] is not None)
                if slot_ret is not None and slot_params is not None and len(claim_sigs) <= 1:
                    has_sig = func.getSignature().getReturnType().getClass().getSimpleName() != 'DefaultDataType'
                    if not has_sig:
                        try:
                            fdef = FunctionDefinitionDataType(CategoryPath('/'), slot_name, dtm)
                            if ptr_size == 4:
                                try:
                                    fdef.setCallingConvention('__thiscall')
                                except Exception:
                                    pass
                            ret_dt = resolve_type(slot_ret)
                            if ret_dt:
                                fdef.setReturnType(ret_dt)
                            pdefs = []
                            this_dt = _lookup_type(class_full_name)
                            this_ptr = dtm.getPointer(this_dt, ptr_size) if this_dt else _PTR
                            pdefs.append(ParameterDefinitionImpl('this', this_ptr, ''))
                            for pname, ptype in slot_params:
                                pdt = resolve_type(ptype) or _PTR
                                pdefs.append(ParameterDefinitionImpl(pname, pdt, ''))
                            fdef.setArguments(pdefs)
                            ApplyFunctionSignatureCmd(func_addr, fdef,
                                SOURCE_VERIFIED, True, False).applyTo(currentProgram)
                        except Exception:
                            pass
            except Exception:
                read_fail += 1
    print('Named {} virtual functions from vtable addresses'.format(named_vfuncs))
    print('  vtbl_found={} vtbl_not_found={} read_fail={} no_func={} already_named={} id_comments={} shared_conflicts={}'.format(
        vtbl_found, vtbl_not_found, read_fail, no_func, already_named, id_comments_added, shared_conflicts))

    # Second pass: walk VTABLE_ labels without struct definitions
    handled_labels = set()
    for vt in VTABLES:
        if vt[5] == 'primary':
            class_short = vt[1].split('::')[-1]
            handled_labels.add('VTABLE_' + class_short)
    unnamed_named = 0
    unnamed_walked = 0
    unnamed_conflicts = 0
    # Match "FOO" or "FOO_N" where N is the secondary vtable index (2..).
    # First collect every claim without mutating the Program.  ICF-folded and
    # inherited bodies frequently occur in more than one physical table; a
    # streaming first-writer-wins walk assigns them an arbitrary class owner.
    sec_re = re.compile(r'^(.+?)_(\\d+)$')
    unnamed_tables = []
    unnamed_claims = {}
    all_vtable_symbols = [
        sym for sym in sym_table.getAllSymbols(False)
        if sym.getName().startswith('VTABLE_')]
    vtable_starts_by_block = {}
    for sym in all_vtable_symbols:
        block = memory.getBlock(sym.getAddress())
        if block is not None:
            vtable_starts_by_block.setdefault(block.getName(), set()).add(
                sym.getAddress().getOffset())
    for claim_addr, claims in vfunc_claims.items():
        unnamed_claims[claim_addr] = set(
            c[0] + '::' + c[1] for c in claims)
    for sym in all_vtable_symbols:
        sname = sym.getName()
        if sname in handled_labels:
            continue
        label_short = sname[7:]
        sec_match = sec_re.match(label_short)
        if sec_match:
            class_short = sec_match.group(1)
            sec_suffix = '_v' + sec_match.group(2)
        else:
            class_short = label_short
            sec_suffix = ''
        vtbl_addr = sym.getAddress()
        block = memory.getBlock(vtbl_addr)
        if block is None:
            continue
        start_off = vtbl_addr.getOffset()
        end_off = block.getEnd().getOffset() + 1
        for candidate in sorted(vtable_starts_by_block.get(
                block.getName(), set())):
            if candidate > start_off:
                end_off = min(end_off, candidate)
                break
        max_table_slots = max(0, (end_off - start_off) // ptr_size)
        table_entries = []
        slot_idx = 0
        while slot_idx < max_table_slots:
            slot_idx += 1
            try:
                func_addr = _read_vfunc(vtbl_addr, (slot_idx - 1) * 8)
                if func_addr is None:
                    break
                func_name = 'Func{}{}'.format(slot_idx, sec_suffix)
                semantic_name = class_short + '::' + func_name
                table_entries.append((func_addr, slot_idx, func_name,
                                      semantic_name))
                unnamed_claims.setdefault(func_addr.getOffset(), set()).add(
                    semantic_name)
            except Exception:
                break
        unnamed_tables.append((class_short, table_entries))
        unnamed_walked += 1

    # Apply a placeholder only when one semantic owner exists globally.
    # Conflicts remain unnamed and retain every competing claim as evidence.
    for class_short, table_entries in unnamed_tables:
        for func_addr, slot_idx, func_name, semantic_name in table_entries:
            try:
                func = _ensure_function(func_addr, None, True)
                if not func:
                    continue
                curr = func.getName()
                if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                    continue
                func_rva = func_addr.getOffset() - base_addr.getOffset()
                comment_parts = []
                id_str = _format_id_comment(func_rva, rva_to_id)
                if id_str:
                    comment_parts.append(id_str)
                comment_parts.append('VTABLE ' + semantic_name)
                comment_parts.append('Slot offset: +0x{:X}'.format(
                    (slot_idx - 1) * ptr_size))
                comment_parts.append(
                    'Source: ' + PROJECT_NAME + ' vtable walk (unnamed)')
                claims = unnamed_claims.get(func_addr.getOffset(), set())
                if len(claims) == 1:
                    func.setName(semantic_name, SOURCE_HEURISTIC)
                    unnamed_named += 1
                else:
                    unnamed_conflicts += 1
                    comment_parts.append(
                        'Shared unnamed-vtable claims: ' +
                        ' | '.join(sorted(claims)))
                _merge_plate_comment(func_addr, comment_parts)
            except Exception:
                read_fail += 1
    print('Unnamed vtable walk: {} vtables walked, {} functions named, '
          '{} shared claims rejected'.format(
              unnamed_walked, unnamed_named, unnamed_conflicts))


def _import_fallback_symbols():
    """Apply fallback symbols only to addresses not yet named."""
    # Per-version offset key embedded in the SYMBOLS array.  F4 OG/VR
    # use ID namespaces disjoint from CommonLibF4's NG/AE-keyed IDs, so
    # no per-symbol offset exists for them; type/vtable/enum application
    # still runs but no function symbols get applied (use byte-signature
    # porting from AE as a separate post-pass).
    version_key = {
        'se': 's', 'ae': 'a', 'svr': 'v',
        'f4_og': 'og', 'f4_ng': 'ng', 'f4_ae': 'a', 'f4_vr': 'v',
        'f4_221': '221',
        'sf': 'sf',
        'fnv': 'fnv',
    }.get(VERSION, 'a')
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()
    symbol_table = currentProgram.getSymbolTable()

    print('Applying ' + str(len(FALLBACK_SYMBOLS)) + ' fallback symbols...')
    count_applied = count_skipped = count_invalid = 0
    count_fb_sig = count_fb_sig_fail = 0

    for s in FALLBACK_SYMBOLS:
        off = s.get(version_key)
        if off is None:
            continue
        off = int(off)
        if not _symbol_evidence_matches_target(s, version_key, off):
            count_invalid += 1
            continue
        symbol_kind = s.get('t', 'label')
        checked_kind = ('func' if symbol_kind == 'func' else
                        ('data' if symbol_kind == 'data' else 'label'))
        addr = _checked_rva(off, checked_kind)
        if addr is None:
            count_invalid += 1
            continue
        sname = s['n']
        source_type = _source_for_symbol(s, True)

        try:
            f = (_ensure_function(addr, None, bool(s.get('verified_entry')))
                 if symbol_kind == 'func' else None)

            sig_target = None
            was_renamed = False
            if symbol_kind == 'func' and f:
                curr = f.getName()
                if curr.startswith('FUN_') or curr.startswith('sub_'):
                    f.setName(sname, source_type)
                    sig_target = f
                    was_renamed = True
                elif curr == sname:
                    # Same symbol applied by a previous run -- still eligible
                    # for signature application (makes sig fixes idempotent
                    # and retro-applicable by re-running the script).
                    sig_target = f
                else:
                    count_skipped += 1
                    continue
            elif symbol_kind == 'func':
                count_invalid += 1
                continue
            else:
                primary = symbol_table.getPrimarySymbol(addr)
                if primary is not None and not (primary.getName().startswith('DAT_')
                                                or primary.getName().startswith('LAB_')):
                    count_skipped += 1
                    continue
                symbol_table.createLabel(addr, sname, source_type)
                was_renamed = True

            # Structured signature (DIA / parsed-PDB-sig derived).  Same
            # apply path as primary symbols; previously fallback symbols
            # dropped their 'sd' on the floor (e.g. FNV ships ~19k of them).
            sd = s.get('sd')
            if sd and sig_target is not None:
                has_sig = sig_target.getSignature().getReturnType().getClass().getSimpleName() != 'DefaultDataType'
                if not has_sig:
                    try:
                        apply_structured_sig(sd, sname, addr, fm, source_type)
                        count_fb_sig += 1
                    except:
                        count_fb_sig_fail += 1

            if not was_renamed:
                count_skipped += 1
                continue

            comment_parts = []
            se_id = s.get('si')
            ae_id = s.get('ai')
            if se_id and ae_id:
                comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
            elif se_id:
                comment_parts.append('REL::ID(' + str(se_id) + ')')
            elif ae_id:
                comment_parts.append('REL::ID(' + str(ae_id) + ')')
            src = s.get('src', '')
            if src == 'skyrimae.rename':
                comment_parts.append('Source: AE rename database (fallback)')
            elif src:
                comment_parts.append('Source: ' + src + ' (fallback)')
            if comment_parts:
                _merge_plate_comment(addr, comment_parts)
            count_applied += 1
        except:
            pass

    print('Fallback: applied ' + str(count_applied) + ', skipped (already named): ' + str(count_skipped))
    print('Fallback rejected invalid/unmapped/section-mismatched: ' + str(count_invalid))
    if count_fb_sig or count_fb_sig_fail:
        print('Fallback signatures applied: ' + str(count_fb_sig) + ', failed: ' + str(count_fb_sig_fail))


run()
'''


# ---------------------------------------------------------------------------
# Script generation
# ---------------------------------------------------------------------------

def generate_script(
    enums: dict,
    structs: dict,
    vtable_structs: dict,
    output_path: str,
    version: str,
    symbols_json: str,
    fallback_symbols_json: str = '[]',
    template_source: str = '',
    project_name: str = 'CommonLibSSE',
    script_header: Optional[str] = None,
    script_footer: Optional[str] = None,
    address_lib_map: Optional[Dict[int, int]] = None,
    target_manifest=None,
    target_binary_path: Optional[str] = None,
) -> Tuple[int, int]:
    """Generate a self-contained Ghidra import script.

    Parameters
    ----------
    enums, structs, vtable_structs:
        Type data dicts produced by the clang_types + build_vtable_structs pipeline.
    output_path:
        File path for the generated .py script.
    version:
        Version key embedded in script (e.g. 'se', 'ae').
    symbols_json, fallback_symbols_json:
        JSON-encoded symbol arrays.
    template_source:
        Python source for TEMPLATE_TYPE_MAP.
    project_name:
        Human-readable project name for comment strings (default 'CommonLibSSE').
    script_header, script_footer:
        Override the default Ghidra Jython header/footer.
    address_lib_map:
        Optional dict of {rva: id} from the address library. Encoded as a
        base64 binary blob for reverse RVA→ID lookups at import time.
    target_manifest, target_binary_path:
        Exact identity of the PE(s) this script may modify. ``target_manifest``
        accepts one PE manifest, a list of manifests, or an artifact-lineage
        sidecar ``{source, artifact}``; only exact analyzed-artifact hashes are
        accepted at runtime. ``target_binary_path`` is a convenience that is
        inspected with :mod:`binary_identity` during generation.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    header = script_header if script_header is not None else GHIDRA_SCRIPT_HEADER
    footer = script_footer if script_footer is not None else GHIDRA_SCRIPT_FOOTER

    target_manifests = []
    target_lineage = []
    if target_binary_path:
        try:
            from .binary_identity import inspect_pe
        except (ImportError, ValueError):
            from binary_identity import inspect_pe
        target_manifests.append(inspect_pe(target_binary_path))
    if target_manifest:
        supplied = target_manifest if isinstance(target_manifest, list) else [target_manifest]
        for item in supplied:
            if not isinstance(item, dict):
                raise TypeError('target_manifest entries must be dictionaries')
            if isinstance(item.get('source'), dict) and isinstance(item.get('artifact'), dict):
                if not item['source'].get('sha256'):
                    raise ValueError('artifact lineage requires exact source.sha256')
                target_lineage.append(item)
                target_manifests.append(item['artifact'])
            else:
                target_manifests.append(item)
    deduped_targets = []
    seen_target_hashes = set()
    for item in target_manifests:
        sha = str(item.get('sha256') or '').lower()
        if (not sha or not item.get('file_size')
                or int(item.get('pointer_size', 0)) not in (4, 8)
                or not item.get('image_base') or not item.get('image_size')
                or not item.get('sections') or not item.get('anchors')
                or (int(item.get('pointer_size', 0)) == 8
                    and 'function_starts' not in item)):
            raise ValueError('target manifests require exact hash, ABI/image layout, sections, and anchors')
        if sha not in seen_target_hashes:
            seen_target_hashes.add(sha)
            deduped_targets.append(item)

    lines = [header]

    lines.append('VERSION = {}'.format(repr(version)))
    lines.append('PROJECT_NAME = {}'.format(repr(project_name)))
    lines.append('import json as _json_target')
    lines.append('TARGET_MANIFESTS = _json_target.loads(' +
                 repr(json.dumps(deduped_targets, separators=(',', ':'))) + ')')
    lines.append('TARGET_LINEAGE = _json_target.loads(' +
                 repr(json.dumps(target_lineage, separators=(',', ':'))) + ')')
    lines.append('')

    # Ghidra has one datatype namespace per category, while C++ permits tag
    # names that collide (and separate namespaces can be flattened by a custom
    # category mapping).  Preserve both definitions with deterministic storage
    # names; exact C++ full names remain the lookup keys in the generated script.
    _dt_groups = {}
    for en in enums.values():
        _dt_groups.setdefault((en['category'], en['name']), []).append(
            ('enum', en['full_name']))
    for st in structs.values():
        _dt_groups.setdefault((st['category'], st['name']), []).append(
            (st.get('record_kind', 'struct'), st['full_name']))
    _storage_names = {}
    for (_category, _leaf), _items in _dt_groups.items():
        if len(_items) == 1:
            _storage_names[_items[0][1]] = _leaf
        else:
            _used_group_names = set()
            for _kind, _full in sorted(_items):
                suffix = re.sub(r'[^A-Za-z0-9_]', '_', _kind)
                candidate = _leaf + '__' + suffix
                serial = 2
                while candidate in _used_group_names:
                    candidate = _leaf + '__' + suffix + '_' + str(serial)
                    serial += 1
                _used_group_names.add(candidate)
                _storage_names[_full] = candidate

    # VTABLES
    lines.append('VTABLES = [')
    for vt in sorted(vtable_structs.values(), key=lambda v: v['name']):
        lines.append('    ({}, {}, {}, {}, {}, {}, {}),'.format(
            repr(vt['name']), repr(vt['class_full_name']), repr(vt['size']),
            repr(vt['category']), repr(vt['slots']),
            repr(vt.get('vtable_kind', 'primary')),
            repr(vt.get('subobject_offset', 0))))
    lines.append(']')
    lines.append('')

    # ENUMS — convert unsigned values >= 2^63 to signed for Java long
    def _wrap_signed(values):
        out = []
        for n, v in values:
            if v >= (1 << 63):
                v -= (1 << 64)
            out.append((n, v))
        return out

    lines.append('ENUMS = [')
    for en in sorted(enums.values(), key=lambda e: e['full_name']):
        name = _storage_names.get(en['full_name'], en['name'])
        size = en['size']
        category = en['category']
        values = _wrap_signed(en['values'])
        val_str = repr(values)
        lines.append('    ({}, {}, {}, {}, {}),'.format(
            repr(name), repr(en['full_name']), repr(size), repr(category), val_str))
    lines.append(']')
    lines.append('')

    # STRUCTS
    lines.append('STRUCTS = [')
    for st in sorted(structs.values(), key=lambda s: s['full_name']):
        name = _storage_names.get(st['full_name'], st['name'])
        size = st['size']
        category = st['category']
        has_vtable = st['has_vtable']
        bases = st['bases']

        fields = sorted(st['fields'], key=lambda f: f['offset'])
        seen_names = {}
        deduped_fields = []
        for f in fields:
            n = f['name']
            if n in seen_names:
                seen_names[n] += 1
                n = '{}_{}'.format(n, seen_names[n])
            else:
                seen_names[n] = 0
            deduped_fields.append((n, f['type'], f['offset'], f['size']))

        lines.append('    ({}, {}, {}, {}, {}, {}, {}, {}),'.format(
            repr(name), repr(st['full_name']), repr(st.get('record_kind', 'struct')),
            repr(size), repr(category), repr(deduped_fields), repr(bases),
            repr(has_vtable)))
    lines.append(']')
    lines.append('')

    # Build class::method -> structured signature lookup from method data
    _method_sd_lookup = {}
    _method_short_candidates = {}
    for st in structs.values():
        class_short = st['name']
        class_full = st['full_name']
        for mname, (ret, params) in st.get('method_sigs', {}).items():
            if ret and params is not None:
                sd = [ret, params, 0]
                _method_sd_lookup[class_full + '::' + mname] = sd
                _method_short_candidates.setdefault(
                    class_short + '::' + mname, []).append(sd)
    for key, candidates in _method_short_candidates.items():
        if len(candidates) == 1 and key not in _method_sd_lookup:
            _method_sd_lookup[key] = candidates[0]

    # Inject structured signatures into symbol entries
    _syms = json.loads(symbols_json)
    _sig_count = 0
    for s in _syms:
        if s['t'] == 'func' and not s.get('sd') and not s.get('sig') and '::' in s.get('n', ''):
            sd = _method_sd_lookup.get(s['n'])
            if sd:
                s['sd'] = sd
                _sig_count += 1
    if _sig_count:
        symbols_json = json.dumps(_syms, separators=(',', ':'))

    lines.append('import json as _json_sym')
    lines.append('SYMBOLS = _json_sym.loads(' + repr(symbols_json) + ')')
    lines.append('')

    # Upgrade fallback symbols that match vtable slots
    _vtable_sig_candidates = {}
    for vt in vtable_structs.values():
        if vt.get('vtable_kind', 'primary') != 'primary':
            continue
        class_short = vt['class_full_name'].split('::')[-1]
        class_full = vt['class_full_name']
        for _off, slot_name, slot_ret, slot_params in vt['slots']:
            if not slot_name.startswith('fn_') and not slot_name.startswith('__'):
                sig = (slot_ret, slot_params)
                _vtable_sig_candidates.setdefault(class_full + '::' + slot_name, []).append(sig)
                _vtable_sig_candidates.setdefault(class_short + '::' + slot_name, []).append(sig)
    _vtable_sigs = {}
    for key, candidates in _vtable_sig_candidates.items():
        unique = {repr(candidate): candidate for candidate in candidates}
        if len(unique) == 1:
            _vtable_sigs[key] = next(iter(unique.values()))
    if fallback_symbols_json != '[]' and _vtable_sigs:
        _fb = json.loads(fallback_symbols_json)
        _upgraded = 0
        for s in _fb:
            sig_info = _vtable_sigs.get(s.get('n'))
            if sig_info:
                s['src'] = project_name
                if sig_info[0] is not None and sig_info[1] is not None and not s.get('sd'):
                    s['sd'] = [sig_info[0], sig_info[1], 0]
                s.setdefault('confidence', 'high')
                _upgraded += 1
        if _upgraded:
            print('  Upgraded {} vtable-known fallback symbols to {} source'.format(_upgraded, project_name))
            fallback_symbols_json = json.dumps(_fb, separators=(',', ':'))

    # Use json.loads so JSON's ``true``/``false``/``null`` parse safely
    # in Python (bare ``false`` would NameError; ``True``/``False`` are
    # capitalized in Python).
    lines.append('import json as _json')
    lines.append('FALLBACK_SYMBOLS = _json.loads(' + repr(fallback_symbols_json) + ')')
    lines.append('')

    # Address library RVA→ID reverse map (base64 binary blob)
    if address_lib_map:
        import base64 as _b64
        pairs = sorted(address_lib_map.items())
        blob = b''.join(struct.pack('<II', rva, rid) for rva, rid in pairs)
        b64 = _b64.b64encode(blob).decode('ascii')
        lines.append('_ADDRLIB_B64 = (')
        for i in range(0, len(b64), 120):
            lines.append("    '" + b64[i:i+120] + "'")
        lines.append(')')
    else:
        lines.append("_ADDRLIB_B64 = ''")
    lines.append('')

    # Template type map
    if template_source:
        lines.append(template_source)
    else:
        lines.append('TEMPLATE_TYPE_MAP = {}')
    lines.append('')

    lines.append(footer)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return len(enums), len(structs)
