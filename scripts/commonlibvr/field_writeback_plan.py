"""Pure (Ghidra-free) logic for the FIELD write-back to CommonLibVR.

The discovery/cross-version pipeline resolved struct-field TYPES that sit in CommonLib
as `unkNN` members. This module turns the per-runtime resolved_fields exports
(class, cl_offset, ghidra_typename) into write-back decisions:

  * demangle_type -- invert the import's `<>,:* ` -> `_` type mangling back to a C++
    spelling, and classify whether the result is SAFE to auto-rewrite. Pointers,
    primitives, and arrays-of-those are safe (a pointer needs only a forward
    declaration). Bitfields, inline class members, and ambiguous templates are NOT
    auto-rewritten -- they are reported for manual handling, because the mangling is
    lossy (a trailing `_` is `>` or `*>`) and an inline member needs a full definition.
  * reconcile -- merge the three runtimes per (class, cl_offset): a field auto-applies
    only when the runtimes that resolved it AGREE on the demangled type; a disagreement
    is flagged, never guessed (the binary is the arbiter).

Kept Ghidra-free and unit-tested; the driver does the CSV read and header edit.
"""
import re

# Ghidra primitive / undefined spelling -> C++ (CommonLib uses fixed-width std types).
PRIM = {
    'byte': 'std::uint8_t', 'sbyte': 'std::int8_t', 'uchar': 'std::uint8_t',
    'char': 'char', 'bool': 'bool', 'float': 'float', 'double': 'double',
    'ushort': 'std::uint16_t', 'short': 'std::int16_t', 'word': 'std::uint16_t',
    'uint': 'std::uint32_t', 'int': 'std::int32_t', 'dword': 'std::uint32_t',
    'ulong': 'std::uint32_t', 'long': 'std::int32_t',
    'ulonglong': 'std::uint64_t', 'longlong': 'std::int64_t', 'qword': 'std::uint64_t',
    'undefined': 'std::uint8_t', 'undefined1': 'std::uint8_t',
    'undefined2': 'std::uint16_t', 'undefined4': 'std::uint32_t',
    'undefined8': 'std::uint64_t', 'pointer': 'void*',
}

# single-arg engine smart pointers: a fixed 8-byte slot, same width as a placeholder.
SMART_PTRS = {'NiPointer', 'NiTSmartPointer', 'BSTSmartPointer', 'GPtr',
              'BSTAutoPointer', 'NiTPointer'}
# other known wrappers we can spell from the mangled form but not auto-size here.
_OTHER_WRAPS = {'BSTArray', 'NiTArray', 'BSTSmallArray', 'BSScrapArray', 'BSSimpleList',
                'BSTHashMap'}


def demangle_type(tn):
    """Ghidra type name -> (cpp_type, kind, safe). cpp_type is the C++ spelling (None
    if unhandled); kind in pointer/primitive/array/bitfield/template/class/unknown;
    safe=True only when the result is sound to auto-write into a header."""
    t = (tn or '').strip()
    if not t:
        return (None, 'unknown', False)
    t = re.sub(r'\.conflict\d*', '', t)               # drop Ghidra dedup residual suffix
    # bitfield 'byte:2' / 'uint:18' -- member is a bitfield; never auto-rewrite
    if re.match(r'^\w+:\d+$', t):
        return (None, 'bitfield', False)
    # array 'BASE[N]'
    m = re.match(r'^(.+)\[(\d+)\]$', t)
    if m:
        bt, _k, ok = demangle_type(m.group(1).strip())
        return ((bt, 'array', m.group(2)), 'array', ok) if bt else (None, 'array', False)
    # pointer 'BASE *' / 'BASE *64' (collapse Ghidra's *64 width tag)
    if re.search(r'\*\s*(64)?$', t):
        base = re.sub(r'\s*\*\s*(64)?$', '', t).strip()
        bt, bk, _ok = demangle_type(base)
        if bt is None:
            return (None, 'pointer', False)
        # a pointer to a plain class or primitive is auto-safe -- a forward declaration
        # is enough. A pointer to a mangled template is reported, not rewritten.
        return (bt + '*', 'pointer', bk in ('class', 'primitive'))
    low = t.lower()
    if low in PRIM:
        return (PRIM[low], 'primitive', True)
    # already-proper-C++ template (Ghidra also emits these, e.g.
    # `NiPointer<RE::NiAVObject>`). Strip the RE:: qualifier (CommonLib headers spell
    # types unqualified inside `namespace RE`) and classify by the wrapper:
    if '<' in t:
        wrap = t.split('<', 1)[0].split('::')[-1].strip()
        cpp = t.replace('RE::', '')
        # a single-arg engine SMART POINTER is a fixed 8-byte slot -> auto-safe.
        if wrap in SMART_PTRS:
            return (cpp, 'smartptr', True)
        # sized containers / maps: spelled but size varies -> reported (a same-or-merge
        # size decision is the driver's, not auto-safe here).
        return (cpp, 'template', False)
    # `_`-mangled template form. Map the known smart pointers to the safe path; other
    # wrappers stay reported (the `_` mangling is ambiguous: trailing `_` is `>`/`*>`).
    mtpl = re.match(r'^([A-Za-z_]\w*)_(.+?)_*$', t)
    if mtpl and mtpl.group(1) in (SMART_PTRS | _OTHER_WRAPS):
        # recursively demangle the inner so the mangled form canonicalizes to the same
        # spelling as the proper-C++ form (BSTArray_NiPointer_NiAVObject__ ==
        # BSTArray<NiPointer<NiAVObject>>), so cross-runtime spelling isn't a conflict.
        inner_cpp, _ik, _is = demangle_type(mtpl.group(2).rstrip('_'))
        inner = inner_cpp if isinstance(inner_cpp, str) else mtpl.group(2).rstrip('_')
        cpp = '%s<%s>' % (mtpl.group(1), inner)
        return (cpp, 'smartptr' if mtpl.group(1) in SMART_PTRS else 'template',
                mtpl.group(1) in SMART_PTRS)
    # a bare class name: an INLINE member needs the full definition -> report, don't
    # auto-write (a forward declaration is not enough for a non-pointer member).
    if re.match(r'^[A-Za-z_]\w*$', t):
        return (t, 'class', False)
    return (None, 'unknown', False)


def cpp_member(cpp_type, kind, name):
    """Format a C++ member declaration line body (no leading indent / trailing comment)
    for a demangled (cpp_type, kind). e.g. (('std::uint8_t','array','3'),...) ->
    'std::uint8_t name[3]'."""
    if kind == 'array':
        base, _a, n = cpp_type
        return '%s %s[%s]' % (base, name, n)
    return '%s %s' % (cpp_type, name)


def reconcile(rows_by_runtime):
    """rows_by_runtime: {runtime: [(class, cl_offset, ghidra_typename), ...]} for the
    runtimes that have a resolved_fields export. Returns
    {(class, cl_offset): {'cpp', 'kind', 'safe', 'runtimes', 'conflict', 'ghidra'}}
    merged across runtimes. A field is `conflict` (and never auto-written) when the
    runtimes that resolved it demangle to DIFFERENT C++ types."""
    agg = {}
    for rt, rows in rows_by_runtime.items():
        for cls, off, tn in rows:
            cpp, kind, safe = demangle_type(tn)
            key = (cls, off)
            rec = agg.setdefault(key, {'spellings': {}, 'runtimes': set(),
                                       'ghidra': tn, 'kind': kind, 'safe': safe})
            rec['runtimes'].add(rt)
            rec['spellings'].setdefault(_norm(cpp, kind), (cpp, kind, safe))
    out = {}
    for key, rec in agg.items():
        conflict = len(rec['spellings']) > 1
        # pick the (only) spelling when consistent; on conflict keep one but mark it
        cpp, kind, safe = list(rec['spellings'].values())[0]
        out[key] = {'cpp': cpp, 'kind': kind, 'safe': safe and not conflict,
                    'runtimes': sorted(rec['runtimes']), 'conflict': conflict,
                    'ghidra': rec['ghidra']}
    return out


_ONE_BYTE = {'std::uint8_t', 'std::int8_t', 'char', 'std::byte'}


def _norm(cpp, kind):
    """A hashable identity for a demangled type, to detect a REAL cross-runtime
    disagreement (not a spelling one). Byte-wide bases (byte/char/uint8) are treated as
    equivalent -- `byte[96]` vs `char[96]` is the same layout, not a conflict."""
    if cpp is None:
        return ('none', kind)
    if kind == 'array':
        base = 'i8' if cpp[0] in _ONE_BYTE else cpp[0]
        return ('array', base, cpp[2])
    return ('t', cpp)
