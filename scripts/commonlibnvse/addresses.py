"""xNVSE address scanner for Fallout New Vegas (32-bit).

FNV doesn't have a meh321 versionlib + ``REL::ID`` pipeline like Skyrim /
F4 / Starfield, so we extract symbols directly from xNVSE C++ headers
which embed hardcoded virtual addresses for FNV 1.4.0.525.  FNV has been
frozen at that build since 2011, so hardcoded addresses are stable.

Recognized patterns
-------------------

1. **Typed constant addresses** (top-level or static):

       static const UInt32 s_Console__Print = 0x0071D0A0;
       const UInt32 _SaveGameManager_ConstructSavegameFilename = 0x0084FF90;

   Becomes a top-level label (or function if the name pattern suggests
   ``_ClassName_Method`` / ``ClassName__Method``).

2. **DEFINE_MEMBER_FN macros** inside a class block:

       class Foo {
           DEFINE_MEMBER_FN(MethodName, retType, 0x12345678, args);
       };

   Becomes ``Foo::MethodName`` at 0x12345678.  Tracks brace depth and
   the enclosing ``class``/``struct`` identifier.

3. **Casted-to-fn-pointer constants**:

       static TESForm * (*LookupFormByID)(UInt32) = (TESForm* (*)(UInt32))0x00483A00;

   Becomes a function symbol at 0x00483A00.

Returns
-------

A flat list of dicts shaped like
``{'name': str, 'class_': Optional[str], 'rva': int, 'kind': 'func' | 'label'}``
keyed by RVA (i.e., VA minus the 0x00400000 image base).  Duplicate
``(name, rva)`` rows are deduplicated.

The optional ``refs/fnv_names.csv`` overlay supplements xNVSE with any
hand-curated names that aren't present in xNVSE headers.
"""

from __future__ import annotations

import csv
import os
import re
from typing import Dict, List, Optional, Tuple

from addressing import AddressError, normalize_address

# FNV's PE image base.  No ASLR on x86, addresses in xNVSE headers are
# straight VAs that bake this in.
FNV_IMAGE_BASE = 0x00400000


# --------------------------------------------------------------------------
# Regex catalogue
# --------------------------------------------------------------------------

# Tier 1: typed-constant addresses
#   static const UInt32 s_Foo = 0x12345678;
#   const UInt32 _Bar = 0x12345678;
#   inline const UInt32 baz = 0x12345678;
#   static const Cmd_Execute Cmd_Foo_Execute = (Cmd_Execute)0x12345678;
#   static const void * kRetn_Foo = (void *)0x12345678;
#   const Cmd_Parse g_defaultParseCommand = (Cmd_Parse)0x12345678;
#
# We allow any type-identifier (or `void *`) to cover xNVSE's mix of raw
# UInt32 addresses, typedef'd function pointers, and casted data pointers.
# The leading qualifier set keeps us anchored to "structured constant"
# shapes -- function-body assignments don't have static/const prefixes
# and aren't picked up.  The optional cast on the RHS is the typical
# function-pointer/void* idiom in xNVSE.
_CONST_ADDR_RE = re.compile(
    r'^\s*(?:static\s+|inline\s+|extern\s+)*(?:const\s+)+'
    r'(?:[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*|void)\s*\**\s+'
    r'(\**[A-Za-z_]\w*)\s*=\s*'
    r'(?:\(\s*[^)]+?\s*\)\s*)?'        # optional cast like (Cmd_Execute) or (void *)
    r'0x([0-9A-Fa-f]{6,8})\s*;',
    re.MULTILINE,
)

# Tier 2: DEFINE_MEMBER_FN(Name, RetType, 0x..., args...)
#   DEFINE_MEMBER_FN(MarkAsTemporary, void, 0x00484490);
#   DEFINE_MEMBER_FN_LONG(SomeClass, Foo, void, 0x00484490, args);
_MEMBER_FN_RE = re.compile(
    r'\bDEFINE_MEMBER_FN(?:_LONG)?\s*\(\s*'
    r'(?:([A-Za-z_]\w*)\s*,\s*)?'   # optional className (only for _LONG)
    r'([A-Za-z_]\w*)\s*,\s*'        # functionName
    r'[^,]+\s*,\s*'                 # retnType (skip)
    r'0x([0-9A-Fa-f]{6,8})'         # address
)

# Tier 3: casted function-pointer constants
#   static TESForm * (*Foo)(UInt32) = (TESForm* (*)(UInt32))0x00483A00;
# We don't need to match the entire prototype -- enough to spot the
# `( <name> )(...)` pattern with a casted hex address on the RHS.
_FN_PTR_CAST_RE = re.compile(
    r'\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\([^)]*\)\s*=\s*'
    r'\([^)]+\)\s*0x([0-9A-Fa-f]{6,8})'
)

# Class/struct scope tracker
_CLASS_OPEN_RE = re.compile(r'\b(?:class|struct)\s+([A-Za-z_]\w*)\b[^;{]*\{')

# Single-line comment + block-comment patterns for sanitizing
_LINE_COMMENT_RE  = re.compile(r'//.*$')
_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _strip_comments(text: str) -> str:
    """Drop block + line comments before scanning.

    Many xNVSE headers embed hex addresses inside comments as breadcrumbs
    (``// see 0x008A083C``).  Those are not symbols -- they're notes for
    humans about the surrounding code.  Removing comments avoids picking
    them up.
    """
    text = _BLOCK_COMMENT_RE.sub('', text)
    return '\n'.join(_LINE_COMMENT_RE.sub('', ln) for ln in text.split('\n'))


def _va_to_rva(va: int) -> Optional[int]:
    """Convert an xNVSE VA to an RVA into FalloutNV.exe.

    Returns None for VAs outside FalloutNV's .text/.rdata range -- xNVSE
    occasionally references kernel32/user32 imports or hardcoded data
    outside the main module.  The image is roughly 0x400000-0x12FFFFF.
    """
    if va < FNV_IMAGE_BASE or va > 0x01400000:
        return None
    return va - FNV_IMAGE_BASE


_DATA_NAME_PREFIXES = (
    'kVtbl_', 'kArr_', 'g_', 'kRetn_', 'kHook_',
    'kJmpAddr', 'kCallAddr', 'kRetnAddr', 'kHookAddr',
)
_DATA_NAME_SUFFIXES = (
    'Ptr', 'Vtbl', 'Vtable', 'HookAddr', 'RetnAddr', 'CallAddr',
    'JmpAddr', 'BaseAddr',
)


def _is_function_like_name(name: str) -> bool:
    """Heuristic: does the symbol name look like a function vs data?

    xNVSE convention:
      - ``kVtbl_Xxx``  vtable pointer (DATA, into .rdata)
      - ``kFoo_HookAddr`` / ``kFoo_RetnAddr``  hook breadcrumbs (DATA)
      - ``g_xxx``      globals (DATA)
      - ``s_xxx`` / ``_xxx`` / ``Cmd_xxx_Execute`` / ``Xxx_Method``  funcs
      - bare CamelCase  funcs (the default)

    Raw integer constants do not carry enough type evidence to create a
    function.  Unknowns therefore remain labels; DEFINE_MEMBER_FN and real
    function-pointer declarations are handled by their dedicated parsers.
    """
    if name.startswith(_DATA_NAME_PREFIXES):
        return False
    # 'kFoo' standalone (capital after k) usually means a constant.
    # 'kAddr_*' / 'kVtbl_*' caught above; 'kScript_*' is also data-ish.
    if name.startswith('k') and len(name) > 1 and name[1].isupper():
        return False
    if any(name.endswith(suf) for suf in _DATA_NAME_SUFFIXES):
        return False
    return False


# --------------------------------------------------------------------------
# Header scanning
# --------------------------------------------------------------------------

def _scan_header(path: str) -> List[dict]:
    """Scan a single .h file for symbol/address pairs."""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return []

    text = _strip_comments(text)
    out: List[dict] = []

    # Tier 2: scan with line-by-line class tracker so DEFINE_MEMBER_FN
    # gets the enclosing class name when present.
    depth = 0
    scope_stack: List[Tuple[str, int]] = []  # (className, brace_depth_at_open)
    for line in text.split('\n'):
        for m in _CLASS_OPEN_RE.finditer(line):
            scope_stack.append((m.group(1), depth))
        opens = line.count('{')
        closes = line.count('}')
        depth += opens - closes
        while scope_stack and scope_stack[-1][1] >= depth:
            scope_stack.pop()

        for m in _MEMBER_FN_RE.finditer(line):
            cls_explicit, fn_name, addr_hex = m.groups()
            cls = cls_explicit or (scope_stack[-1][0] if scope_stack else None)
            # Skip the macro-template line itself (`_MEMBER_FN_BASE_TYPE`
            # is the placeholder used in DEFINE_MEMBER_FN's recursive
            # expansion).
            if cls == '_MEMBER_FN_BASE_TYPE':
                cls = None
            rva = _va_to_rva(int(addr_hex, 16))
            if rva is None:
                continue
            out.append({
                'name':   fn_name,
                'class_': cls,
                'rva':    rva,
                'kind':   'func',
                'src':    'xNVSE/DEFINE_MEMBER_FN',
                # This macro is a typed call through the exact member-procedure
                # entry address, rather than a hook/return-site breadcrumb.
                'verified_entry': True,
            })

    # Tier 1: typed-constant addresses (whole-text, not line-by-line).
    # Most of these are top-level so class scope doesn't apply.
    for m in _CONST_ADDR_RE.finditer(text):
        raw_name, addr_hex = m.groups()
        # Strip leading `*` (pointer-typed declarations -- rare but seen)
        name = raw_name.lstrip('*')
        if name.startswith(('kFlag', 'kFlags_', 'kEffFlag', 'kFormFlag',
                            'kNiFlag')):
            continue
        # Skip names that look like enum members (kEvent_OnX = 0x4) -- the
        # CONST_ADDR_RE already excludes those by requiring const-UInt32
        # qualifier, but be paranoid.
        rva = _va_to_rva(int(addr_hex, 16))
        if rva is None:
            continue
        # Strip a single leading '_' or 's_' prefix conventionally used in
        # xNVSE for "this is the address of <Name>".  Keeps the symbol
        # readable as ``Console::Print`` instead of ``s_Console__Print``.
        sym_name = name
        if sym_name.startswith('s_'):
            sym_name = sym_name[2:]
        if sym_name.startswith('_'):
            sym_name = sym_name[1:]
        # xNVSE uses double-underscore as a class/method separator:
        # ``Console__Print`` -> ``Console::Print``.
        cls = None
        if '__' in sym_name:
            cls, _, sym_name = sym_name.partition('__')
        kind = 'func' if _is_function_like_name(sym_name) else 'label'
        out.append({
            'name':   sym_name,
            'class_': cls,
            'rva':    rva,
            'kind':   kind,
            'src':    'xNVSE/const',
        })

    # Tier 3: casted function-pointer constants
    for m in _FN_PTR_CAST_RE.finditer(text):
        fn_name, addr_hex = m.groups()
        rva = _va_to_rva(int(addr_hex, 16))
        if rva is None:
            continue
        out.append({
            'name':   fn_name,
            'class_': None,
            'rva':    rva,
            'kind':   'func',
            'src':    'xNVSE/fnptrcast',
            # A typed function-pointer initializer denotes a procedure entry.
            'verified_entry': True,
        })

    return out


def scan_xnvse(xnvse_root: str, verbose: bool = False) -> List[dict]:
    """Walk xNVSE's header tree, scan every .h, return flat symbol list.

    Looks under ``nvse/`` and ``common/`` subdirs of the submodule.  Skips
    the example plugin and any test fixtures.
    """
    if not os.path.isdir(xnvse_root):
        if verbose:
            print('  xNVSE root not found: {}'.format(xnvse_root))
        return []

    targets = []
    for sub in ('nvse', 'common'):
        d = os.path.join(xnvse_root, sub)
        if os.path.isdir(d):
            for dirpath, _, fnames in os.walk(d):
                # Skip nested example/test plugins.
                if 'plugin_example' in dirpath or 'Algohol' in dirpath:
                    continue
                for fn in fnames:
                    if fn.endswith('.h') or fn.endswith('.cpp'):
                        targets.append(os.path.join(dirpath, fn))

    if verbose:
        print('  scanning {} xNVSE header files ...'.format(len(targets)))

    out: List[dict] = []
    for path in targets:
        out.extend(_scan_header(path))
    return out


# --------------------------------------------------------------------------
# CSV overlay (optional)
# --------------------------------------------------------------------------

def load_overlay_csv(path: str) -> List[dict]:
    """Load supplemental name,rva,kind,class rows from a CSV.

    Format documented in ``refs/fnv_names.csv.example``.  Returns an
    empty list if the file is missing or unreadable.
    """
    if not os.path.isfile(path):
        return []

    out: List[dict] = []
    try:
        with open(path, encoding='utf-8', errors='replace', newline='') as f:
            reader = csv.DictReader(
                (row for row in f if row.strip() and not row.lstrip().startswith('#'))
            )
            for row in reader:
                name = (row.get('name') or '').strip()
                raw_rva = (row.get('rva') or '').strip()
                kind = (row.get('kind') or 'func').strip().lower() or 'func'
                cls = (row.get('class') or '').strip() or None
                if not name or not raw_rva:
                    continue
                try:
                    rva = int(raw_rva, 16) if raw_rva.lower().startswith('0x') \
                        else int(raw_rva)
                except ValueError:
                    continue
                coordinate = (row.get('coordinate') or 'RVA').strip().upper()
                try:
                    rva = normalize_address(rva, coordinate)
                except AddressError:
                    continue
                out.append({
                    'name':   name,
                    'class_': cls,
                    'rva':    rva,
                    'kind':   'func' if kind == 'func' else 'label',
                    'src':    'csv/fnv_names',
                    # Manual rows must opt in explicitly.  A ``kind=func``
                    # assertion alone is not enough evidence to create code.
                    'verified_entry': (
                        kind == 'func' and
                        (row.get('verified_entry') or '').strip().lower()
                        in ('1', 'true', 'yes')
                    ),
                })
    except OSError:
        return []
    return out


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def collect_all(xnvse_root: str, refs_dir: str, verbose: bool = False
                ) -> Tuple[List[dict], List[dict]]:
    """Scan xNVSE + apply CSV overlay; split into funcs vs labels.

    Returns ``(func_syms, label_syms)`` shaped the same way as the
    CommonLibSSE/F4/SF parsers.  Later overlay rows override earlier
    xNVSE rows for the same ``(name, rva)``.
    """
    rows = scan_xnvse(xnvse_root, verbose=verbose)

    overlay_path = os.path.join(refs_dir, 'fnv_names.csv')
    overlay = load_overlay_csv(overlay_path)
    if verbose and overlay:
        print('  CSV overlay rows: {}'.format(len(overlay)))
    rows.extend(overlay)

    # Dedup on (name, class_, rva)
    seen = set()
    deduped = []
    for r in rows:
        key = (r['name'], r.get('class_'), r['rva'])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    funcs = [r for r in deduped if r['kind'] == 'func']
    labels = [r for r in deduped if r['kind'] == 'label']

    if verbose:
        print('  xNVSE+overlay symbols: {} ({} funcs, {} labels)'.format(
            len(deduped), len(funcs), len(labels)))

    return funcs, labels
