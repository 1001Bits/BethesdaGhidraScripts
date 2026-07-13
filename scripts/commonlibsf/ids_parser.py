"""Parser for CommonLibSF's IDs.h family.

CommonLibSF maintains four manifest files that map symbol names to address-
library IDs.  Single-version (Starfield is single-platform on PC), so each
entry is just ``<name> = REL::ID(<id>)`` -- no SE/AE-style preprocessor
arithmetic.

  RE/IDs.h         function IDs, grouped by ``namespace RE::ID::<Class> {}``
  RE/IDs_RTTI.h    flat ``RTTI_*`` IDs under ``namespace RE::RTTI``
  RE/IDs_VTABLE.h  ``VTABLE_*`` as ``std::array<REL::ID, N>``
  RE/IDs_NiRTTI.h  flat ``NiRTTI_*`` IDs under ``namespace RE::NiRTTI``

The output of every parse function is a flat list of dicts shaped like
``{'name': str, 'class_': Optional[str], 'sf_off': int}`` so they slot into
the existing ghidra_import_gen pipeline (which keys per-symbol offsets by
version-specific dict fields -- 'sf_off' for Starfield).
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple


# inline constexpr REL::ID Name{ 123 };     (single brace-init)
# Trailing `;` is optional in some CommonLibSF revisions.
_INLINE_ID_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+([A-Za-z_]\w*)\s*\{\s*(\d+)\s*\}'
)

# inline constexpr std::array<REL::ID, N>  NAME{ REL::ID(x), REL::ID(y), ... };
_VTABLE_ARR_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::ID,\s*(\d+)>\s+([A-Za-z_]\w*)\s*\{([^}]+)\}'
)
_REL_ID_NUM_RE = re.compile(r'REL::ID\s*\(\s*(\d+)\s*\)')

_QUALIFIED_NS = r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*'
_NS_OPEN_RE       = re.compile(r'\bnamespace\s+(' + _QUALIFIED_NS + r')\s*\{')
_NS_DECL_ONLY_RE  = re.compile(r'^\s*namespace\s+(' + _QUALIFIED_NS + r')\s*$')


class _ScopeTracker:
    """Brace-aware namespace tracker.

    Handles both ``namespace RE { ... }`` (same-line brace) and ::

        namespace RE
        {
            ...
        }
    """

    def __init__(self):
        self._stack: List[Tuple[str, int]] = []  # (name, brace_depth_at_open)
        self._depth = 0
        self._pending: Optional[str] = None

    @property
    def path(self) -> List[str]:
        return [n for n, _ in self._stack]

    def feed(self, line: str) -> None:
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('#'):
            return

        opens = line.count('{')
        closes = line.count('}')

        # Same-line ``namespace X {`` (incl. ``namespace X::Y { ... ``)
        for m in _NS_OPEN_RE.finditer(line):
            # ``namespace RE::ID::Actor`` opens one lexical scope but names
            # three namespace components.  Keep the components separately so
            # callers never lose the RE::ID prefix or collapse nested class
            # namespaces to an unqualified leaf name.
            for component in m.group(1).split('::'):
                self._stack.append((component, self._depth))

        # Bare ``namespace X`` waiting for ``{`` on next line
        if opens == 0 and closes == 0:
            mm = _NS_DECL_ONLY_RE.match(line)
            if mm:
                self._pending = mm.group(1)

        if self._pending and opens > 0:
            for component in self._pending.split('::'):
                self._stack.append((component, self._depth))
            self._pending = None

        self._depth += opens - closes

        # Pop scopes that have closed
        while self._stack and self._stack[-1][1] >= self._depth:
            self._stack.pop()


def _read_text(path: str) -> str:
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return ''


# ---------------------------------------------------------------------------
# IDs.h: function IDs grouped per class via namespacing
# ---------------------------------------------------------------------------

def parse_ids_h(re_include: str, addr_lib) -> List[dict]:
    """Parse ``RE/IDs.h`` into function symbols.

    Structure::

        namespace RE::ID
        {
            namespace Actor
            {
                inline constexpr REL::ID EvaluatePackage{ 150640 };
                ...
            }
        }

    Each leaf entry becomes ``{name: EvaluatePackage, class_: Actor,
    sf_off: <rva>}``.  Entries whose ID is missing from the address library
    are dropped (no offset means we can't place a symbol).
    """
    path = os.path.join(re_include, 'IDs.h')
    text = _read_text(path)
    if not text:
        return []

    out: List[dict] = []
    scope = _ScopeTracker()
    for line in text.split('\n'):
        scope.feed(line)
        m = _INLINE_ID_RE.search(line)
        if not m:
            continue
        name = m.group(1)
        try:
            sid = int(m.group(2))
        except ValueError:
            continue

        # Resolve the symbol's class from scope.  Path is normally
        # ['RE', 'ID', 'ClassName'] (or RE::ID compounded).  Strip the
        # 'RE' / 'ID' prefix and use whatever's left as class_.
        ns = scope.path
        idx = 0
        if idx < len(ns) and ns[idx] == 'RE':
            idx += 1
        if idx < len(ns) and ns[idx] == 'ID':
            idx += 1
        cls_parts = ns[idx:]
        cls = '::'.join(cls_parts) if cls_parts else None

        off = addr_lib.sf_db.get(sid)
        if not off:
            continue
        out.append({
            'name': name,
            'class_': cls,
            'ret': '', 'params': '',
            'is_static': False,
            'sf_off': off,
        })
    return out


# ---------------------------------------------------------------------------
# IDs_RTTI.h, IDs_NiRTTI.h: flat label tables
# ---------------------------------------------------------------------------

def parse_rtti_h(re_include: str, addr_lib, filename: str,
                 name_prefix: str) -> List[dict]:
    """Parse a flat ``inline constexpr REL::ID Name{ id }`` manifest.

    ``filename``      file under ``re_include`` to read (e.g. 'IDs_RTTI.h')
    ``name_prefix``   prefix to attach to each entry (e.g. 'RTTI_')

    Some CommonLibSF revisions already include the prefix in the symbol
    name itself (e.g. ``RTTI_Actor``); the heuristic below only attaches
    ``name_prefix`` when the raw name doesn't already start with it.
    """
    path = os.path.join(re_include, filename)
    text = _read_text(path)
    if not text:
        return []

    out: List[dict] = []
    for m in _INLINE_ID_RE.finditer(text):
        raw_name = m.group(1)
        try:
            sid = int(m.group(2))
        except ValueError:
            continue
        off = addr_lib.sf_db.get(sid)
        if not off:
            continue
        lname = raw_name if raw_name.startswith(name_prefix) else f'{name_prefix}{raw_name}'
        out.append({'name': lname, 'sf_off': off})
    return out


# ---------------------------------------------------------------------------
# IDs_VTABLE.h: std::array<REL::ID, N>
# ---------------------------------------------------------------------------

def parse_vtable_h(re_include: str, addr_lib,
                   vtable_path: Optional[str] = None) -> List[dict]:
    """Parse ``RE/IDs_VTABLE.h`` for VTABLE_* labels.

    Each ``std::array<REL::ID, N>`` produces N labels: ``VTABLE_Name`` for
    the primary slot and ``VTABLE_Name_<i>`` for secondary slots
    (i >= 2, 1-based after the primary).  Entries whose IDs aren't in the
    address library are dropped.
    """
    path = vtable_path or os.path.join(re_include, 'IDs_VTABLE.h')
    text = _read_text(path)
    if not text:
        return []

    out: List[dict] = []
    for m in _VTABLE_ARR_RE.finditer(text):
        raw_name = m.group(2)
        ids = [int(x) for x in _REL_ID_NUM_RE.findall(m.group(3))]
        lname_base = raw_name if raw_name.startswith('VTABLE_') else f'VTABLE_{raw_name}'
        for idx, sid in enumerate(ids):
            off = addr_lib.sf_db.get(sid)
            if not off:
                continue
            lname = lname_base if idx == 0 else f'{lname_base}_{idx + 1}'
            out.append({
                'name': lname,
                'sf_off': off,
                # Array order is not a primary/secondary-vtable contract.
                # Consumers with PE bytes must use the MSVC COL offset to
                # decide which element receives the unsuffixed primary name.
                'vtable_class': (lname_base[len('VTABLE_'):]
                                 if lname_base.startswith('VTABLE_')
                                 else lname_base),
                'vtable_array_index': idx,
                'vtable_id': sid,
            })
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_all(re_include: str, addr_lib, verbose: bool = False
                ) -> Tuple[List[dict], List[dict]]:
    """Run every manifest scanner.

    Returns ``(func_syms, label_syms)`` where label_syms covers RTTI,
    NiRTTI, and VTABLE entries.  Both lists are deduplicated on
    ``(name, sf_off)``.
    """
    funcs = parse_ids_h(re_include, addr_lib)

    labels: List[dict] = []
    labels.extend(parse_rtti_h(re_include, addr_lib, 'IDs_RTTI.h',   'RTTI_'))
    labels.extend(parse_rtti_h(re_include, addr_lib, 'IDs_NiRTTI.h', 'NiRTTI_'))
    labels.extend(parse_vtable_h(re_include, addr_lib))

    seen_f = set()
    deduped_f = []
    for f in funcs:
        key = (f['name'], f.get('class_'), f['sf_off'])
        if key in seen_f:
            continue
        seen_f.add(key)
        deduped_f.append(f)

    seen_l = set()
    deduped_l = []
    for l in labels:
        key = (l['name'], l['sf_off'])
        if key in seen_l:
            continue
        seen_l.add(key)
        deduped_l.append(l)

    if verbose:
        print(f'  IDs.h: {len(deduped_f)} function symbols')
        print(f'  IDs_RTTI.h + IDs_NiRTTI.h + IDs_VTABLE.h: {len(deduped_l)} labels')

    return deduped_f, deduped_l
