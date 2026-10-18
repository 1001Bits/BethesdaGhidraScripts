"""Regex-based relocation/symbol scanner for libxse/commonlibf4.

ID format (IDs.h) -- single AE ID per entry:
  namespace RE::ID {
    namespace Actor {
      inline constexpr REL::ID AddPerk{ 2230121 };
    }
  }

Header usage:
  static REL::Relocation<func_t> func{ ID::Actor::AddPerk };

RTTI/NiRTTI (IDs_RTTI.h / IDs_NiRTTI.h):
  inline constexpr REL::ID Actor{ 4839606 };

VTABLE (IDs_VTABLE.h):
  inline constexpr std::array<REL::ID, 17> Actor{ REL::ID(1455516), ... };

CommonLibF4VR (alandtse/ArthurHub fork) layout -- no IDs.h at all:
  RTTI_IDs.h / NiRTTI_IDs.h:
    inline constexpr REL::RelocationID Actor{ 1234567, 2773423 };   (og, ng)
    inline constexpr REL::ID           Lambda{ 2782995 };
  VTABLE_IDs.h:
    std::array<REL::ID, 1>           Name{ REL::ID(65996) };
    std::array<REL::RelocationID, 2> Name{ REL::RelocationID(902583, 2730081), ... };
  headers / src, inline:
    static REL::Relocation<func_t> func{ REL::ID(1415178) };
    static REL::Relocation<func_t> func{ REL::RelocationID(1468462, 2232275) };

ID namespaces (see address_library.py): legacy IDs < 1,600,000 are ONE
namespace across OG 1.10.163 / NG / AE / VR 1.2.72; IDs >= 2,000,000 exist only
in NG and later.  ``RelocationID(og, ng)`` therefore carries a legacy ID
(``og_id``: og_db + vr_db) and an NG-range ID (``ng_id``: ng/ae/221/240).

Public API:
  collect_relocations(re_include, addr_lib, verbose) ->
      (func_syms, label_syms, static_methods)
  Each sym has 'ae_off' (AE offset, or None if unresolved) and 'id'; syms from
  a RelocationID pair also have 'og_id' / 'ng_id'.
"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IDs.h: inline constexpr REL::ID Name{ id1[, id2[, id3]] };
_ID_DECL_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+(\w+)\s*\{([^}]+)\}'
)

# IDs_VTABLE.h: std::array<REL::ID, N> Name{ REL::ID(id), ... }
_VTABLE_ARRAY_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::ID,\s*(\d+)>\s+(\w+)\s*\{([^}]+)\}'
)
_REL_ID_CALL_RE = re.compile(r'REL::ID\s*\(\s*(\d+)\s*\)')

# CommonLibF4VR: REL::RelocationID Name{ og, ng } and array elements that are
# either REL::ID(n) or REL::RelocationID(og, ng).
_RELOCATION_ID_DECL_RE = re.compile(
    r'inline\s+constexpr\s+REL::RelocationID\s+(\w+)\s*\{\s*(\d+)\s*,\s*(\d+)\s*\}'
)
_VTABLE_ANY_ARRAY_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::(?:Relocation)?ID,\s*(\d+)>\s+(\w+)\s*\{([^}]+)\}'
)
_ANY_ID_CALL_RE = re.compile(
    r'REL::(?:RelocationID\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)|ID\s*\(\s*(\d+)\s*\))')
# Inline relocation: REL::Relocation<T> var{ REL::ID(n) [, offset] } /
#                    REL::Relocation<T> var{ REL::RelocationID(og, ng) [, offset] }
# ``T`` may itself contain ``<...>``; the variable name is the last word
# before the brace.  A trailing ``, +-0x..`` member offset means the symbol is
# NOT at the ID's address, so those are skipped.
_INLINE_RELOC_RE = re.compile(
    r'REL::Relocation<(.+)>\s+(\w+)\s*\{\s*'
    r'REL::(?:RelocationID\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)|ID\s*\(\s*(\d+)\s*\))'
    r'\s*\}'
)

# Header: REL::Relocation<func_t> func{ ID::Class::Method }
_RELOC_REF_RE = re.compile(
    r'REL::Relocation<[^>]+>\s+\w+\s*\{\s*ID::([\w:]+)\s*\}'
)

# Namespace detection
_NS_OPEN_RE   = re.compile(r'\bnamespace\s+([\w:]+)\s*\{')
_NS_DECL_RE   = re.compile(r'^\s*namespace\s+([\w:]+)\s*$')
# ``class __declspec(novtable) alignas(0x10) Name`` (CommonLibF4VR) must not
# name the class ``__declspec`` / ``alignas``: without the class scope every
# relocation in it is anonymous (28 CLF4VR classes carry ``alignas``).
_DECLSPEC     = r'(?:(?:__declspec|alignas)\s*\([^)]*\)\s*)*'
_CLASS_RE     = re.compile(r'\b(?:class|struct)\s+' + _DECLSPEC + r'(\w+)\s*(?:final\s*)?(?::\s*[^{]*?)?\{')
_CLASS_DECL_RE = re.compile(r'^\s*(?:class|struct)\s+' + _DECLSPEC + r'(\w+)\s*(?:final\s*)?(?::\s*[^{;]*)?\s*$')
_METHOD_DEF_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?\s*\{'
)
_METHOD_DECL_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?\s*$'
)
_STATIC_METHOD_RE = re.compile(
    r'static\s+(?!constexpr\s+auto\s+RTTI|constexpr\s+auto\s+VTABLE)'
    r'.*?\b(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?;'
)


# ---------------------------------------------------------------------------
# IDs.h parser
# ---------------------------------------------------------------------------

_NS_DECL_BARE_RE = re.compile(r'^\s*namespace\s+([\w:]+)\s*$')  # no brace on same line


def _parse_ids_file(file_path: str) -> Dict[str, int]:
    """Parse IDs.h → {'ClassName::MethodName': ae_id}

    Single AE ID per entry (libxse fork). 0 means missing.
    Handles K&R-style opening braces on the line following the namespace keyword.
    """
    id_map: Dict[str, int] = {}

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return {}

    # scope_stack: list of (name, brace_depth_when_opened)
    scope_stack: List[Tuple[str, int]] = []
    in_re_id   = False
    re_id_depth = -1
    brace_depth = 0
    # pending: namespace declared on a line without '{', waiting for next '{'
    _pending_re_id  = False  # waiting to open RE::ID namespace
    _pending_sub_ns: Optional[str] = None  # waiting to open a sub-namespace

    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue

        opens  = line.count('{')
        closes = line.count('}')

        # Resolve pending namespaces when '{' arrives
        if opens > 0:
            if _pending_re_id:
                in_re_id    = True
                re_id_depth = brace_depth
                _pending_re_id = False
            elif _pending_sub_ns is not None and in_re_id:
                scope_stack.append((_pending_sub_ns, brace_depth))
                _pending_sub_ns = None

        # Detect namespace keywords (brace may or may not be on same line).
        # Entry-point is only the qualified form `<X>::ID` (e.g. RE::ID).
        # An unqualified `namespace ID` may legitimately appear nested inside a
        # sub-namespace and must NOT be treated as a re-entry.
        for ns_m in _NS_OPEN_RE.finditer(line):
            ns_name = ns_m.group(1)
            if ns_name.endswith('::ID') and not in_re_id:
                in_re_id    = True
                re_id_depth = brace_depth
            elif in_re_id:
                scope_stack.append((ns_name, brace_depth))

        # Next-line brace: namespace RE::ID\n{
        if opens == 0:
            m = _NS_DECL_BARE_RE.match(line)
            if m:
                ns_name = m.group(1)
                if ns_name.endswith('::ID') and not in_re_id:
                    _pending_re_id = True
                elif in_re_id:
                    _pending_sub_ns = ns_name

        # Parse ID declarations
        if in_re_id:
            id_m = _ID_DECL_RE.search(line)
            if id_m:
                name    = id_m.group(1)
                raw_ids = id_m.group(2)
                ids: List[int] = []
                for tok in raw_ids.split(','):
                    tok = tok.strip()
                    try:
                        ids.append(int(tok))
                    except ValueError:
                        pass
                if ids and ids[0]:
                    if scope_stack:
                        key = '::'.join(s[0] for s in scope_stack) + '::' + name
                    else:
                        key = name
                    id_map[key] = ids[0]

        brace_depth += opens - closes

        # Pop scopes whose depth has been closed
        while scope_stack and scope_stack[-1][1] >= brace_depth:
            scope_stack.pop()

        if in_re_id and brace_depth <= re_id_depth:
            in_re_id = False
            scope_stack = []

    return id_map


# ---------------------------------------------------------------------------
# Brace-tracking context (same structure as SSE reloc_parser)
# ---------------------------------------------------------------------------

class _ContextTracker:
    def __init__(self):
        self.scope_stack: List[Tuple[str, str, int]] = []  # (kind, name, depth)
        self.brace_depth = 0
        self._pending: Optional[Tuple[str, str]] = None
        self._pending_method: Optional[str] = None
        self.method_name: Optional[str] = None
        self._method_depth: Optional[int] = None

    def feed_line(self, line: str):
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('#'):
            return
        opens  = line.count('{')
        closes = line.count('}')
        for m in _NS_OPEN_RE.finditer(line):
            self.scope_stack.append(('ns', m.group(1), self.brace_depth))
        for m in _CLASS_RE.finditer(line):
            self.scope_stack.append(('class', m.group(1), self.brace_depth))
        code_line = re.sub(r'\s*//.*$', '', line)
        if opens == 0 and closes == 0:
            m = _NS_DECL_RE.match(code_line)
            if m:
                self._pending = ('ns', m.group(1))
            else:
                m = _CLASS_DECL_RE.match(code_line)
                if m:
                    self._pending = ('class', m.group(1))
                elif self.class_name and '(' in code_line:
                    # (the '(' test only skips lines the regex cannot match;
                    # its lazy prefix is expensive on long member lines)
                    m = _METHOD_DECL_RE.search(code_line)
                    if m and m.group(1) not in ('return','if','else','for','while','switch','do'):
                        self._pending_method = m.group(1)
        if self._pending and opens > 0:
            self.scope_stack.append((self._pending[0], self._pending[1], self.brace_depth))
            self._pending = None
        if self.class_name and opens > 0:
            m = _METHOD_DEF_RE.search(line) if '(' in line else None
            if m:
                self.method_name = m.group(1)
                self._method_depth = self.brace_depth
                self._pending_method = None
            elif self._pending_method:
                self.method_name = self._pending_method
                self._method_depth = self.brace_depth
                self._pending_method = None
        self.brace_depth += opens - closes
        while self.scope_stack and self.scope_stack[-1][2] >= self.brace_depth:
            self.scope_stack.pop()
        if self._method_depth is not None and self.brace_depth <= self._method_depth:
            self.method_name = None
            self._method_depth = None

    @property
    def class_name(self) -> Optional[str]:
        for kind, name, _ in reversed(self.scope_stack):
            if kind == 'class':
                return name
        return None

    @property
    def full_class(self) -> Optional[str]:
        classes = [name for kind, name, _ in self.scope_stack if kind == 'class']
        if not classes:
            return None
        ns = [name for kind, name, _ in self.scope_stack if kind == 'ns']
        return '::'.join(ns + classes)

    @property
    def namespace_scope_depth(self) -> Optional[int]:
        """Brace depth of namespace-scope code; ``None`` inside a class body."""
        if not self.scope_stack:
            return 0
        kind, _name, depth = self.scope_stack[-1]
        return depth + 1 if kind == 'ns' else None


# ---------------------------------------------------------------------------
# RTTI / NiRTTI / VTABLE label scanner
# ---------------------------------------------------------------------------

def _scan_label_files(
    re_include: str,
    addr_lib,
) -> List[dict]:
    """Scan IDs_RTTI.h, IDs_NiRTTI.h, IDs_VTABLE.h for label symbols (AE-only)."""
    labels: Dict[str, dict] = {}

    # --- RTTI and NiRTTI (single bare ID per entry) ---
    for fname, prefix in (('IDs_RTTI.h', 'RTTI_'), ('IDs_NiRTTI.h', 'NiRTTI_')):
        fpath = os.path.join(re_include, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            continue
        for m in _ID_DECL_RE.finditer(content):
            name    = m.group(1)
            raw_ids = m.group(2)
            ids: List[int] = []
            for tok in raw_ids.split(','):
                tok = tok.strip()
                try:
                    ids.append(int(tok))
                except ValueError:
                    pass
            if not ids:
                continue
            id_val = ids[0]
            ae_off = addr_lib.get_ae(id_val)
            lname = prefix + name
            labels.setdefault(lname, {'name': lname, 'ae_off': ae_off, 'id': id_val})

    # --- VTABLE (std::array<REL::ID, N> using REL::ID() constructor) ---
    vtable_path = os.path.join(re_include, 'IDs_VTABLE.h')
    if os.path.isfile(vtable_path):
        try:
            with open(vtable_path, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            content = ''
        for m in _VTABLE_ARRAY_RE.finditer(content):
            name     = m.group(2)
            id_calls = [int(x) for x in _REL_ID_CALL_RE.findall(m.group(3))]
            for idx, id_ in enumerate(id_calls):
                ae_off = addr_lib.get_ae(id_)
                suffix = '' if idx == 0 else '_{}'.format(idx + 1)
                lname = 'VTABLE_' + name + suffix
                labels.setdefault(lname, {'name': lname, 'ae_off': ae_off, 'id': id_,
                                          'vtable_class': name, 'vtable_index': idx})

    return list(labels.values())


def _id_fields(og_id: int, ng_id: int, single_id: int) -> dict:
    """Normalise one parsed reference to ``id`` (+ ``og_id`` / ``ng_id``)."""
    if single_id:
        return {'id': single_id}
    fields = {'id': ng_id or og_id}
    if og_id:
        fields['og_id'] = og_id
    if ng_id:
        fields['ng_id'] = ng_id
    return fields


def _scan_clf4vr_label_files(re_include: str, addr_lib) -> List[dict]:
    """Scan CommonLibF4VR's RTTI_IDs.h / NiRTTI_IDs.h / VTABLE_IDs.h."""
    labels: Dict[str, dict] = {}

    def _read(fname: str) -> str:
        try:
            with open(os.path.join(re_include, fname), encoding='utf-8',
                      errors='replace') as f:
                return f.read()
        except OSError:
            return ''

    for fname, prefix in (('RTTI_IDs.h', 'RTTI_'), ('NiRTTI_IDs.h', 'NiRTTI_')):
        content = _read(fname)
        for m in _RELOCATION_ID_DECL_RE.finditer(content):
            fields = _id_fields(int(m.group(2)), int(m.group(3)), 0)
            if not fields['id']:
                continue
            lname = prefix + m.group(1)
            entry = {'name': lname, 'ae_off': addr_lib.get_ae(fields.get('ng_id'))}
            entry.update(fields)
            labels.setdefault(lname, entry)
        for m in _ID_DECL_RE.finditer(content):
            try:
                id_val = int(m.group(2).split(',')[0].strip())
            except ValueError:
                continue
            if not id_val:
                continue
            lname = prefix + m.group(1)
            labels.setdefault(lname, {'name': lname, 'id': id_val,
                                      'ae_off': addr_lib.get_ae(id_val)})

    for m in _VTABLE_ANY_ARRAY_RE.finditer(_read('VTABLE_IDs.h')):
        name = m.group(2)
        for idx, call in enumerate(_ANY_ID_CALL_RE.finditer(m.group(3))):
            fields = _id_fields(int(call.group(1) or 0), int(call.group(2) or 0),
                                int(call.group(3) or 0))
            if not fields['id']:
                continue
            suffix = '' if idx == 0 else '_{}'.format(idx + 1)
            lname = 'VTABLE_' + name + suffix
            entry = {'name': lname,
                     'ae_off': addr_lib.get_ae(fields.get('ng_id') or fields['id']),
                     'vtable_class': name, 'vtable_index': idx}
            entry.update(fields)
            labels.setdefault(lname, entry)

    return list(labels.values())


# ``[[attr]] Ret Class::Method(args)`` definition line in a .cpp (no ``;``).
# Only matched at namespace scope: inside a body the same shape is a call
# (``return RE::Other::Thing(a,`` continued on the next line).
_QUALIFIED_DEF_RE = re.compile(
    r'\s*(?:\[\[.*?\]\]\s*)*(?:[\w:*&<>,\s]+?\s+)?((?:\w+::)+)(~?\w+)\s*\([^;]*$')


def _scan_inline_relocations(
    file_path: str,
    addr_lib,
    root_namespace: str = 'RE',
    qualified_definitions: bool = False,
) -> List[dict]:
    """Scan one CommonLibF4VR header / .cpp for inline ``REL::ID`` relocations.

    ``qualified_definitions`` (src/*.cpp): the enclosing scope comes from
    ``Ret Class::Method(...)`` definitions instead of class bodies.  That scope
    ends with the definition's body; a relocation outside any known scope (a
    free function) is skipped rather than credited to the previous definition.
    """
    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return []
    if 'REL::Relocation' not in content:
        return []

    out: List[dict] = []
    _ns_pre = root_namespace + '::'
    ctx = _ContextTracker()
    qualified = None          # (class, method) of the current .cpp definition
    qualified_depth = 0       # brace depth the definition was written at
    qualified_open = False    # its body has been entered
    for line in content.split('\n'):
        depth_before = ctx.brace_depth
        scope_depth = ctx.namespace_scope_depth
        ctx.feed_line(line)
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        code = line.split('//', 1)[0]
        if qualified_definitions:
            dm = (_QUALIFIED_DEF_RE.match(code)
                  if depth_before == scope_depth else None)
            if dm:
                qualified = (dm.group(1).rstrip(':'), dm.group(2))
                qualified_depth = depth_before
                qualified_open = '{' in code[dm.end(2):]
            elif qualified is not None:
                if ctx.brace_depth > qualified_depth:
                    qualified_open = True
                elif not qualified_open and ';' in code:
                    qualified = None      # a declaration, not a definition
        scope = qualified
        if (qualified is not None and qualified_open
                and ctx.brace_depth <= qualified_depth):
            qualified = None              # the definition's body closed here
        m = _INLINE_RELOC_RE.search(code)
        if not m:
            continue
        fields = _id_fields(int(m.group(3) or 0), int(m.group(4) or 0),
                            int(m.group(5) or 0))
        if not fields['id']:
            continue
        var_type, var_name = m.group(1), m.group(2)
        kind = 'func' if ('func_t' in var_type or var_name == 'func') else 'label'

        sym_class = ctx.full_class
        sym_name = ctx.method_name
        if qualified_definitions and not sym_class:
            if scope is None:
                continue                   # free function / unknown scope
            sym_class, sym_name = scope
        if sym_class and sym_class.startswith(_ns_pre):
            sym_class = sym_class[len(_ns_pre):]
        if kind == 'label':
            # Data: the relocation names the variable, not its accessor.
            sym_name = '{}::{}'.format(sym_name, var_name) if sym_name else var_name
        elif not sym_name:
            continue                       # an anonymous function is no evidence
        entry = {
            'name': sym_name, 'class_': sym_class,
            'ret': '', 'params': '', 'is_static': False, 'kind': kind,
            'ae_off': addr_lib.get_ae(fields.get('ng_id') or fields['id']),
        }
        entry.update(fields)
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Header scanner
# ---------------------------------------------------------------------------

def _scan_header(
    file_path: str,
    id_map: Dict[str, int],
    addr_lib,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], Set[Tuple[str, str]]]:
    """Scan a single header for REL::Relocation{ ID::Class::Method } and static methods."""
    func_syms: List[dict] = []
    static_methods: Set[Tuple[str, str]] = set()

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return func_syms, static_methods

    if 'REL::Relocation' not in content and 'static' not in content:
        return func_syms, static_methods

    lines = content.split('\n')
    _ns_pre = root_namespace + '::'

    # Pass 1: static methods
    ctx = _ContextTracker()
    for line in lines:
        ctx.feed_line(line)
        if ctx.class_name:
            for m in _STATIC_METHOD_RE.finditer(line):
                full_cls = ctx.full_class
                if full_cls and full_cls.startswith(_ns_pre):
                    static_methods.add((full_cls[len(_ns_pre):], m.group(1)))

    # Pass 2: REL::Relocation{ ID::Class::Method }
    ctx2 = _ContextTracker()
    for line in lines:
        ctx2.feed_line(line)

        ref_m = _RELOC_REF_RE.search(line)
        if not ref_m:
            continue

        id_key = ref_m.group(1)  # e.g. 'Actor::AddPerk'
        ng_id = id_map.get(id_key)
        if not ng_id:
            continue

        ae_off = addr_lib.get_ae(ng_id)

        sym_class = ctx2.full_class
        if sym_class and sym_class.startswith(_ns_pre):
            sym_class = sym_class[len(_ns_pre):]

        # Name from context, or derive from the ID key
        sym_name = ctx2.method_name
        if not sym_name:
            parts = id_key.split('::')
            sym_name = parts[-1]
            if not sym_class and len(parts) > 1:
                sym_class = '::'.join(parts[:-1])

        func_syms.append({
            'name': sym_name,
            'class_': sym_class,
            'ret': '', 'params': '',
            'is_static': False,
            'ae_off': ae_off,
            'id': ng_id,
        })

    return func_syms, static_methods


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_relocations(
    re_include: str,
    addr_lib,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Set[Tuple[str, str]]]:
    """Scan RE/ headers for relocation symbols.

    Returns (func_syms, label_syms, static_methods).
    Each sym has 'ae_off' (None if unresolved).
    """
    # 1. Parse centralised ID registry
    ids_h = os.path.join(re_include, 'IDs.h')
    id_map = _parse_ids_file(ids_h)
    if verbose:
        print(f'  IDs.h: {len(id_map)} relocation IDs')

    # CommonLibF4VR ships RTTI_IDs.h / VTABLE_IDs.h and inline REL::ID /
    # REL::RelocationID instead of IDs.h + IDs_*.h.
    clf4vr_layout = (not os.path.isfile(ids_h) and any(
        os.path.isfile(os.path.join(re_include, n))
        for n in ('VTABLE_IDs.h', 'RTTI_IDs.h', 'NiRTTI_IDs.h')))

    # 2. RTTI / NiRTTI / VTABLE labels
    label_syms = _scan_label_files(re_include, addr_lib)
    if clf4vr_layout:
        label_syms.extend(_scan_clf4vr_label_files(re_include, addr_lib))
    if verbose:
        rtti_n  = sum(1 for l in label_syms if l['name'].startswith('RTTI_'))
        nirtti_n = sum(1 for l in label_syms if l['name'].startswith('NiRTTI_'))
        vtbl_n  = sum(1 for l in label_syms if l['name'].startswith('VTABLE_'))
        print(f'  Labels: {rtti_n} RTTI, {nirtti_n} NiRTTI, {vtbl_n} VTABLE')

    # 3. Scan all RE/ headers
    skip = {'IDs.h', 'IDs_RTTI.h', 'IDs_NiRTTI.h', 'IDs_VTABLE.h', 'RTTI.h',
            'RTTI_IDs.h', 'NiRTTI_IDs.h', 'VTABLE_IDs.h'}
    all_func: List[dict] = []
    all_statics: Set[Tuple[str, str]] = set()

    for h_path in sorted(glob.glob(os.path.join(re_include, '**', '*.h'), recursive=True)):
        if os.path.basename(h_path) in skip:
            continue
        funcs, statics = _scan_header(h_path, id_map, addr_lib, root_namespace)
        all_func.extend(funcs)
        all_statics |= statics
        if clf4vr_layout:
            all_func.extend(_scan_inline_relocations(h_path, addr_lib, root_namespace))

    if clf4vr_layout:
        # <root>/include/RE -> <root>/src
        src_dir = os.path.join(os.path.dirname(os.path.dirname(re_include)), 'src')
        for cpp_path in sorted(glob.glob(os.path.join(src_dir, '**', '*.cpp'),
                                         recursive=True)):
            all_func.extend(_scan_inline_relocations(
                cpp_path, addr_lib, root_namespace, qualified_definitions=True))

    if verbose:
        ae_found = sum(1 for f in all_func if f['ae_off'])
        print(f'  Header scan: {len(all_func)} func symbols '
              f'({ae_found} AE), {len(all_statics)} static methods')

    # Dedup by ae_off; a symbol with no AE offset (legacy-only ID) is keyed
    # by its IDs so header + src copies of one relocation collapse too.
    seen: Set[object] = set()
    deduped: List[dict] = []
    for f in all_func:
        key = f.get('ae_off')
        if key is None and (f.get('og_id') or f.get('ng_id') or clf4vr_layout):
            key = ('ids', f.get('id'), f.get('og_id'), f.get('ng_id'))
        if key is None or key not in seen:
            if key is not None:
                seen.add(key)
            deduped.append(f)

    return deduped, label_syms, all_statics
