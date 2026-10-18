"""Regex-based relocation/symbol scanner for CommonLibSSE.

Parses raw C++ source files (headers and .cpp) with regex to extract:
  - REL::Relocation<T> vars with RELOCATION_ID(SE, AE) → function symbols
  - REL::Relocation<T> vars with Offset:: references  → function symbols
  - RTTI_* / NiRTTI_* / VTABLE_* labels from Offsets_RTTI.h /
    Offsets_NiRTTI.h / Offsets_VTABLE.h
  - Offset:: namespace IDs from Offsets.h (handles #ifdef SE/AE sections)
  - Static method declarations in class bodies

Key advantage over AST-based scanning: RELOCATION_ID(SE, AE) is parsed before
preprocessor expansion, giving both SE and AE IDs in a single pass.

Public API:
  collect_relocations()      - scan RE/ headers for all symbol types
  collect_src_relocations()  - scan src/**/*.cpp for relocation symbols
"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# RELOCATION_ID(se_id, ae_id) — captures both IDs before macro expansion
_RELOC_ID_RE = re.compile(r'RELOCATION_ID\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)')

# REL::ID(integer) — single ID (used in RTTI/VTABLE/Offset headers)
_REL_ID_RE = re.compile(r'REL::ID\s*\(\s*(?:static_cast<std::uint64_t>\(\s*)?(\d+)\s*\)?\s*\)')

# REL::Relocation<T> variable declaration
# Matches: [static] [const] REL::Relocation<...> varname { init } or ( init )
_RELOC_VAR_RE = re.compile(
    r'(?:static\s+)?(?:const\s+)?REL::Relocation<[^>]+>\s+(\w+)\s*[\{(]'
)

# RTTI / NiRTTI label.  The AE half of the headers is brace-initialised, the
# SE half is call-initialised; both must parse or a whole runtime loses its
# labels (group 2 = brace form, group 3 = paren form):
#   inline constexpr REL::ID RTTI_Name{ id };
#   inline constexpr REL::ID RTTI_Name(static_cast<std::uint64_t>(id));
_RTTI_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+((?:Ni)?RTTI_\w+)\s*'
    r'(?:\{\s*(\d+)\s*\}'
    r'|\(\s*(?:static_cast<std::uint64_t>\s*\(\s*)?(\d+)\s*\)?\s*\))'
)

# VTABLE label: inline constexpr std::array<REL::ID, N> VTABLE_Name{ REL::ID(x), ... };
_VTABLE_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::ID,\s*(\d+)>\s+(VTABLE_\w+)\s*\{([^}]+)\}'
)

# Offset namespace: inline constexpr REL::ID Name(static_cast<...>(id));
_OFFSET_ID_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+(\w+)\s*\(\s*static_cast<std::uint64_t>\s*\(\s*(\d+)\s*\)\s*\)'
)

# Namespace opening (with or without same-line brace)
_NS_OPEN_RE = re.compile(r'\bnamespace\s+(\w+)\s*\{')
_NS_DECL_NOPAREN_RE = re.compile(r'^\s*namespace\s+(\w+)\s*$')

# Class/struct opening (with or without same-line brace).  ``alignas(16)`` /
# ``__declspec(novtable)`` may sit between the keyword and the name.
_DECLSPEC = r'(?:(?:__declspec|alignas)\s*\([^)]*\)\s*)*'
_CLASS_RE = re.compile(r'\b(?:class|struct)\s+' + _DECLSPEC +
                       r'(\w+)\s*(?:final\s*)?(?::\s*[^{]*?)?\{')
_CLASS_DECL_RE = re.compile(r'^\s*(?:class|struct)\s+' + _DECLSPEC +
                            r'(\w+)\s*(?:final\s*)?(?::\s*[^{;]*?)?\s*$')

# Method definition inside a class body (for header inline methods)
# Matches with same-line brace: void GetSingleton() {
_METHOD_DEF_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+'
    r'(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?'
    r'\s*\{'
)
# Matches without brace: void GetSingleton() or [[nodiscard]] static Type* GetSingleton()
_METHOD_DECL_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+'
    r'(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?'
    r'\s*$'
)

# Static method in class
_STATIC_METHOD_RE = re.compile(
    r'static\s+(?!constexpr\s+auto\s+RTTI|constexpr\s+auto\s+VTABLE).*?\b(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?;'
)

# Function/method definition (for enclosing context of REL::Relocation vars)
# Matches: ReturnType ClassName::MethodName(params) { or ReturnType FuncName(params) {
_FUNC_DEF_RE = re.compile(
    r'(?:[\w:*&<>,\s]+?)\s+((?:\w+::)*\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{'
)

# ifdef SKYRIM_SUPPORT_AE tracking
_IFDEF_AE_RE = re.compile(r'#\s*ifn?def\s+SKYRIM_SUPPORT_AE')
_ELSE_RE = re.compile(r'#\s*else\b')
_ENDIF_RE = re.compile(r'#\s*endif\b')


# ---------------------------------------------------------------------------
# Brace-tracking context parser
# ---------------------------------------------------------------------------

class _ContextTracker:
    """Track namespace/class/method context via brace counting.

    Handles both same-line braces (``namespace RE {``) and next-line braces::

        namespace RE
        {
    """

    def __init__(self):
        self.scope_stack: List[Tuple[str, str, int]] = []  # (kind, name, brace_depth)
        self.brace_depth = 0
        self._pending: Optional[Tuple[str, str]] = None  # (kind, name) waiting for '{'
        self._pending_method: Optional[str] = None
        self.method_name: Optional[str] = None
        self._method_depth: Optional[int] = None

    def feed_line(self, line: str):
        """Update brace depth and scope from a line of code."""
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('#'):
            return

        opens = line.count('{')
        closes = line.count('}')

        # Same-line namespace/class openings
        for m in _NS_OPEN_RE.finditer(line):
            self.scope_stack.append(('ns', m.group(1), self.brace_depth))
        for m in _CLASS_RE.finditer(line):
            self.scope_stack.append(('class', m.group(1), self.brace_depth))

        # Strip trailing C++ comments for matching
        code_line = re.sub(r'\s*//.*$', '', line)

        # Next-line declarations (no '{' on this line)
        if opens == 0 and closes == 0:
            m = _NS_DECL_NOPAREN_RE.match(code_line)
            if m:
                self._pending = ('ns', m.group(1))
            else:
                m = _CLASS_DECL_RE.match(code_line)
                if m:
                    self._pending = ('class', m.group(1))
                elif self.class_name:
                    m = _METHOD_DECL_RE.search(code_line)
                    if m and m.group(1) not in ('return', 'if', 'else', 'for', 'while', 'switch', 'do'):
                        self._pending_method = m.group(1)

        # Resolve pending declaration when '{' appears
        if self._pending and opens > 0:
            self.scope_stack.append((self._pending[0], self._pending[1], self.brace_depth))
            self._pending = None

        # Track method definitions inside class bodies
        if self.class_name and opens > 0:
            m = _METHOD_DEF_RE.search(line)
            if m:
                self.method_name = m.group(1)
                self._method_depth = self.brace_depth
                self._pending_method = None
            elif self._pending_method:
                self.method_name = self._pending_method
                self._method_depth = self.brace_depth
                self._pending_method = None

        self.brace_depth += opens - closes

        # Pop scopes that have been closed
        while self.scope_stack and self.scope_stack[-1][2] >= self.brace_depth:
            self.scope_stack.pop()

        # Clear method when its brace scope closes
        if self._method_depth is not None and self.brace_depth <= self._method_depth:
            self.method_name = None
            self._method_depth = None

    @property
    def namespace_path(self) -> List[str]:
        return [name for kind, name, _ in self.scope_stack if kind == 'ns']

    @property
    def class_name(self) -> Optional[str]:
        for kind, name, _ in reversed(self.scope_stack):
            if kind == 'class':
                return name
        return None

    @property
    def full_class(self) -> Optional[str]:
        """Full qualified class name (ns1::ns2::Class)."""
        classes = [name for kind, name, _ in self.scope_stack if kind == 'class']
        if not classes:
            return None
        ns = [name for kind, name, _ in self.scope_stack if kind == 'ns']
        return '::'.join(ns + classes)


# ---------------------------------------------------------------------------
# Header file scanner
# ---------------------------------------------------------------------------

def _scan_header_relocations(
    file_path: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Set[Tuple[str, str]]]:
    """Scan a single header file for REL::Relocation, RTTI, VTABLE declarations.

    Returns (func_syms, label_syms, static_methods).
    """
    # The merged ``offset_id_map`` mixes both ID namespaces; resolving one
    # half through it would hand an AE ID to the SE database (or vice versa).
    # A missing per-namespace map resolves nothing.
    if se_offset_map is None:
        se_offset_map = {}
    if ae_offset_map is None:
        ae_offset_map = {}
    func_syms: List[dict] = []
    label_syms: List[dict] = []
    static_methods: Set[Tuple[str, str]] = set()

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return func_syms, label_syms, static_methods

    lines = content.split('\n')
    ctx = _ContextTracker()

    for line in lines:
        ctx.feed_line(line)
        cls = ctx.class_name

        # Static methods
        if cls:
            for m in _STATIC_METHOD_RE.finditer(line):
                method_name = m.group(1)
                full_cls = ctx.full_class
                if full_cls:
                    bare = full_cls
                    _ns_pre = root_namespace + '::'
                    if bare.startswith(_ns_pre):
                        bare = bare[len(_ns_pre):]
                    static_methods.add((bare, method_name))

    # Now do content-level (multi-line-aware) regex scans
    # Scan for REL::Relocation vars with RELOCATION_ID or Offset:: references
    _decltype_re = re.compile(r'decltype\(&([\w:]+(?:\(\))?)\)')
    ctx2 = _ContextTracker()
    _ns_pre2 = root_namespace + '::'
    prev_line = ''
    for line in lines:
        ctx2.feed_line(line)

        reloc_id_match = _RELOC_ID_RE.search(line)
        if reloc_id_match and 'REL::Relocation' in line:
            se_id = int(reloc_id_match.group(1))
            ae_id = int(reloc_id_match.group(2))

            se_off = addr_lib.se_db.get(se_id)
            ae_off = addr_lib.ae_db.get(ae_id)
            # SkyrimVR (1.4.15) shares the SE-derived ID namespace, so the
            # VR DB is keyed on se_id.
            vr_off = addr_lib.vr_db.get(se_id) if hasattr(addr_lib, 'vr_db') else None
            if (not se_off and not ae_off and not vr_off
                    and not _ae_id_known(addr_lib, ae_id)):
                prev_line = line
                continue

            var_match = _RELOC_VAR_RE.search(line)
            var_name = var_match.group(1) if var_match else 'func'

            sym_class = ctx2.full_class
            if sym_class and sym_class.startswith(_ns_pre2):
                sym_class = sym_class[len(_ns_pre2):]

            # Use method name from context, or decltype on prev line, or var name
            sym_name = ctx2.method_name
            if not sym_name or sym_name == var_name:
                dt = _decltype_re.search(prev_line) or _decltype_re.search(line)
                if dt:
                    parts = dt.group(1).split('::')
                    sym_name = parts[-1]
                    if not sym_class and len(parts) > 1:
                        sym_class = '::'.join(parts[:-1])
            sym_name = sym_name or var_name

            func_syms.append({
                'name': sym_name,
                'class_': sym_class,
                'ret': '', 'params': '',
                'is_static': False,
                'se_off': se_off, 'ae_off': ae_off, 'vr_off': vr_off,
                'se_id': se_id or None, 'ae_id': ae_id or None,
            })

        # REL::Relocation using Offset:: reference (no RELOCATION_ID)
        elif 'REL::Relocation' in line and 'Offset::' in line and not _RELOC_ID_RE.search(line):
            var_match = _RELOC_VAR_RE.search(line)
            if not var_match:
                prev_line = line
                continue
            var_name = var_match.group(1)

            off_match = re.search(r'Offset::(\w+(?:::\w+)*)', line)
            if not off_match:
                prev_line = line
                continue
            offset_key = off_match.group(1)
            se_id = se_offset_map.get(offset_key)
            ae_id = ae_offset_map.get(offset_key)
            if se_id is None and ae_id is None:
                prev_line = line
                continue

            se_off = addr_lib.se_db.get(se_id) if se_id else None
            ae_off = addr_lib.ae_db.get(ae_id) if ae_id else None
            vr_off = (addr_lib.vr_db.get(se_id) if (se_id and hasattr(addr_lib, 'vr_db'))
                      else None)
            if (not se_off and not ae_off and not vr_off
                    and not _ae_id_known(addr_lib, ae_id)):
                prev_line = line
                continue

            sym_class = ctx2.full_class
            if sym_class and sym_class.startswith(_ns_pre2):
                sym_class = sym_class[len(_ns_pre2):]

            sym_name = ctx2.method_name
            if not sym_name or sym_name == var_name:
                dt = _decltype_re.search(prev_line) or _decltype_re.search(line)
                if dt:
                    parts = dt.group(1).split('::')
                    sym_name = parts[-1]
                    if not sym_class and len(parts) > 1:
                        sym_class = '::'.join(parts[:-1])
            sym_name = sym_name or var_name

            func_syms.append({
                'name': sym_name,
                'class_': sym_class,
                'ret': '', 'params': '',
                'is_static': False,
                'se_off': se_off, 'ae_off': ae_off, 'vr_off': vr_off,
                'se_id': se_id or None, 'ae_id': ae_id or None,
            })

        prev_line = line

    return func_syms, label_syms, static_methods


def _scan_offsets_file(file_path: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Parse Offsets.h to build offset_id_maps: 'Class::Method' → integer ID.

    Handles #ifdef SKYRIM_SUPPORT_AE / #else / #endif sections.
    Returns (se_offset_map, ae_offset_map).
    """
    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return {}, {}

    ae_text, se_text, has_ifdef = _split_ae_se_sections(content)
    if has_ifdef:
        return _parse_offset_section(se_text), _parse_offset_section(ae_text)
    return _parse_offset_section(content), {}


_NS_DECL_RE = re.compile(r'\bnamespace\s+(\w+)')


def _parse_offset_section(text: str) -> Dict[str, int]:
    """Parse a single section of Offsets.h for namespace::ID entries."""
    offset_map: Dict[str, int] = {}
    ns_stack: List[str] = []
    brace_depth = 0
    ns_at_depth: Dict[int, str] = {}
    pending_ns = None

    for line in text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue

        ns_m = _NS_DECL_RE.search(line)
        if ns_m:
            ns_name = ns_m.group(1)
            if ns_name not in ('RE', 'Offset'):
                if '{' in line[ns_m.end():]:
                    ns_at_depth[brace_depth] = ns_name
                    ns_stack.append(ns_name)
                else:
                    pending_ns = ns_name

        opens = line.count('{')
        closes = line.count('}')

        if pending_ns and opens > 0:
            ns_at_depth[brace_depth] = pending_ns
            ns_stack.append(pending_ns)
            pending_ns = None

        off_m = _OFFSET_ID_RE.search(line)
        if off_m:
            name = off_m.group(1)
            the_id = int(off_m.group(2))
            key = '::'.join(ns_stack + [name])
            offset_map[key] = the_id

        brace_depth += opens - closes

        while ns_at_depth:
            max_depth = max(ns_at_depth.keys())
            if max_depth >= brace_depth:
                ns_at_depth.pop(max_depth)
                if ns_stack:
                    ns_stack.pop()
            else:
                break

    return offset_map


def _split_ae_se_sections(content: str) -> Tuple[str, str, bool]:
    """Split a header on its ``SKYRIM_SUPPORT_AE`` conditional.

    Returns ``(ae_text, se_text, has_conditional)``.  The two halves are
    DIFFERENT address-library ID namespaces (SE 1.5.97 + VR 1.4.15 share one,
    AE 1.6.x / 1.7.x share another), so an ID must be looked up only in the
    databases of the half it was written in.
    """
    if 'SKYRIM_SUPPORT_AE' not in content:
        return '', content, False
    ae_lines: List[str] = []
    se_lines: List[str] = []
    section = None   # None | 'ae' | 'se' | 'other' (an #elif branch: neither)
    first = None     # the half the opening #ifdef/#ifndef selected
    nested = 0       # unrelated #if blocks inside the conditional
    for line in content.split('\n'):
        stripped = line.strip()
        directive = re.match(r'#\s*(ifdef|ifndef|if|else|elif|endif)\b', stripped)
        if directive:
            word = directive.group(1)
            if section is None:
                if word in ('ifdef', 'ifndef') and 'SKYRIM_SUPPORT_AE' in stripped:
                    section = first = 'ae' if word == 'ifdef' else 'se'
                    nested = 0
                    continue
            elif word in ('ifdef', 'ifndef', 'if'):
                nested += 1
            elif word == 'endif':
                if nested:
                    nested -= 1
                else:
                    section = None
                    continue
            elif word == 'elif' and not nested:
                # Its condition is something else entirely: the lines belong
                # to neither half (fail closed rather than stay in the first).
                section = 'other'
                continue
            elif word == 'else' and not nested:
                section = 'se' if first == 'ae' else 'ae'
                continue
        if section == 'ae':
            ae_lines.append(line)
        elif section == 'se':
            se_lines.append(line)
    return '\n'.join(ae_lines), '\n'.join(se_lines), True


# Databases keyed on the AE ID namespace (1.6.1170 is the primary ``ae_db``).
_AE_NAMESPACE_DBS = ('ae_db', 'db_16640', 'db_17104')


def _ae_id_known(addr_lib, ae_id) -> bool:
    """True when ``ae_id`` resolves in ANY AE-namespace runtime.

    An ID that 1.6.1170 dropped can still exist in 1.6.640; the symbol must
    survive the scan so the generator can resolve that runtime from the ID.
    """
    if not ae_id:
        return False
    return any(ae_id in (getattr(addr_lib, attr, None) or {})
               for attr in _AE_NAMESPACE_DBS)


def _new_label(name: str) -> dict:
    return {'name': name, 'se_off': None, 'ae_off': None, 'vr_off': None,
            'se_id': None, 'ae_id': None}


def _iter_label_ids(text: str):
    """Yield ``(label_name, id, vtable_class, vtable_index)`` for one section."""
    for m in _RTTI_RE.finditer(text):
        yield m.group(1), int(m.group(2) or m.group(3)), None, None
    for m in _VTABLE_RE.finditer(text):
        base_name = m.group(2)
        ids = [int(x) for x in _REL_ID_RE.findall(m.group(3))]
        for idx, id_ in enumerate(ids):
            lname = base_name if idx == 0 else '{}_{}'.format(base_name, idx + 1)
            yield lname, id_, base_name[len('VTABLE_'):], idx


def _scan_rtti_vtable_file(
    file_path: str,
    addr_lib,
) -> List[dict]:
    """Parse Offsets_RTTI.h / Offsets_NiRTTI.h / Offsets_VTABLE.h for labels.

    These files have the structure:
        #ifdef SKYRIM_SUPPORT_AE   (AE IDs)
        #else                      (SE IDs)
        #endif
    AE-section IDs are resolved ONLY in AE-namespace databases and SE-section
    IDs ONLY in ``se_db`` / ``vr_db``.  Each label carries the ID it was
    declared with (``se_id`` / ``ae_id``) so later stages never have to
    recover it from an RVA.
    """
    labels: Dict[str, dict] = {}

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return list(labels.values())

    ae_text, se_text, _has_ifdef = _split_ae_se_sections(content)
    has_vr = hasattr(addr_lib, 'vr_db')

    for name, id_, vt_class, vt_index in _iter_label_ids(ae_text):
        if not _ae_id_known(addr_lib, id_):
            continue
        entry = labels.setdefault(name, _new_label(name))
        entry['ae_id'] = id_
        off = addr_lib.ae_db.get(id_)
        if off:
            entry['ae_off'] = off
        if vt_class is not None:
            entry['vtable_class'], entry['vtable_index'] = vt_class, vt_index

    # A header without the conditional is SE-namespace (powerof3 default).
    for name, id_, vt_class, vt_index in _iter_label_ids(se_text):
        off = addr_lib.se_db.get(id_)
        vr_off = addr_lib.vr_db.get(id_) if has_vr else None
        if not off and not vr_off:
            continue
        entry = labels.setdefault(name, _new_label(name))
        entry['se_id'] = id_
        if off:    entry['se_off'] = off
        if vr_off: entry['vr_off'] = vr_off
        if vt_class is not None:
            entry['vtable_class'], entry['vtable_index'] = vt_class, vt_index

    return list(labels.values())


# ---------------------------------------------------------------------------
# Source file scanner (.cpp)
# ---------------------------------------------------------------------------

def _scan_src_relocations(
    src_dir: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    root_namespace: str = 'RE',
) -> List[dict]:
    """Scan CommonLibSSE src/**/*.cpp for REL::Relocation + RELOCATION_ID."""
    # The merged ``offset_id_map`` mixes both ID namespaces; resolving one
    # half through it would hand an AE ID to the SE database (or vice versa).
    # A missing per-namespace map resolves nothing.
    if se_offset_map is None:
        se_offset_map = {}
    if ae_offset_map is None:
        ae_offset_map = {}
    func_syms: List[dict] = []

    cpp_files = sorted(glob.glob(os.path.join(src_dir, '**', '*.cpp'), recursive=True))
    for cpp_path in cpp_files:
        try:
            with open(cpp_path, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            continue

        # Quick check — skip files without REL references
        if 'RELOCATION_ID' not in content and 'REL::Relocation' not in content:
            continue

        _decltype_re = re.compile(r'decltype\(&([\w:]+(?:\(\))?)\)')
        lines = content.split('\n')
        current_func_class = None
        current_func_name = None
        pending_func = None
        prev_line = ''

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Track function definitions for context.
            # Handles both "RetType Class::Method(...) {" (same line)
            # and "RetType Class::Method(...)\n{" (brace on next line).
            func_m = re.match(r'.*?\b((?:\w+::)+)(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:->.*?)?\s*\{?', line)
            if func_m and '::' in func_m.group(1):
                qual = func_m.group(1).rstrip(':')
                fname = func_m.group(2)
                _ns_pre = root_namespace + '::'
                if qual.startswith(_ns_pre):
                    qual = qual[len(_ns_pre):]
                if '{' in line[func_m.end()-1:]:
                    current_func_class = qual
                    current_func_name = fname
                    pending_func = None
                else:
                    pending_func = (qual, fname)
            elif pending_func and stripped == '{':
                current_func_class, current_func_name = pending_func
                pending_func = None

            # RELOCATION_ID in this line
            reloc_m = _RELOC_ID_RE.search(line)
            if reloc_m:
                se_id = int(reloc_m.group(1))
                ae_id = int(reloc_m.group(2))
                se_off = addr_lib.se_db.get(se_id)
                ae_off = addr_lib.ae_db.get(ae_id)
                # SkyrimVR (1.4.15) shares the SE ID namespace: key on se_id,
                # exactly like the header scanner.
                vr_off = addr_lib.vr_db.get(se_id) if hasattr(addr_lib, 'vr_db') else None
                if (not se_off and not ae_off and not vr_off
                        and not _ae_id_known(addr_lib, ae_id)):
                    prev_line = line
                    continue

                var_match = _RELOC_VAR_RE.search(line)
                var_name = var_match.group(1) if var_match else 'func'

                sym_name = current_func_name
                sym_class = current_func_class

                # Fallback: extract from decltype on previous or current line
                if not sym_name or not sym_class:
                    dt = _decltype_re.search(prev_line) or _decltype_re.search(line)
                    if dt:
                        parts = dt.group(1).split('::')
                        if not sym_name:
                            sym_name = parts[-1]
                        if not sym_class and len(parts) > 1:
                            sym_class = '::'.join(parts[:-1])
                sym_name = sym_name or var_name

                func_syms.append({
                    'name': sym_name,
                    'class_': sym_class,
                    'ret': '', 'params': '',
                    'is_static': False,
                    'se_off': se_off, 'ae_off': ae_off, 'vr_off': vr_off,
                    'se_id': se_id or None, 'ae_id': ae_id or None,
                })

            # Offset:: reference
            elif 'REL::Relocation' in line and 'Offset::' in line:
                var_match = _RELOC_VAR_RE.search(line)
                if not var_match:
                    prev_line = line
                    continue
                off_match = re.search(r'Offset::(\w+(?:::\w+)*)', line)
                if not off_match:
                    prev_line = line
                    continue
                offset_key = off_match.group(1)
                se_id = se_offset_map.get(offset_key)
                ae_id = ae_offset_map.get(offset_key)
                if se_id is None and ae_id is None:
                    prev_line = line
                    continue
                se_off = addr_lib.se_db.get(se_id) if se_id else None
                ae_off = addr_lib.ae_db.get(ae_id) if ae_id else None
                vr_off = (addr_lib.vr_db.get(se_id)
                          if (se_id and hasattr(addr_lib, 'vr_db')) else None)
                if (not se_off and not ae_off and not vr_off
                        and not _ae_id_known(addr_lib, ae_id)):
                    prev_line = line
                    continue

                sym_name = current_func_name
                sym_class = current_func_class

                if not sym_name or not sym_class:
                    dt = _decltype_re.search(prev_line) or _decltype_re.search(line)
                    if dt:
                        parts = dt.group(1).split('::')
                        if not sym_name:
                            sym_name = parts[-1]
                        if not sym_class and len(parts) > 1:
                            sym_class = '::'.join(parts[:-1])
                sym_name = sym_name or var_match.group(1)

                func_syms.append({
                    'name': sym_name,
                    'class_': sym_class,
                    'ret': '', 'params': '',
                    'is_static': False,
                    'se_off': se_off, 'ae_off': ae_off, 'vr_off': vr_off,
                    'se_id': se_id or None, 'ae_id': ae_id or None,
                })

            prev_line = line

    return func_syms


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_LABEL_HEADERS = ('Offsets_RTTI.h', 'Offsets_NiRTTI.h', 'Offsets_VTABLE.h')


def _func_dedup_key(func_sym: dict):
    """``(se_off, ae_off)``; symbols that resolve in neither primary database
    (VR-only, or an AE ID that only 1.6.640 still has) are keyed by their IDs
    so they do not all collapse into one ``(None, None)`` entry."""
    key = (func_sym.get('se_off'), func_sym.get('ae_off'))
    if key == (None, None):
        return ('ids', func_sym.get('se_id'), func_sym.get('ae_id'))
    return key


def collect_relocations(
    re_include: str,
    addr_lib,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Dict[str, int], Set[Tuple[str, str]], Dict[str, int], Dict[str, int]]:
    """Scan headers for relocation symbols.

    Returns (func_syms, label_syms, offset_id_map, static_methods, se_offset_map, ae_offset_map).
    Each func_sym has both se_off and ae_off (from RELOCATION_ID).
    """
    all_func_syms: List[dict] = []
    all_label_syms: List[dict] = []
    all_static_methods: Set[Tuple[str, str]] = set()

    # 1. Parse Offsets.h for offset_id_map (SE and AE sections)
    commonlib_include = os.path.dirname(re_include)
    offsets_h = os.path.join(re_include, 'Offsets.h')
    se_offset_map, ae_offset_map = _scan_offsets_file(offsets_h)
    offset_id_map = dict(se_offset_map)
    for k, v in ae_offset_map.items():
        offset_id_map.setdefault(k, v)
    if verbose:
        print(f'  Parsed {len(se_offset_map)} SE + {len(ae_offset_map)} AE offset IDs from Offsets.h')

    # 2. Parse RTTI/NiRTTI/VTABLE offset headers
    for fname in _LABEL_HEADERS:
        fpath = os.path.join(re_include, fname)
        if os.path.isfile(fpath):
            labels = _scan_rtti_vtable_file(fpath, addr_lib)
            all_label_syms.extend(labels)
            if verbose:
                print(f'  Parsed {len(labels)} labels from {fname}')

    # 3. Scan all RE/ header files for REL::Relocation + static methods
    h_files = sorted(glob.glob(os.path.join(re_include, '**', '*.h'), recursive=True))
    for h_path in h_files:
        basename = os.path.basename(h_path)
        if basename == 'Offsets.h' or basename in _LABEL_HEADERS:
            continue
        funcs, labels, statics = _scan_header_relocations(h_path, addr_lib, offset_id_map,
                                                            se_offset_map=se_offset_map,
                                                            ae_offset_map=ae_offset_map,
                                                            root_namespace=root_namespace)
        all_func_syms.extend(funcs)
        all_label_syms.extend(labels)
        all_static_methods |= statics

    if verbose:
        print(f'  Header scan: {len(all_func_syms)} func symbols, '
              f'{len(all_label_syms)} labels, {len(all_static_methods)} static methods')

    # Dedup by (se_off, ae_off)
    seen = set()
    deduped_funcs = []
    for f in all_func_syms:
        key = _func_dedup_key(f)
        if key not in seen:
            seen.add(key)
            deduped_funcs.append(f)
    all_func_syms = deduped_funcs

    seen_labels = set()
    deduped_labels = []
    for l in all_label_syms:
        key = (l['name'], l.get('se_off'), l.get('ae_off'))
        if key not in seen_labels:
            seen_labels.add(key)
            deduped_labels.append(l)
    all_label_syms = deduped_labels

    return all_func_syms, all_label_syms, offset_id_map, all_static_methods, se_offset_map, ae_offset_map


def collect_src_relocations(
    src_dir: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> List[dict]:
    """Scan src/**/*.cpp for relocation symbols.

    Returns func_syms with both se_off and ae_off populated.
    """
    func_syms = _scan_src_relocations(src_dir, addr_lib, offset_id_map,
                                       se_offset_map=se_offset_map,
                                       ae_offset_map=ae_offset_map,
                                       root_namespace=root_namespace)

    # Dedup
    seen = set()
    deduped = []
    for f in func_syms:
        key = _func_dedup_key(f)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if verbose:
        print(f'  src/ scan: {len(deduped)} func symbols from '
              f'{len(glob.glob(os.path.join(src_dir, "**", "*.cpp"), recursive=True))} cpp files')

    return deduped
