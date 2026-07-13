#!/usr/bin/env python3
"""
Clang subprocess-based C++ type extraction for Ghidra import.

Four-pass approach using clang.exe:
  Pass 1: -ast-dump (text)
            → enums, base classes, virtual methods, type aliases
  Pass 2: -fdump-record-layouts-complete/canonical
            → struct fields, byte offsets, sizes, base offsets
  Pass 3: synthetic ``struct sN { T<args> _; }`` + record-layout dump
            → forced layouts for template instantiations the orchestrator
              header never used (and re-tried for entries propagation
              filled with shape-mismatched donor fields)
  Pass 4: synthetic ``auto u<N> = &Class::Method`` + ``-fdump-vtable-layouts``
            → exact primary-vtable slot indices and per-(class, subobject)
              secondary-vtable layouts for multi-inheritance

After all passes, results are merged, template instantiations are discovered
via template_types.py, vmethods/methods are propagated from each template
definition onto its instantiations, anonymous lambda/unnamed types are
stripped, and forward-declared external types get 0-byte opaque stubs so
references type-check in Ghidra.

Project-agnostic: root namespace and category prefix are configurable, and
``extra_scope_paths`` lets the AST extraction follow sibling header trees
(REL/REX/F4SE/SKSE/Scaleform) outside the main include dir.

Public API:
  collect_types()         - run all passes and return (enums, structs, template_source)
  find_clang_binary()     - locate clang (explicit override, PATH, Windows fallbacks)
  _setup_include_paths()  - build clang include args from CommonLib + stub dirs
"""

import os
import sys
import re
import shutil
import subprocess
import tempfile


# Keep generated include overlays alive for every Clang pass in this process.
# TemporaryDirectory removes them when the interpreter exits.
_RUNTIME_STUB_DIRS = []


# ---------------------------------------------------------------------------
# clang.exe discovery
# ---------------------------------------------------------------------------

def find_clang_binary():
    """Locate Clang without bypassing a caller-prepended toolchain on PATH.

    ``BGS_CLANG_BINARY`` is an optional exact executable override.  A bad
    override is an error rather than permission to silently select a different
    compiler, which keeps generated layouts reproducible.
    """
    explicit = os.environ.get('BGS_CLANG_BINARY')
    if explicit:
        candidate = os.path.abspath(os.path.expanduser(
            os.path.expandvars(explicit.strip().strip('"'))))
        if not os.path.isfile(candidate):
            raise FileNotFoundError(
                'BGS_CLANG_BINARY does not name a file: {}'.format(candidate))
        return candidate

    # run.py prepends the repository-pinned LLVM directory to PATH.  Honor it
    # before registry/global-install probes, which may point at another LLVM.
    candidate = shutil.which('clang')
    if candidate:
        return candidate

    try:
        import winreg
        for hive, key in [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\LLVM\LLVM'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\LLVM\LLVM'),
        ]:
            try:
                with winreg.OpenKey(hive, key) as k:
                    install_dir, _ = winreg.QueryValueEx(k, '')
                    candidate = os.path.join(install_dir, 'bin', 'clang.exe')
                    if os.path.isfile(candidate):
                        return candidate
            except OSError:
                pass
    except ImportError:
        pass
    for path in [
        r'C:\Program Files\LLVM\bin\clang.exe',
        r'C:\Program Files (x86)\LLVM\bin\clang.exe',
    ]:
        if os.path.isfile(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Type-string mapping (clang type names → pipeline type descriptors)
# ---------------------------------------------------------------------------

_CLANG_TYPE_MAP = {
    'bool': 'bool', '_Bool': 'bool',
    'char': 'i8', 'signed char': 'i8', 'unsigned char': 'u8',
    'short': 'i16', 'signed short': 'i16', 'unsigned short': 'u16',
    'int': 'i32', 'signed int': 'i32', 'unsigned int': 'u32',
    'long': 'i32', 'signed long': 'i32', 'unsigned long': 'u32',
    'long long': 'i64', 'signed long long': 'i64', 'unsigned long long': 'u64',
    '__int64': 'i64', 'unsigned __int64': 'u64',
    'float': 'f32', 'double': 'f64', 'long double': 'f64',
    'void': 'void',
    # C/C++ wide & UTF char types (Windows: wchar_t = 16-bit)
    'wchar_t':  'u16',
    'char16_t': 'u16',
    'char32_t': 'u32',
    'char8_t':  'u8',
    # std::byte is enum class byte : unsigned char {} — pure 1-byte storage
    'std::byte': 'u8', 'byte': 'u8',
    'std::uint8_t': 'u8', 'uint8_t': 'u8',
    'std::uint16_t': 'u16', 'uint16_t': 'u16',
    'std::uint32_t': 'u32', 'uint32_t': 'u32',
    'std::uint64_t': 'u64', 'uint64_t': 'u64',
    'std::int8_t': 'i8', 'int8_t': 'i8',
    'std::int16_t': 'i16', 'int16_t': 'i16',
    'std::int32_t': 'i32', 'int32_t': 'i32',
    'std::int64_t': 'i64', 'int64_t': 'i64',
    'std::size_t': 'usize', 'size_t': 'usize',
    'std::ptrdiff_t': 'isize', 'ptrdiff_t': 'isize',
    'std::uintptr_t': 'usize', 'uintptr_t': 'usize',
    'std::intptr_t': 'isize', 'intptr_t': 'isize',
}

_KW_STRIP_RE = re.compile(r'\b(?:class|struct|union|enum)\s+')
# Match the keyword anywhere as a whole word — covers `const T`, `T const`, and
# `T *const` (where `*` is non-word so `\b` lies between it and `c`).
_CV_STRIP_RE = re.compile(r'\b(?:const|volatile|restrict)\b')

_PRIM_BARE = frozenset({
    'void', 'bool', '_Bool', 'char', 'wchar_t', 'char8_t', 'char16_t', 'char32_t',
    'float', 'double', 'auto',
    'short', 'int', 'long',
    'signed', 'unsigned', '__int64', '__int32', '__int16', '__int8', '__int128',
    'nullptr_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'size_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t',
    'byte',
})

_PRIM_MULTI = frozenset({
    'signed char', 'unsigned char',
    'signed short', 'unsigned short',
    'signed int', 'unsigned int',
    'signed long', 'unsigned long',
    'long long', 'signed long long', 'unsigned long long',
    'long double',
    'unsigned __int64', 'signed __int64',
})

_PRIM_ALL = _PRIM_BARE | _PRIM_MULTI


def _split_tmpl_args(inner):
    args = []
    depth = 0
    start = 0
    for i, ch in enumerate(inner):
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
        elif ch == ',' and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    tail = inner[start:].strip()
    if tail:
        args.append(tail)
    return args


_LITERAL_KEYWORDS = frozenset({'true', 'false', 'nullptr', 'this'})


def _ensure_qualified(name, root_ns='RE'):
    """Prepend root_ns:: to bare identifiers. Already-qualified names are unchanged.

    ``root_ns`` may be None or empty for codebases that put their game
    types at global scope (xNVSE/FNV).  In that case identifiers pass
    through unchanged.
    """
    name = name.strip()
    if not name:
        return name
    if not root_ns:
        return name
    if '::' in name:
        return name
    if name in _PRIM_ALL:
        return name
    if name in _LITERAL_KEYWORDS:
        return name
    # Numeric literals: int, float, hex, octal — with optional sign and suffix
    if re.fullmatch(r"[+-]?(?:0[xX][0-9A-Fa-f]+|[0-9]+(?:\.[0-9]*)?)[uUlLfFeE0-9+\-]*", name):
        return name
    # Character or string literal
    if (name.startswith("'") and name.endswith("'")) or (name.startswith('"') and name.endswith('"')):
        return name
    return root_ns + '::' + name


def _qualify_type(name, root_ns='RE'):
    """Recursively ensure a C++ type name is fully qualified.

    Strips cv-qualifiers and pointer/reference suffixes, qualifies the core
    name (and template arguments), then re-attaches them.
    """
    name = name.strip()
    if not name:
        return name
    leading = ''
    for q in ('const ', 'volatile '):
        while name.startswith(q):
            leading += q
            name = name[len(q):]
    trailing = ''
    _changed = True
    while _changed:
        _changed = False
        for t in (' const', ' *', ' &', '*', '&'):
            if name.endswith(t):
                trailing = t + trailing
                name = name[:-len(t)].rstrip()
                _changed = True
                break
    name = name.strip()
    lt = name.find('<')
    if lt >= 0 and name.endswith('>'):
        outer = name[:lt].strip()
        inner_str = name[lt + 1:-1]
        qual_outer = _ensure_qualified(outer, root_ns)
        inner_args = _split_tmpl_args(inner_str)
        qual_args = ', '.join(_qualify_type(a, root_ns) for a in inner_args)
        return '{}{}<{}>{}'.format(leading, qual_outer, qual_args, trailing)
    if name in _PRIM_ALL:
        return '{}{}{}'.format(leading, name, trailing)
    if '::' in name:
        parts = _split_ns(name)
        qualified_parts = []
        for p in parts:
            plt = p.find('<')
            if plt >= 0 and p.endswith('>'):
                p_outer = p[:plt].strip()
                p_inner = p[plt + 1:-1]
                p_args = _split_tmpl_args(p_inner)
                q_args = ', '.join(_qualify_type(a, root_ns) for a in p_args)
                qualified_parts.append('{}<{}>'.format(p_outer, q_args))
            else:
                qualified_parts.append(p)
        return '{}{}{}'.format(leading, '::'.join(qualified_parts), trailing)
    if name in _PRIM_BARE:
        return '{}{}{}'.format(leading, name, trailing)
    # Bare leaf — protect non-type tokens (numeric template args like ``16``,
    # boolean/null literals, string/char literals) before falling back to the
    # ``root_ns::name`` qualifier.
    return '{}{}{}'.format(leading, _ensure_qualified(name, root_ns), trailing)


_VEC_ATTR_RE = re.compile(
    r'__attribute__\s*\(\s*\(\s*__vector_size__\s*\(\s*'
    r'(\d+)\s*\*\s*sizeof\s*\(\s*([^)]+?)\s*\)\s*\)\s*\)\s*\)\s*'
)
_PRIM_BYTE_SIZE = {
    'char': 1, 'signed char': 1, 'unsigned char': 1, 'bool': 1, '_Bool': 1, 'byte': 1,
    'char8_t': 1, 'std::byte': 1,
    'short': 2, 'signed short': 2, 'unsigned short': 2, 'wchar_t': 2,
    'char16_t': 2,
    'int': 4, 'signed int': 4, 'unsigned int': 4, 'char32_t': 4,
    'long': 4, 'signed long': 4, 'unsigned long': 4,
    'float': 4,
    'long long': 8, 'signed long long': 8, 'unsigned long long': 8,
    '__int64': 8, 'unsigned __int64': 8,
    'double': 8, 'long double': 8,
}


def _is_function_pointer_type(raw: str) -> bool:
    """Detect function-pointer-shaped types in any depth:
    ``Ret (*)(args)``, ``Ret (**)(args)``, ``Ret (Class::*)(args)``,
    ``Ret (*[N])(args)`` and ``Ret (&)(args)`` (function reference).
    """
    return bool(re.search(
        r'\(\s*(?:[\w:]+\s*::\s*)?[*&]+\s*(?:\[\d*\]\s*)?[\w]*\s*\)\s*\(', raw))


def _record_type_to_pipeline(raw, root_ns='RE'):
    """Convert a raw clang type string to a pipeline type descriptor."""
    raw = _KW_STRIP_RE.sub('', raw.strip()).strip()
    # Drop cv-qualifiers — they don't affect the underlying type or layout.
    raw = _CV_STRIP_RE.sub(' ', raw).strip()
    raw = re.sub(r'\s+', ' ', raw)

    # SIMD vectors: clang emits `__attribute__((__vector_size__(N * sizeof(T)))) T`
    # Map to a byte array of the computed size.
    m_vec = _VEC_ATTR_RE.search(raw)
    if m_vec:
        try:
            count = int(m_vec.group(1))
            elem  = m_vec.group(2).strip()
            elem_size = _PRIM_BYTE_SIZE.get(elem)
            if elem_size:
                return 'arr:u8:{}'.format(count * elem_size)
        except ValueError:
            pass
        return 'ptr'

    # Function pointer types: `Ret (*)(args)` and member pointers `Ret (C::*)(args)`
    if _is_function_pointer_type(raw):
        return 'ptr'

    if raw.endswith('*') or raw.endswith('&'):
        pointee = raw[:-1].strip()
        inner = _record_type_to_pipeline(pointee, root_ns)
        # Wrap any typed inner descriptor (primitive / struct / enum / nested
        # ptr / arr).  Only fall back to bare ``ptr`` when the inner itself
        # was unresolvable, to avoid producing a misleading ``ptr:ptr``.
        if inner and inner != 'ptr':
            return 'ptr:' + inner
        return 'ptr'
    if raw in _CLANG_TYPE_MAP:
        return _CLANG_TYPE_MAP[raw]
    m_arr = re.match(r'^(.+)\[(\d+)\]$', raw)
    if m_arr:
        elem_type = _record_type_to_pipeline(m_arr.group(1).strip(), root_ns)
        count = int(m_arr.group(2))
        return 'arr:{}:{}'.format(elem_type, count)
    if raw:
        return 'struct:' + _qualify_type(raw, root_ns)
    return 'ptr'


# ---------------------------------------------------------------------------
# Include path and stub generation
# ---------------------------------------------------------------------------

def _target_abi(target_arch='x64'):
    arch = str(target_arch).lower()
    if arch in ('x86', 'i386', 'i686', '32'):
        return {
            'arch': 'x86', 'pointer_size': 4,
            'triple': 'i686-pc-windows-msvc',
            'vcpkg_triplets': ('x86-windows-static', 'x86-windows'),
            'defines': ('-DWIN32', '-D_WIN32', '-D_M_IX86'),
            'undefines': ('-U_WIN64', '-U_M_X64', '-U_AMD64_'),
        }
    if arch in ('x64', 'amd64', 'x86_64', '64'):
        return {
            'arch': 'x64', 'pointer_size': 8,
            'triple': 'x86_64-pc-windows-msvc',
            'vcpkg_triplets': ('x64-windows-static', 'x64-windows'),
            'defines': ('-DWIN32', '-D_WIN32', '-D_WIN64', '-D_M_X64'),
            'undefines': ('-U_M_IX86',),
        }
    raise ValueError('unsupported target architecture: {}'.format(target_arch))


def _normalize_abi_args(parse_args, target_arch=None):
    """Return (clang_args, abi), removing contradictory legacy macros."""
    if target_arch is None:
        lowered = [str(arg).lower() for arg in parse_args]
        # Only a *definition* of _M_IX86 selects the 32-bit ABI.  The x64
        # setup intentionally contains ``-U_M_IX86``; substring matching that
        # token used to turn every default x64 parse back into i686.
        defines_ix86 = any(
            arg == '-d_m_ix86' or arg.startswith('-d_m_ix86=')
            for arg in lowered)
        targets_i386 = any(
            arg.startswith('--target=') and
            arg.split('=', 1)[1].startswith(
                ('i386-', 'i486-', 'i586-', 'i686-'))
            for arg in lowered)
        target_arch = 'x86' if (defines_ix86 or targets_i386) else 'x64'
    abi = _target_abi(target_arch)
    filtered = []
    skip_next = False
    contradictory = {
        '-d_win64', '-d_m_x64', '-d_m_ix86', '-u_win64', '-u_m_x64', '-u_m_ix86',
    }
    for arg in parse_args:
        low = arg.lower()
        if low.startswith('--target=') or low in contradictory:
            continue
        filtered.append(arg)
    normalized = ['--target=' + abi['triple']]
    normalized.extend(abi['undefines'])
    normalized.extend(abi['defines'])
    normalized.extend(filtered)
    return normalized, abi


def _setup_include_paths(commonlib_include, clang_stub_dir, target_arch='x64'):

    abi = _target_abi(target_arch)

    _vcpkg_include = None
    _vcpkg_root = os.environ.get('VCPKG_ROOT', '')
    if _vcpkg_root:
        for _triplet in abi['vcpkg_triplets']:
            _candidate = os.path.join(_vcpkg_root, 'installed', _triplet, 'include')
            if (os.path.isfile(os.path.join(_candidate, 'binary_io', 'file_stream.hpp'))
                    and os.path.isfile(os.path.join(_candidate, 'spdlog', 'spdlog.h'))):
                _vcpkg_include = _candidate
                break

    if _vcpkg_include:
        third_party = _vcpkg_include
    else:
        os.makedirs(os.path.join(clang_stub_dir, 'binary_io'), exist_ok=True)
        os.makedirs(os.path.join(clang_stub_dir, 'spdlog'), exist_ok=True)

        bio_stub = os.path.join(clang_stub_dir, 'binary_io', 'file_stream.hpp')
        if not os.path.isfile(bio_stub):
            with open(bio_stub, 'w') as f:
                f.write('#pragma once\nnamespace binary_io { class file_istream {}; class file_ostream {}; }\n')

        spdlog_stub = os.path.join(clang_stub_dir, 'spdlog', 'spdlog.h')
        if not os.path.isfile(spdlog_stub):
            with open(spdlog_stub, 'w') as f:
                f.write('#pragma once\nnamespace spdlog { class logger {}; }\n')

        third_party = clang_stub_dir

    # Shadow spdlog/details/windows_include.h to undef REX::W32 macro conflicts.
    # The undef list is game/header-tree specific, so never write it into the
    # shared tracked stub tree.  Copy that tiny static tree to a process-lifetime
    # overlay to preserve its existing include precedence, then customize only
    # the temporary copy.
    runtime_stubs = tempfile.TemporaryDirectory(prefix='bgs-clang-stubs-')
    _RUNTIME_STUB_DIRS.append(runtime_stubs)
    win_stub_dir = runtime_stubs.name
    if os.path.isdir(clang_stub_dir):
        shutil.copytree(clang_stub_dir, win_stub_dir, dirs_exist_ok=True)
    os.makedirs(os.path.join(win_stub_dir, 'spdlog', 'details'), exist_ok=True)
    os.makedirs(os.path.join(win_stub_dir, 'spdlog', 'sinks'), exist_ok=True)

    with open(os.path.join(win_stub_dir, 'spdlog', 'sinks', 'wincolor_sink-inl.h'), 'w') as f:
        f.write('#pragma once\n')

    rex_w32_names = []
    rex_dir = os.path.join(commonlib_include, 'REX', 'W32')
    if os.path.isdir(rex_dir):
        for root, _dirs, files in os.walk(rex_dir):
            for fname in files:
                if fname.endswith('.h'):
                    try:
                        with open(os.path.join(root, fname), encoding='utf-8', errors='replace') as fh:
                            for line in fh:
                                m = re.match(r'\s*inline\s+(?:constexpr\s+|const\s+)?auto\s+(\w+)', line)
                                if m:
                                    rex_w32_names.append(m.group(1))
                    except OSError:
                        pass

    extra_undefs = ['IMAGE_FIRST_SECTION', 'IMAGE_SNAP_BY_ORDINAL64']
    undef_block = '\n'.join('#undef ' + n for n in rex_w32_names + extra_undefs)
    win_inc_stub = os.path.join(win_stub_dir, 'spdlog', 'details', 'windows_include.h')
    with open(win_inc_stub, 'w') as f:
        f.write(
            '#pragma once\n'
            '#ifndef NOMINMAX\n#define NOMINMAX\n#endif\n'
            '#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n'
            '#include <windows.h>\n'
            + undef_block + '\n'
        )

    parse_args = [
        '--target=' + abi['triple'],
        '-x', 'c++',
        '-std=c++23',
        '-fms-compatibility',
        '-fms-extensions',
    ] + list(abi['undefines']) + list(abi['defines']) + [
        '-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',
        '-D_CRT_USE_BUILTIN_OFFSETOF',
        '-DSPDLOG_COMPILED_LIB',
        '-I' + win_stub_dir,
        '-isystem', third_party,
        '-I' + commonlib_include,
    ]

    return parse_args


# ---------------------------------------------------------------------------
# AST text dump parser — enums, base classes, virtual methods
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(r'^([| ]*[|`]-)\s*(.*)')


def _parse_line(line):
    """Extract (depth, content) from an AST dump line.

    Returns (depth, content) or (0, None) if the line is not a tree node.
    """
    m = _LINE_RE.match(line)
    if m:
        return len(m.group(1)) // 2, m.group(2)
    if line and not line[0].isspace() and not line.startswith('|'):
        return 0, line.rstrip()
    return 0, None


def _parse_ast_dump(text, re_include_path, root_ns='RE', category_prefix='/CommonLibSSE',
                    extra_scope_paths=None):
    """Parse clang -ast-dump text output for enums and virtual methods.

    Streams through the text tracking namespace/class nesting via indentation.
    Records types defined under the given include path or any
    ``extra_scope_paths`` — used to capture sibling namespaces (REL, REX, F4SE,
    Scaleform stubs) shipped alongside the main RE include directory.

    Returns:
        enums: dict full_name -> {name, full_name, size, category, values}
        ast_classes: dict full_name -> {name, full_name, bases, has_vtable, vmethods, category}
    """
    enums = {}
    ast_classes = {}
    aliases = {}  # alias_full_name -> canonical_full_name (for `using X = Y;`)

    scope_paths = [re_include_path.replace('\\', '/')]
    for p in (extra_scope_paths or ()):
        if p:
            scope_paths.append(p.replace('\\', '/'))
    re_path_fwd = scope_paths[0]

    # Nesting stack: [(depth, kind, name, in_re)]
    stack = []
    cur_enum = None
    cur_enum_depth = 0
    pending_const_name = None
    last_enum_value = -1

    _ENUM_SIZE = {
        'unsigned char': 1, 'signed char': 1, 'char': 1,
        'unsigned short': 2, 'short': 2,
        'unsigned int': 4, 'int': 4,
        'unsigned long': 4, 'long': 4,
        'unsigned long long': 8, 'long long': 8,
    }

    def _qual_prefix():
        return '::'.join(s[2] for s in stack if s[2])

    def _is_re():
        return any(s[3] for s in stack)

    def _category():
        ns_parts = [s[2] for s in stack if s[1] == 'namespace' and s[2]]
        return category_prefix + '/' + '/'.join(ns_parts) if ns_parts else category_prefix

    def _src_is_re(content):
        m = re.search(r'<([^>]+)>', content)
        if not m:
            return False
        loc = m.group(1).replace('\\', '/')
        return any(p in loc for p in scope_paths)

    for line in text.splitlines():
        depth, content = _parse_line(line)
        if content is None:
            continue

        # Pop stack entries at or deeper than current depth
        while stack and stack[-1][0] >= depth:
            popped = stack.pop()
            if popped[1] == 'enum' and cur_enum and cur_enum_depth >= depth:
                if pending_const_name:
                    last_enum_value += 1
                    cur_enum['values'].append((pending_const_name, last_enum_value))
                    pending_const_name = None
                if cur_enum.get('values') is not None:
                    enums[cur_enum['full_name']] = cur_enum
                cur_enum = None
                cur_enum_depth = 0

        # NamespaceDecl — name is the trailing identifier, but clang appends
        # modifier keywords ``nested`` (for ``namespace A::B {}`` form) and
        # ``inline`` after the name.  Strip those so we read the real name.
        if content.startswith('NamespaceDecl '):
            tokens = content.rstrip().split()
            while tokens and tokens[-1] in ('nested', 'inline'):
                tokens.pop()
            if not tokens:
                continue
            ns_name = tokens[-1]
            if ns_name.startswith('0x') or ns_name in ('C', 'C++'):
                continue
            # ``in_re`` propagates the in-scope flag down so child decls don't
            # need their own file location.  A NamespaceDecl is in scope when:
            #   1. an ancestor was already in scope, OR
            #   2. it's the configured root namespace (``RE`` by default), OR
            #   3. its declaration's file location is under one of the
            #      configured scope paths (covers REL/REX/SKSE/F4SE).
            #   4. it's ``std`` — std-derived user types (std::runtime_error
            #      subclasses, std::function vtables, etc.) need their bases'
            #      virtual-method signatures to generate accurate vtable
            #      structs for the user-facing classes that inherit from them.
            in_re = (_is_re()
                     or ns_name == root_ns
                     or ns_name == 'std'
                     or _src_is_re(content))
            stack.append((depth, 'namespace', ns_name, in_re))
            continue

        # EnumDecl
        if content.startswith('EnumDecl '):
            m = re.search(r"(?:class\s+)?([a-zA-Z_]\w*)\s+'([^']*)'", content)
            if m:
                enum_name = m.group(1)
                underlying = m.group(2)
                # Strip desugared type: 'std::uint32_t':'unsigned int' -> 'unsigned int'
                if ':' in underlying and "'" in underlying:
                    underlying = underlying.split("'")[-1] if "':'" in underlying else underlying
                m2 = re.search(r"'[^']*':'([^']*)'", content)
                if m2:
                    underlying = m2.group(1)
                in_re = _is_re() or _src_is_re(content)
                prefix = _qual_prefix()
                full_name = prefix + '::' + enum_name if prefix else enum_name
                stack.append((depth, 'enum', enum_name, in_re))
                if in_re and enum_name and (full_name not in enums or not enums[full_name]['values']):
                    sz = _ENUM_SIZE.get(underlying, 4)
                    cur_enum = {
                        'name': enum_name,
                        'full_name': full_name,
                        'size': sz,
                        'category': _category(),
                        'values': [],
                    }
                    cur_enum_depth = depth
                    last_enum_value = -1
                    pending_const_name = None
            continue

        # EnumConstantDecl
        if content.startswith('EnumConstantDecl ') and cur_enum:
            if pending_const_name:
                last_enum_value += 1
                cur_enum['values'].append((pending_const_name, last_enum_value))
            m = re.search(r"(\w+)\s+'", content)
            pending_const_name = m.group(1) if m else None
            continue

        # value: Int N
        if pending_const_name and content.startswith('value: Int'):
            m = re.match(r'value:\s+Int\s+(-?\d+)', content)
            if m and cur_enum:
                last_enum_value = int(m.group(1))
                cur_enum['values'].append((pending_const_name, last_enum_value))
            pending_const_name = None
            continue

        # TypeAliasDecl / TypedefDecl - using X = Y;  or  typedef Y X;
        # Format: TypeAliasDecl 0x... <loc> col:N AliasName 'Written':'Canonical'
        # Canonical is what we want to point at.
        if content.startswith('TypeAliasDecl ') or content.startswith('TypedefDecl '):
            m = re.search(r"(?:TypeAliasDecl|TypedefDecl)\s+0x\w+\s+<[^>]*>\s+(?:<[^>]*>\s+)?(?:col:\d+\s+|line:\d+:\d+\s+)?(?:referenced\s+)?(?:implicit\s+)?(\w+)\s+'([^']*)'(?::'([^']*)')?", content)
            if m and _is_re():
                alias_short = m.group(1)
                canonical   = (m.group(3) or m.group(2) or '').strip()
                if alias_short and canonical:
                    prefix = _qual_prefix()
                    alias_full = prefix + '::' + alias_short if prefix else alias_short
                    # Strip clang's noise: leading 'class '/'struct '/'enum ' keywords
                    canonical = _KW_STRIP_RE.sub('', canonical).strip()
                    canonical = _CV_STRIP_RE.sub(' ', canonical).strip()
                    canonical = re.sub(r'\s+', ' ', canonical)
                    # Skip pointer/array typedefs — they don't help with struct resolution
                    if canonical and not canonical.endswith(('*', '&')):
                        # Qualify template args so the canonical form matches struct keys
                        canonical = _qualify_type(canonical, root_ns)
                        if canonical != alias_full:
                            aliases[alias_full] = canonical
            continue

        # CXXRecordDecl (class/struct definition)
        if content.startswith('CXXRecordDecl ') and content.endswith('definition'):
            m = re.search(r'(class|struct|union)\s+(\w+)\s+definition', content)
            if m:
                record_kind = m.group(1)
                class_name = m.group(2)
                in_re = _is_re() or _src_is_re(content)
                prefix = _qual_prefix()
                full_name = prefix + '::' + class_name if prefix else class_name
                stack.append((depth, 'class', class_name, in_re))
                if in_re and class_name and full_name not in ast_classes:
                    ast_classes[full_name] = {
                        'name': class_name,
                        'full_name': full_name,
                        'record_kind': record_kind,
                        'bases': [],
                        'has_vtable': False,
                        'vmethods': {},
                        'methods': {},
                        'category': _category(),
                    }
            continue

        # Base class specifier
        if content.startswith(('public ', 'private ', 'protected ')) and "'" in content:
            m = re.match(r"(?:public|private|protected)\s+'([^']+)'(?::'([^']*)')?", content)
            if m:
                for s in reversed(stack):
                    if s[1] == 'class':
                        qn = _qual_prefix() + '::' + s[2] if _qual_prefix().endswith(s[2]) else '::'.join(ss[2] for ss in stack if ss[2])
                        # Reconstruct full name from stack
                        parts = [ss[2] for ss in stack if ss[1] in ('namespace', 'class') and ss[2]]
                        fn = '::'.join(parts)
                        if fn in ast_classes:
                            base_name = m.group(2) or m.group(1)
                            ast_classes[fn]['bases'].append(base_name)
                        break
            continue

        # Method declarations (virtual and non-virtual)
        if content.startswith('CXXMethodDecl '):
            is_virtual = ' virtual' in content
            m = re.search(r"(operator\(\)|operator\w*|\w+)\s+'([^']+)'", content)
            if m:
                method_name = m.group(1)
                method_sig = m.group(2)
                parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
                fn = '::'.join(parts)
                if fn in ast_classes:
                    cls = ast_classes[fn]
                    if method_name and '<' not in method_name:
                        ret, params = _parse_method_sig(method_sig, root_ns)
                        if is_virtual:
                            cls['has_vtable'] = True
                            existing = cls['vmethods'].get(method_name)
                            if existing is None:
                                cls['vmethods'][method_name] = (ret, params)
                            elif existing != (ret, params):
                                # Distinct C++ overload sharing the leaf name
                                # gets its own vtable slot.  Disambiguate the
                                # vmethods key by appending an index so the
                                # downstream slot count matches the binary's
                                # vtable layout — without this every overloaded
                                # base virtual shifts subsequent slots one
                                # earlier than the binary.  The alias is
                                # stripped back to the leaf name when emitting
                                # the slot label in _compute_vfuncs.
                                idx = 2
                                while (method_name + '__overload_' + str(idx)) in cls['vmethods']:
                                    idx += 1
                                cls['vmethods'][method_name + '__overload_' + str(idx)] = (ret, params)
                                cls.setdefault('_overload_aliases', {})[
                                    method_name + '__overload_' + str(idx)] = method_name
                        if method_name not in cls['methods']:
                            is_static = ' static' in content
                            cls['methods'][method_name] = (ret, params, is_static)
            continue

        # Constructor declarations
        if content.startswith('CXXConstructorDecl ') and ' implicit ' not in content:
            m = re.search(r"(\w+)\s+'([^']+)'", content)
            if m:
                ctor_name = m.group(1)
                ctor_sig = m.group(2)
                parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
                fn = '::'.join(parts)
                if fn in ast_classes:
                    cls = ast_classes[fn]
                    if ctor_name == cls['name'] and ctor_name not in cls['methods']:
                        _ret, params = _parse_method_sig(ctor_sig, root_ns)
                        cls['methods'][ctor_name] = ('void', params, False)
            continue

        # Free function declarations in namespaces (stored as pseudo-class methods)
        if content.startswith('FunctionDecl ') and ' implicit ' not in content and _is_re():
            m = re.search(r"(operator\(\)|operator\w*|\w+)\s+'([^']+)'", content)
            if m:
                func_name = m.group(1)
                func_sig = m.group(2)
                ns_parts = [s[2] for s in stack if s[1] == 'namespace' and s[2]]
                fn = '::'.join(ns_parts)
                if fn and fn not in ast_classes:
                    short_name = ns_parts[-1] if ns_parts else fn
                    ast_classes[fn] = {
                        'name': short_name,
                        'full_name': fn,
                        'record_kind': 'namespace',
                        'bases': [],
                        'has_vtable': False,
                        'vmethods': {},
                        'methods': {},
                        'category': _category(),
                    }
                if fn and fn in ast_classes and func_name and '<' not in func_name:
                    cls = ast_classes[fn]
                    if func_name not in cls['methods']:
                        ret, params = _parse_method_sig(func_sig, root_ns)
                        is_static = ' static' in content
                        cls['methods'][func_name] = (ret, params, is_static)
            continue

        # Virtual destructor
        if content.startswith('CXXDestructorDecl ') and ' virtual' in content:
            parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
            fn = '::'.join(parts)
            if fn in ast_classes:
                cls = ast_classes[fn]
                cls['has_vtable'] = True
                dtor_name = '~' + cls['name']
                if dtor_name not in cls['vmethods']:
                    cls['vmethods'][dtor_name] = ('void', [])
            continue

    if cur_enum and cur_enum.get('values') is not None:
        if pending_const_name:
            last_enum_value += 1
            cur_enum['values'].append((pending_const_name, last_enum_value))
        enums[cur_enum['full_name']] = cur_enum

    return enums, ast_classes, aliases


def _parse_method_sig(sig, root_ns='RE'):
    """Parse 'ReturnType (ParamTypes) const' into (ret_str, [(name, type_str)])."""
    sig = sig.strip()
    sig = re.sub(r'\)\s*(?:const|noexcept|override|\s)+$', ')', sig)
    m = re.match(r'^(.+?)\s*\(([^)]*)\)\s*$', sig)
    if not m:
        return 'void', []
    ret_raw = m.group(1).strip()
    params_raw = m.group(2).strip()
    ret = _record_type_to_pipeline(ret_raw, root_ns)
    params = []
    if params_raw and params_raw != 'void':
        for i, p in enumerate(params_raw.split(',')):
            p = p.strip()
            ptype = _record_type_to_pipeline(p, root_ns)
            params.append(('p{}'.format(i), ptype))
    return ret, params


# ---------------------------------------------------------------------------
# Record layout parser
# ---------------------------------------------------------------------------

def _parse_layouts_with_bases(text, root_ns='RE', pointer_size=8):
    """Parse -fdump-record-layouts-complete output.

    Returns:
        layouts: dict type_name -> {size, fields, bases, has_vtable}
    """
    results = {}

    for block in re.split(r'\*\*\* Dumping AST Record Layout', text)[1:]:
        m_sz = re.search(r'\[sizeof=(\d+)', block)
        if not m_sz:
            continue
        sizeof_bytes = int(m_sz.group(1))

        type_name = ''
        record_kind = 'struct'
        fields = []
        bases = []
        has_vtable = False
        first_seen = False
        value_field_indents = []

        for line in block.splitlines():
            line_r = line.rstrip()
            if not line_r or line_r.lstrip().startswith('['):
                continue
            bar = line_r.find('|')
            if bar < 0:
                continue
            rest = line_r[bar + 1:]
            indent = len(rest) - len(rest.lstrip())
            content = rest.strip()
            if not content:
                continue

            # Pop value-field frames
            while value_field_indents and indent <= value_field_indents[-1]:
                value_field_indents.pop()

            if value_field_indents:
                continue

            # Record header
            if not first_seen and indent == 1:
                m_rec = re.match(r'(class|struct|union)\s+(.+?)\s*$', content)
                if m_rec:
                    first_seen = True
                    record_kind = m_rec.group(1)
                    raw_name = _KW_STRIP_RE.sub('', m_rec.group(2)).strip()
                    raw_name = re.sub(r'\s*\(empty\)\s*$', '', raw_name)
                    type_name = _qualify_type(raw_name, root_ns)
                continue

            # Base class
            if '(base)' in content or '(primary base)' in content:
                m_off = re.match(r'^\s*(\d+)\s+\|', line_r)
                if m_off:
                    base_off = int(m_off.group(1))
                    m_base = re.match(r'^(?:class|struct)\s+(.+?)\s+\((?:primary )?base\)', content)
                    if m_base:
                        bname = _qualify_type(
                            _KW_STRIP_RE.sub('', m_base.group(1)).strip(), root_ns)
                        bases.append((bname, base_off))
                continue

            if '(empty)' in content:
                continue

            # Vtable pointer
            if 'vftable pointer' in content or 'vbtable pointer' in content:
                has_vtable = True
                continue

            # Field — plain offset (e.g. "  0 |") or bitfield ("0:0-7 |")
            m_off = re.match(r'^\s*(\d+)\s+\|', line_r)
            m_bf = None
            if not m_off:
                m_bf = re.match(r'^\s*(\d+):(\d+)-(\d+)\s+\|', line_r)
                if not m_bf:
                    continue

            if m_bf:
                bf_byte = int(m_bf.group(1))
                bf_bit_start = int(m_bf.group(2))
                bf_bit_end = int(m_bf.group(3))
                bf_width = bf_bit_end - bf_bit_start + 1
                m_tn = re.match(
                    r'^(?:(?:class|struct|union|enum)\s+)?(.+?)\s+(\w+)\s*$', content)
                if not m_tn:
                    continue
                fname = m_tn.group(2)
                bf_bit_offset = bf_byte * 8 + bf_bit_start
                fields.append({
                    'name': fname,
                    'offset': bf_byte,
                    'size': 0,
                    'type': '',
                    '_bf_bit_offset': bf_bit_offset,
                    '_bf_width': bf_width,
                })
                continue

            is_record_field = bool(re.match(r'^(?:class|struct|union)\s+', content))

            m_tn = re.match(
                r'^(?:(?:class|struct|union|enum)\s+)?(.+?)\s+(\w+)\s*$', content)
            if not m_tn:
                continue
            ftype_raw = m_tn.group(1).strip()
            fname = m_tn.group(2)
            if fname.startswith('_vptr') or fname == '':
                continue

            fields.append({
                'name': fname,
                'offset': int(m_off.group(1)),
                'size': 0,
                'type': _record_type_to_pipeline(ftype_raw, root_ns),
            })

            if is_record_field:
                value_field_indents.append(indent)

        if type_name:
            non_bf_fields = [f for f in fields if '_bf_bit_offset' not in f]
            _backfill_sizes(non_bf_fields, sizeof_bytes,
                            record_kind=record_kind, pointer_size=pointer_size)
            for f in fields:
                if '_bf_bit_offset' in f:
                    f['type'] = 'bf:{}:{}'.format(f.pop('_bf_bit_offset'), f.pop('_bf_width'))
                    f['size'] = 0
            results[type_name] = {
                'size': sizeof_bytes,
                'fields': fields,
                'bases': bases,
                'has_vtable': has_vtable,
                'record_kind': record_kind,
            }

    return results



def _backfill_sizes(fields, total_size, record_kind='struct', pointer_size=8):
    _NATURAL = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': pointer_size, 'usize': pointer_size, 'isize': pointer_size,
    }
    for i, f in enumerate(fields):
        if record_kind == 'union':
            natural = _NATURAL.get(f.get('type', ''), 0)
            f['size'] = natural or total_size
            continue
        next_off = fields[i + 1]['offset'] if i + 1 < len(fields) else total_size
        computed = max(next_off - f['offset'], 0)
        natural = _NATURAL.get(f.get('type', ''), 0)
        if natural and natural < computed:
            f['size'] = natural
        else:
            f['size'] = computed


def _split_ns(qualified):
    """Split a qualified C++ name on :: boundaries, respecting template <> nesting."""
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(qualified):
        c = qualified[i]
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ':' and depth == 0 and i + 1 < len(qualified) and qualified[i + 1] == ':':
            parts.append(qualified[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(qualified[start:])
    return parts


def _short_name(qualified):
    """Get the unqualified (short) name from a qualified C++ name."""
    return _split_ns(qualified)[-1]


def _ns_parts(qualified):
    """Get the namespace parts (everything except the final name)."""
    parts = _split_ns(qualified)
    return parts[:-1] if len(parts) > 1 else []


# ---------------------------------------------------------------------------
# Merge AST + layout data into unified struct descriptors
# ---------------------------------------------------------------------------

def _merge_ast_and_layouts(ast_classes, layouts, re_include_path,
                           root_ns='RE', category_prefix='/CommonLibSSE'):
    """Merge AST class metadata with record layout data.

    Returns structs dict: full_name -> {name, full_name, size, category,
                                        fields, bases, has_vtable, vmethods}
    """
    structs = {}
    re_path_fwd = re_include_path.replace('\\', '/')

    # Index layouts by short name for matching
    layouts_by_short = {}
    for lname, ldata in layouts.items():
        short = _short_name(lname) if '::' in lname else lname
        lt = short.find('<')
        base_short = short[:lt] if lt >= 0 else short
        layouts_by_short.setdefault(base_short, []).append((lname, ldata))

    # Process AST classes — merge with layout data
    ns_prefix = (root_ns + '::') if root_ns else ''
    for full_name, ast in ast_classes.items():
        layout = layouts.get(full_name)
        if not layout and ns_prefix:
            layout = layouts.get(ns_prefix + full_name)
        if not layout:
            short_candidates = layouts_by_short.get(ast['name'], [])
            if len(short_candidates) == 1:
                layout = short_candidates[0][1]

        key = full_name

        if layout:
            bases = []
            for bname, boff in layout['bases']:
                bases.append(bname)

            structs[key] = {
                'name': ast['name'],
                'full_name': key,
                'record_kind': layout.get('record_kind', ast.get('record_kind', 'struct')),
                'size': layout['size'],
                'category': ast['category'],
                'fields': layout['fields'],
                'bases': bases,
                'pdb_bases': layout['bases'],
                'has_vtable': layout['has_vtable'] or ast['has_vtable'],
                'vmethods': ast.get('vmethods', {}),
                'methods': ast.get('methods', {}),
                '_overload_aliases': dict(ast.get('_overload_aliases', {})),
            }
        else:
            structs[key] = {
                'name': ast['name'],
                'full_name': key,
                'record_kind': ast.get('record_kind', 'struct'),
                'size': 0,
                'category': ast['category'],
                'fields': [],
                'bases': ast['bases'],
                'has_vtable': ast['has_vtable'],
                'vmethods': ast.get('vmethods', {}),
                'methods': ast.get('methods', {}),
                '_overload_aliases': dict(ast.get('_overload_aliases', {})),
            }

    # Add layout-only types (templates, types not in AST class list)
    for lname, ldata in layouts.items():
        if lname in structs:
            continue

        short = _short_name(lname)

        bases = [bname for bname, _ in ldata['bases']]

        ns_parts = _ns_parts(lname)
        category = category_prefix + '/' + '/'.join(ns_parts) if ns_parts else category_prefix

        # Template instantiations (T<args>) lose their vmethods/methods because
        # the AST records them on the template definition (T) keyed without
        # angle brackets.  Look up the definition by stripping <args> at the
        # outermost level and copy method dictionaries forward so vtable-struct
        # generation and signature application work for instantiations too.
        vmethods = {}
        methods  = {}
        aliases  = {}
        has_vtbl = ldata['has_vtable']
        if '<' in lname:
            tmpl_base = _strip_outer_template(lname)
            tmpl_def  = ast_classes.get(tmpl_base)
            if tmpl_def is None and tmpl_base.startswith(ns_prefix):
                tmpl_def = ast_classes.get(tmpl_base[len(ns_prefix):])
            if tmpl_def:
                vmethods = dict(tmpl_def.get('vmethods', {}))
                methods  = dict(tmpl_def.get('methods',  {}))
                aliases  = dict(tmpl_def.get('_overload_aliases', {}))
                has_vtbl = has_vtbl or tmpl_def.get('has_vtable', False)

        structs[lname] = {
            'name': short,
            'full_name': lname,
            'record_kind': ldata.get('record_kind', 'struct'),
            'size': ldata['size'],
            'category': category,
            'fields': ldata['fields'],
            'bases': bases,
            'pdb_bases': ldata['bases'],
            'has_vtable': has_vtbl,
            'vmethods': vmethods,
            'methods':  methods,
            '_overload_aliases': aliases,
        }

    return structs


def _strip_outer_template(name):
    """Drop the outermost ``<...>`` cluster from a fully-qualified type name.

    ``RE::BSTEventSink<RE::Foo>``                  -> ``RE::BSTEventSink``
    ``std::optional<RE::BSTArray<int>>::_Storage`` -> unchanged (the ``<>`` is
        not at the tail, so the outer template is not what we want to peel)
    """
    if '<' not in name:
        return name
    # Only strip when the angle bracket cluster covers the tail (or up to '::')
    depth = 0
    open_idx = -1
    for i, ch in enumerate(name):
        if ch == '<':
            if depth == 0 and open_idx < 0:
                open_idx = i
            depth += 1
        elif ch == '>':
            depth -= 1
            if depth == 0 and i == len(name) - 1:
                return name[:open_idx]
    return name


# ---------------------------------------------------------------------------
# Vtable slot computation
# ---------------------------------------------------------------------------

def _compute_vfuncs(structs, root_ns='RE'):
    slot_cache = {}
    vmname_cache = {}
    ns_prefix = (root_ns + '::') if root_ns else ''

    def resolve(name):
        st = structs.get(name)
        if st:
            return st
        if name.startswith(ns_prefix):
            st = structs.get(name[len(ns_prefix):])
            if st:
                return st
        if '<' not in name:
            return structs.get(name.split('::')[-1])
        return None

    def all_vmethod_names(full_name, depth=0):
        if depth > 30:
            return frozenset()
        if full_name in vmname_cache:
            return vmname_cache[full_name]
        vmname_cache[full_name] = frozenset()
        st = structs.get(full_name)
        if not st:
            return frozenset()
        result = set(st.get('vmethods', {}).keys())
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                result |= all_vmethod_names(bs['full_name'], depth + 1)
            break
        frozen = frozenset(result)
        vmname_cache[full_name] = frozen
        return frozen

    def total_slots(full_name, depth=0):
        if depth > 30:
            return 0
        if full_name in slot_cache:
            return slot_cache[full_name]
        slot_cache[full_name] = 0
        st = structs.get(full_name)
        if not st:
            return 0
        base_count = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                base_count = total_slots(bs['full_name'], depth + 1)
            break
        primary_base_names = frozenset()
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                primary_base_names = all_vmethod_names(bs['full_name'])
            break
        own_intro = sum(1 for n in st.get('vmethods', {}) if n not in primary_base_names)
        result = base_count + own_intro
        slot_cache[full_name] = result
        return result

    count = 0
    for st in structs.values():
        if not st.get('has_vtable'):
            continue
        # Don't clobber vfuncs that came from clang -fdump-vtable-layouts —
        # those are exact and AST-derived counts can disagree with them
        # (e.g. when AST double-counts an inline destructor).
        if st.get('_vfuncs_from_dump'):
            continue
        primary_base_names = frozenset()
        base_start = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                primary_base_names = all_vmethod_names(bs['full_name'])
                base_start = total_slots(bs['full_name'])
            break
        intro = [n for n in st.get('vmethods', {}) if n not in primary_base_names]
        if not intro:
            continue
        # Strip overload-disambiguation suffixes (Name__overload_N) before
        # emitting slot labels.  The alias only exists so the vtable slot
        # count matches the binary; the user-visible name is the leaf name.
        aliases = st.get('_overload_aliases', {})
        st['vfuncs'] = [
            (aliases.get(mname, mname), (base_start + i) * 8)
            for i, mname in enumerate(intro)
        ]
        count += 1

    print('Computed vtable slots for {} structs from AST'.format(count))


def _tmpl_base(name):
    """Extract template base name: 'RE::NiPointer<RE::Actor>' -> 'RE::NiPointer'."""
    lt = name.find('<')
    return name[:lt] if lt >= 0 else None


def _generalize_field(f):
    """Copy a field dict, replacing type-specific pointer types with generic ptr."""
    f = dict(f)
    t = f['type']
    if t.startswith('ptr:struct:') or t.startswith('ptr:enum:'):
        f['type'] = 'ptr'
    elif t.startswith('struct:') and f['size'] == 8:
        pass
    return f


def _tmpl_args_of(name):
    """Return the outermost template argument list of ``name`` as a list of
    qualified type strings, or ``None`` if ``name`` is not a template
    instantiation.

    ``RE::BSTArray<RE::Actor *, RE::BSTSmallArrayHeapAllocator<8>>``
        -> [``RE::Actor *``, ``RE::BSTSmallArrayHeapAllocator<8>``]
    """
    if '<' not in name or not name.endswith('>'):
        return None
    lt = name.find('<')
    inner = name[lt + 1:-1]
    return _split_tmpl_args(inner)


_DESC_TYPE_ARG_RE = re.compile(r'(?<![A-Za-z0-9_:])([A-Za-z_][\w:]*(?:<[^<>]*>)?)(?![A-Za-z0-9_])')


def _substitute_template_args(desc, donor_args, recipient_args):
    """Rewrite a pipeline descriptor produced for ``donor_args`` so it refers
    to ``recipient_args`` instead.

    Used by template-layout propagation: when ``BSTArray<int>`` lends its
    layout to the empty placeholder ``BSTArray<float>``, every occurrence of
    ``int`` inside the field type strings should become ``float``, etc.
    The substitution is bounded to whole-token matches (no partial matches
    inside longer identifiers).
    """
    if not desc or len(donor_args) != len(recipient_args):
        return desc
    # Apply the longest tokens first so a substring of one arg cannot match
    # before the longer arg containing it gets rewritten.
    pairs = sorted(zip(donor_args, recipient_args), key=lambda p: -len(p[0]))
    out = desc
    for d, r in pairs:
        if d == r or not d:
            continue
        # Whole-token replacement: don't match in the middle of an identifier
        # or as a sub-element of a qualified path.
        pattern = r'(?<![A-Za-z0-9_:])' + re.escape(d) + r'(?![A-Za-z0-9_:])'
        out = re.sub(pattern, r, out)
    return out


def _retype_field_for_instantiation(f, donor_args, recipient_args):
    """Copy a donor field, substituting donor template args -> recipient
    template args inside the type descriptor.  Falls back to the original
    generalisation behaviour for fields whose type doesn't reference any
    template parameter (so multi-instantiation propagation stays sound).
    """
    f = dict(f)
    new_type = _substitute_template_args(f.get('type', ''),
                                         donor_args, recipient_args)
    if new_type != f.get('type'):
        f['type'] = new_type
    else:
        # Type didn't reference any template argument — generalise to keep
        # the original behaviour (e.g. ``int* _data`` in BSTArray<int> stays
        # generic when propagated to BSTArray<float>).
        f = _generalize_field(f)
    return f


def _retype_base_for_instantiation(base_name, donor_args, recipient_args):
    """Substitute template args in a base-class name string."""
    return _substitute_template_args(base_name, donor_args, recipient_args)


_TEMPLATE_NAME_BAD = re.compile(r'(?:^|::)\d')          # e.g. 'RE::8'
_ANGLE_INNER       = re.compile(r'<[^<>]*>')


def _is_safe_template_name(name: str) -> bool:
    """Reject obviously malformed template names that would fail to compile.

    Drops names like ``Allocator<24, RE::8>`` where a qualified path component
    starts with a digit, or names containing illegal substrings (anonymous
    structs, lambda mangles, etc.).
    """
    if any(s in name for s in ('(unnamed', '$', '(anonymous', '(lambda')):
        return False
    # Strip innermost template args and check qualified-name segments
    stripped = name
    while True:
        new_stripped = _ANGLE_INNER.sub('', stripped)
        if new_stripped == stripped:
            break
        stripped = new_stripped
    if _TEMPLATE_NAME_BAD.search(stripped):
        return False
    return True


def _resolve_aliases_in_descriptor(desc: str, alias_map, class_scope=None) -> str:
    """Rewrite a pipeline type descriptor by following alias chains.

    Handles ``struct:NAME`` (and pointer/array wrappers) by replacing NAME
    with the canonical form when ``NAME`` appears in ``alias_map``.  Follows
    chains (alias -> alias -> canonical) up to a depth limit.

    When ``class_scope`` is provided, the resolver also tries
    ``<class_scope>::<short>`` as a candidate key — this catches class-local
    ``using X = Y;`` declarations whose short name escapes into method/field
    descriptors without the class prefix.
    """
    if not desc or not alias_map:
        return desc
    if desc.startswith('ptr:'):
        inner = _resolve_aliases_in_descriptor(desc[4:], alias_map, class_scope)
        return 'ptr:' + inner if inner != desc[4:] else desc
    if desc.startswith('arr:'):
        rest = desc[4:]
        last = rest.rfind(':')
        if last < 0 or not rest[last + 1:].isdigit():
            return desc
        inner = _resolve_aliases_in_descriptor(rest[:last], alias_map, class_scope)
        return 'arr:{}:{}'.format(inner, rest[last + 1:])
    if desc.startswith('struct:') or desc.startswith('enum:'):
        prefix, name = desc.split(':', 1)
        # Try class-scope-qualified form first, so a method on RE::Foo that
        # mentions a typedef declared in RE::Foo (which the AST emitted as
        # `RE::TypedefName`) can hit the alias key `RE::Foo::TypedefName`.
        if class_scope:
            short = name.split('::')[-1]
            scoped = class_scope + '::' + short
            if scoped in alias_map and scoped != name:
                name = scoped
        seen = set()
        while name in alias_map and name not in seen:
            seen.add(name)
            name = alias_map[name]
        return prefix + ':' + name
    return desc


def _apply_aliases_to_structs(structs, alias_map, verbose=False):
    """Walk every type descriptor in structs and apply alias resolution.

    Each struct's own ``full_name`` is passed as the resolver's ``class_scope``
    so class-local typedefs resolve correctly when their short name leaks into
    the AST sig of one of that class's own methods.
    """
    if not alias_map:
        return 0
    rewrites = 0
    for st in structs.values():
        cls = st.get('full_name')
        # Field types
        for f in st.get('fields', []):
            t0 = f.get('type', '')
            t1 = _resolve_aliases_in_descriptor(t0, alias_map, class_scope=cls)
            if t1 != t0:
                f['type'] = t1
                rewrites += 1
        # vmethods: { name: (ret, params) }
        for mname, info in list(st.get('vmethods', {}).items()):
            ret, params = info
            new_ret    = _resolve_aliases_in_descriptor(ret, alias_map, class_scope=cls)
            new_params = [(pn, _resolve_aliases_in_descriptor(pt, alias_map, class_scope=cls))
                          for pn, pt in params]
            if new_ret != ret or new_params != params:
                st['vmethods'][mname] = (new_ret, new_params)
                rewrites += 1
        # methods: { name: (ret, params, is_static) }
        for mname, info in list(st.get('methods', {}).items()):
            ret, params, is_static = info
            new_ret    = _resolve_aliases_in_descriptor(ret, alias_map, class_scope=cls)
            new_params = [(pn, _resolve_aliases_in_descriptor(pt, alias_map, class_scope=cls))
                          for pn, pt in params]
            if new_ret != ret or new_params != params:
                st['methods'][mname] = (new_ret, new_params, is_static)
                rewrites += 1
    if verbose and rewrites:
        print('Resolved {} type-alias references via {} aliases'.format(rewrites, len(alias_map)))
    return rewrites


_VTABLE_BAD_METHOD_PREFIX = ('~',)
_OPERATOR_RE = re.compile(r'^operator\b')


def _pick_virtual_method_for_addr(structs, full_name, root_ns, depth=0):
    """Pick any visible virtual method name on a class that should be safe to
    write as ``&Class::Method`` in synthetic source.

    Skips destructors, operators, and names with non-identifier characters.
    Walks the primary inheritance chain when the class itself only overrides.
    """
    if depth > 30:
        return None
    st = structs.get(full_name)
    if not st:
        return None
    for vm in st.get('vmethods', {}):
        if vm.startswith(_VTABLE_BAD_METHOD_PREFIX):
            continue
        if _OPERATOR_RE.match(vm):
            continue
        if not vm.replace('_', '').isalnum():
            continue
        return vm
    for base in st.get('bases', []):
        bs = structs.get(base)
        if not bs and root_ns:
            bs = structs.get(root_ns + '::' + base)
        if bs:
            r = _pick_virtual_method_for_addr(structs, bs['full_name'], root_ns, depth + 1)
            if r:
                return r
        break  # only primary base
    return None


def _extract_vtable_method_name(sig: str):
    """Extract the bare method name from a clang-vtable signature.

    e.g. ``"void RE::Foo::Bar() const"`` -> ``"Bar"``
         ``"RE::Foo::~Foo() [vector deleting]"`` -> ``"~Foo"``
    """
    if not sig:
        return None
    sig = re.sub(r'\s*\[(?:vector deleting|scalar deleting|pure)\]\s*$', '', sig).strip()
    paren = sig.find('(')
    if paren < 0:
        return None
    head = sig[:paren].strip()
    tail = head.split('::')[-1].strip()
    if tail.startswith('operator'):
        return tail
    if tail.startswith('~'):
        return tail
    m = re.match(r'(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)$', tail)
    if m:
        return m.group(1)
    return None


def _parse_vtable_dump(text, root_ns):
    """Parse clang ``-fdump-vtable-layouts`` text into per-class slot maps.

    Returns ``(primary_layouts, secondary_layouts)``:

      primary_layouts:   ``{full_name: [(func_slot, method_name), ...]}``
                         from ``VFTable indices for 'X'`` blocks (slot indices
                         match the function-slot scheme: 0 = dtor).

      secondary_layouts: ``{(full_name, subobject_offset): [(func_slot, method_name), ...]}``
                         derived from ``VFTable for 'B' in 'C'`` blocks whose
                         ``[this adjustment: -N non-virtual]`` annotations show
                         the B subobject lives at offset ``N`` in C. Slot
                         indices already in function-slot space (RTTI dropped).
    """
    primary = {}
    secondary = {}

    for_re     = re.compile(r"^VFTable for '([^']+)'((?:\s+in\s+'[^']+')*)\s*\(")
    in_re      = re.compile(r"\s+in\s+'([^']+)'")
    indices_re = re.compile(r"^VFTable indices for '([^']+)'")
    slot_re    = re.compile(r"^\s*(\d+)\s*\|\s*(.+?)\s*$")
    adj_re     = re.compile(r'\[this adjustment:\s*(-?\d+)\s+non-virtual\]')

    state           = None     # 'indices' | 'full_block' | None
    cur_class       = None
    cur_full_class  = None
    cur_subobj_off  = 0
    cur_slots       = []

    def flush_secondary():
        nonlocal cur_full_class, cur_subobj_off, cur_slots
        if cur_full_class and cur_subobj_off > 0 and cur_slots:
            key = (cur_full_class, cur_subobj_off)
            # Multiple 'in' chains can produce blocks for the same (C, offset);
            # keep the longest (most informative) one.
            if key not in secondary or len(cur_slots) > len(secondary[key]):
                secondary[key] = list(cur_slots)
        cur_full_class = None
        cur_subobj_off = 0
        cur_slots = []

    def reset():
        nonlocal state, cur_class
        if state == 'full_block':
            flush_secondary()
        state = None
        cur_class = None

    for ln in text.splitlines():
        if not ln.strip():
            reset()
            continue

        m_idx = indices_re.match(ln)
        if m_idx:
            reset()
            cur_class = m_idx.group(1)
            primary.setdefault(cur_class, [])
            state = 'indices'
            continue

        m_for = for_re.match(ln)
        if m_for:
            reset()
            ins = in_re.findall(m_for.group(2))
            if ins:
                cur_full_class = ins[-1]
                cur_subobj_off = 0
                cur_slots = []
                state = 'full_block'
            else:
                state = None
            continue

        if state == 'indices':
            if ln.lstrip().startswith(('--', '[')):
                continue
            m_slot = slot_re.match(ln)
            if not m_slot:
                continue
            sig = m_slot.group(2)
            if sig.startswith('[') or 'this adjustment' in sig:
                continue
            name = _extract_vtable_method_name(sig)
            if name and cur_class:
                primary[cur_class].append((int(m_slot.group(1)), name))
            continue

        if state == 'full_block':
            m_adj = adj_re.search(ln)
            if m_adj:
                adj = int(m_adj.group(1))
                if adj < 0:
                    cur_subobj_off = max(cur_subobj_off, -adj)
                continue
            m_slot = slot_re.match(ln)
            if m_slot:
                idx = int(m_slot.group(1))
                if idx == 0:
                    # RTTI marker line; skip
                    continue
                sig = m_slot.group(2)
                if sig.endswith('RTTI'):
                    continue
                name = _extract_vtable_method_name(sig)
                if name:
                    cur_slots.append((idx - 1, name))  # function-slot index
            continue

    if state == 'full_block':
        flush_secondary()

    return primary, secondary


def _dump_vtable_layouts(structs, header_path, parse_args, clang_binary,
                        root_ns, verbose=False):
    """Generic clang ``-fdump-vtable-layouts`` enrichment pass.

    For every polymorphic class in ``structs`` (root namespace only), pick any
    virtual method from AST data and emit ``auto u<N> = &Class::Method;`` in a
    synthetic source.  A two-stage compile (``-fsyntax-only`` filter, then
    ``-S -emit-llvm`` with ``-fdump-vtable-layouts``) yields exact slot
    indices for the classes whose method addresses survive front-end checking.

    The address-of-virtual-member trick avoids destructor instantiation, which
    is what makes simpler approaches (``delete t``, ``t->~T()``) fail on
    classes with smart-pointer members of forward-declared types.

    Returns dict ``full_name -> [(slot_index, method_name)]``.  Empty when no
    candidates could be found or when clang produced no output.
    """
    import tempfile

    template_defs = set()
    for k in structs:
        if '<' in k:
            template_defs.add(k.split('<', 1)[0])

    ns_pre = (root_ns + '::') if root_ns else ''
    candidates = []  # (cls_full, method_name)
    for k, s in structs.items():
        if not s.get('has_vtable'):
            continue
        if '<' in k:
            continue
        if not k.startswith(ns_pre):
            continue
        if k in template_defs:
            continue
        m = _pick_virtual_method_for_addr(structs, k, root_ns)
        if m:
            candidates.append((k, m))

    if not candidates:
        return {}, {}

    header_fwd = header_path.replace('\\', '/')
    tmp_dir = tempfile.mkdtemp(prefix='ghidra_vt_dump_')
    spath_dry   = os.path.join(tmp_dir, 'force_vt_dry.cpp')
    spath_clean = os.path.join(tmp_dir, 'force_vt_clean.cpp')

    def _emit(items):
        lines = ['#include "{}"'.format(header_fwd),
                 'namespace __force_vt_dump {']
        for i, (cls, m) in enumerate(items):
            lines.append('    auto u{} = &{}::{};'.format(i, cls, m))
        lines.append('}')
        return '\n'.join(lines) + '\n'

    try:
        # Stage 1: dry-run with -fsyntax-only to identify bad declarations
        with open(spath_dry, 'w', encoding='utf-8') as f:
            f.write(_emit(candidates))
        cmd_dry = [clang_binary, '-fsyntax-only', '-ferror-limit=0'] + parse_args + [spath_dry]
        if verbose:
            print('Pass 4: dry-run vtable dump candidates ({} classes)...'.format(len(candidates)))
        r_dry = subprocess.run(cmd_dry, capture_output=True, text=True,
                               encoding='utf-8', errors='replace')
        bad_lines = set()
        err_re = re.compile(re.escape(spath_dry) + r':(\d+):\d+:\s+error:')
        for ln in r_dry.stderr.splitlines():
            m = err_re.search(ln)
            if m:
                bad_lines.add(int(m.group(1)))
        # Header is 2 lines, decl idx 0 -> source line 3.
        cleaned = [(c, m) for i, (c, m) in enumerate(candidates) if (i + 3) not in bad_lines]
        if verbose:
            print('  filtered {} bad address-takes; {} candidates remain'.format(
                len(candidates) - len(cleaned), len(cleaned)))
        if not cleaned:
            return {}, {}

        # Stage 2: emit-llvm with vtable layout dump
        with open(spath_clean, 'w', encoding='utf-8') as f:
            f.write(_emit(cleaned))
        cmd = [clang_binary, '-S', '-emit-llvm', '-o', os.devnull,
               '-Xclang', '-fdump-vtable-layouts',
               '-ferror-limit=0'] + parse_args + [spath_clean]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        # -ferror-limit=0 codegen: residual instantiation errors do not
        # invalidate the vtable layouts clang did emit; gate on empty output
        # rather than exit status.
        if r.returncode != 0 and not r.stdout.strip():
            if verbose:
                print('  clang vtable codegen produced no output '
                      '(exit {}); skipping'.format(r.returncode))
            return {}, {}
    finally:
        for p in (spath_dry, spath_clean):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass

    primary_layouts, secondary_layouts = _parse_vtable_dump(r.stdout, root_ns)
    if verbose:
        print('  parsed clang vtable indices for {} classes ({} secondary blocks)'.format(
            len(primary_layouts), len(secondary_layouts)))
    return primary_layouts, secondary_layouts


def _apply_vtable_dump(structs, vtable_layouts, root_ns, verbose=False):
    """Replace AST-computed ``vfuncs`` with clang-dump slot data when available.

    For each class with a clang-dump entry, ``vfuncs`` is rewritten to the
    list of own-method slots (filtering out destructor and inherited entries
    by intersecting with the class's own ``vmethods`` set), with byte offsets
    computed as ``slot_index * 8``.

    Classes without a clang-dump entry are left alone — the AST-based
    ``_compute_vfuncs`` result remains in place.
    """
    if not vtable_layouts:
        return 0
    replaced = 0
    for cls, slots in vtable_layouts.items():
        st = structs.get(cls)
        if not st:
            continue
        own_vms = set(st.get('vmethods', {}))
        if not own_vms:
            continue
        clang_own = []
        for slot_idx, mname in slots:
            if mname in own_vms:
                clang_own.append((mname, slot_idx * 8))
        if not clang_own:
            continue
        st['vfuncs'] = clang_own
        st['_vfuncs_from_dump'] = True
        replaced += 1
    if verbose and replaced:
        print('Replaced vfuncs with clang vtable dump for {} classes'.format(replaced))
    return replaced


_OPAQUE_BAD_FRAGS = ('__attribute__', '*const', '*volatile', 'unnamed', 'lambda',
                     'anonymous', '$', '...', '(*)', '(&)', ' (*', ' (&')


_ANON_FRAGS = ('(lambda at ', '(anonymous at ', '(unnamed at ')


def _name_is_anonymous(name: str) -> bool:
    """True for clang-synthesised anonymous type names that embed absolute
    file paths and line:col positions, e.g. ``(lambda at PATH:L:C)``,
    ``(anonymous at PATH:L:C)``, ``(unnamed at PATH:L:C)``.

    Such names also taint any wrapper template/nested type whose name contains
    them as a fragment (e.g. ``std::optional<RE::(lambda at ...)>::_Value``).
    """
    if not name:
        return False
    return any(frag in name for frag in _ANON_FRAGS)


def _strip_anonymous_types(structs: dict, verbose: bool = False) -> int:
    """Drop struct entries whose full_name (or any name fragment) embeds a
    clang-synthesised anonymous identifier (lambda / anonymous / unnamed).

    Replaces every descriptor referencing one of those names with a raw
    ``bytes:<size>`` padding (or bare ``ptr`` when wrapped in ``ptr:``), so
    fields keep their byte footprint without leaking unportable names into
    the generated Ghidra script.
    """
    anon_keys = [k for k in structs if _name_is_anonymous(k)]
    anon_set  = set(anon_keys)

    def _rewrite(desc: str, byte_size=None) -> str:
        """Rewrite a descriptor that references an anonymous type."""
        if not desc:
            return desc
        if desc.startswith('ptr:'):
            inner = _rewrite(desc[4:], None)
            if inner == 'ptr' or inner == '':
                return 'ptr'
            return 'ptr:' + inner
        if desc.startswith('arr:'):
            rest = desc[4:]
            last = rest.rfind(':')
            if last > 0 and rest[last+1:].isdigit():
                inner = _rewrite(rest[:last], None)
                count = rest[last+1:]
                if inner.startswith('struct:') or inner == 'ptr' or inner == '':
                    return 'arr:u8:{}'.format(int(count))
                return 'arr:{}:{}'.format(inner, count)
        if desc.startswith('struct:'):
            ref = desc[7:]
            if _name_is_anonymous(ref):
                if byte_size and byte_size > 0:
                    return 'bytes:{}'.format(byte_size)
                return 'ptr'
        return desc

    rewrites = 0
    for st in structs.values():
        if _name_is_anonymous(st.get('full_name', '')):
            continue  # will be dropped; no need to rewrite its own fields
        for f in st.get('fields', []):
            new = _rewrite(f.get('type', ''), f.get('size', 0))
            if new != f.get('type'):
                f['type'] = new
                rewrites += 1
        # Also rewrite vmethod / method signatures
        for mdict_key in ('vmethods', 'methods'):
            mdict = st.get(mdict_key) or {}
            for mname, info in list(mdict.items()):
                if mdict_key == 'vmethods':
                    ret, params = info
                else:
                    ret, params, is_static = info
                new_ret = _rewrite(ret, None)
                new_params = [(pn, _rewrite(pt, None)) for pn, pt in params]
                if new_ret != ret or new_params != params:
                    if mdict_key == 'vmethods':
                        mdict[mname] = (new_ret, new_params)
                    else:
                        mdict[mname] = (new_ret, new_params, is_static)
                    rewrites += 1
        # Filter out anonymous bases (they were placeholders anyway)
        if st.get('bases'):
            st['bases'] = [b for b in st['bases'] if not _name_is_anonymous(b)]
        if st.get('pdb_bases'):
            st['pdb_bases'] = [(b, off) for (b, off) in st['pdb_bases']
                               if not _name_is_anonymous(b)]

    for k in anon_keys:
        del structs[k]

    if verbose and (anon_keys or rewrites):
        print('Stripped {} anonymous-type entries; rewrote {} descriptors'.format(
            len(anon_keys), rewrites))
    return len(anon_keys)

_OPAQUE_PLAIN_NAME_RE  = re.compile(r'^[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)*$')
# Nested type inside a template instantiation:  Outer<args>::Inner[::Inner2...]
# Tail must be plain identifiers; head may contain matched <>.
_OPAQUE_NESTED_RE      = re.compile(
    r'^[\w:]+(?:<.+>)(?:::[A-Za-z_][\w]*)+$'
)


def _is_opaque_safe_name(name: str) -> bool:
    """Reject names that aren't safe to materialise as opaque structs.

    Allowed:
      - Plain qualified names (no template args):  ``RE::Foo::Bar``
      - Nested types in template instantiations:   ``Foo<X>::Inner``
        (the trailing component after the closing ``>`` must be a plain
         identifier path).
    """
    if not name:
        return False
    if any(s in name for s in _OPAQUE_BAD_FRAGS):
        return False
    last = name.split('::')[-1]
    # Single-letter uppercase typically denotes uninstantiated template params.
    if len(last) == 1 and last.isupper():
        return False
    # Reject names whose trailing component still contains template angle brackets
    # — those are pure templates handled by template_map, not nested members.
    if '<' in last or '>' in last:
        return False
    # Plain qualified path (no template anywhere)
    if _OPAQUE_PLAIN_NAME_RE.match(name):
        return True
    # Nested type inside a template instantiation
    if _OPAQUE_NESTED_RE.match(name):
        return True
    return False


def _collect_descriptor_refs(structs):
    """Walk every descriptor in structs.fields/vmethods/methods and collect
    every ``struct:`` / ``enum:`` name referenced (recursing through ptr/arr
    wrappers).  Used by the opaque-struct generator.
    """
    refs = set()

    def visit(t):
        if not t:
            return
        if t.startswith('ptr:'):
            visit(t[4:]); return
        if t.startswith('arr:'):
            rest = t[4:]
            last = rest.rfind(':')
            if last > 0 and rest[last+1:].isdigit():
                visit(rest[:last]); return
        if t.startswith('struct:') or t.startswith('enum:'):
            refs.add(t.split(':', 1)[1])

    for st in structs.values():
        for f in st.get('fields', []):
            visit(f.get('type', ''))
        for ret, params in st.get('vmethods', {}).values():
            visit(ret)
            for _pn, pt in params:
                visit(pt)
        for ret, params, _is_static in st.get('methods', {}).values():
            visit(ret)
            for _pn, pt in params:
                visit(pt)
    return refs


def _add_opaque_for_forward_decls(structs, enums, root_ns, category_prefix, verbose=False):
    """Generate 0-byte opaque struct entries for any name that's referenced
    in a descriptor but neither defined in ``structs`` nor present as an
    enum.  This converts ``void *`` fallbacks into typed pointers in Ghidra
    for forward-declared external types (Havok ``hk*``, ``REX::W32::*``,
    nested types inside templates, etc.).
    """
    referenced = _collect_descriptor_refs(structs)

    existing_short_struct = {st['name'] for st in structs.values()}
    existing_short_enum   = {e.split('::')[-1] for e in enums}
    added = 0
    for name in sorted(referenced):
        if name in structs or name in enums:
            continue
        short = name.split('::')[-1]
        # Whole-template names go through template_map; nested types inside
        # templates (Outer<args>::Inner) are admitted.
        if not _is_opaque_safe_name(name):
            continue
        if short in existing_short_struct or short in existing_short_enum:
            continue
        ns_parts = name.split('::')[:-1]
        if ns_parts:
            category = category_prefix + '/' + '/'.join(ns_parts)
        else:
            category = category_prefix
        structs[name] = {
            'name':       name.split('::')[-1],
            'full_name':  name,
            'record_kind': 'struct',
            'size':       0,
            'category':   category,
            'fields':     [],
            'bases':      [],
            'has_vtable': False,
        }
        added += 1
    if verbose and added:
        print('Added {} opaque struct entries for forward-declared types'.format(added))
    return added


def _store_vtable_secondaries(structs, secondary_layouts, verbose=False):
    """Attach per-class secondary-vtable layout maps to the struct dicts.

    Each entry is recorded on the most-derived class as
    ``st['secondary_vtables'][offset] = [(slot, method_name), ...]``.
    Used downstream by vtable-struct generation and field-type rewriting.
    """
    if not secondary_layouts:
        return 0
    stored = 0
    for (cls, off), slots in secondary_layouts.items():
        st = structs.get(cls)
        if not st or not slots:
            continue
        sv = st.setdefault('secondary_vtables', {})
        # Keep the longer one if a duplicate (C, off) appears
        if off not in sv or len(slots) > len(sv[off]):
            sv[off] = list(slots)
            stored += 1
    if verbose and stored:
        print('Stored {} secondary-vtable layouts on classes'.format(stored))
    return stored


def _force_template_layouts(structs, header_path, parse_args, clang_binary,
                            root_ns, verbose, pointer_size=8):
    """Force clang to emit record layouts for empty template placeholders.

    For each placeholder ``T<...>`` whose layout is unknown, emit a synthetic
    .cpp file that includes the orchestrator header and contains
    ``struct sN { T<...> _; };`` for every candidate.  Running clang's
    record-layout dump on that file forces template instantiation and emits
    the missing layouts, which we then merge back into the placeholder
    structs.
    """
    import tempfile

    def _all_fields_generic(st):
        """True iff every field is bare ``ptr`` or padding — i.e. nothing in
        the layout would be lost by re-running synthesis."""
        if not st['fields']:
            return True
        for f in st['fields']:
            t = f.get('type', '')
            if t and t != 'ptr' and not t.startswith('bytes:'):
                return False
        return True

    # Process both empty entries AND entries whose fields are all generic
    # ptr/padding — those came from propagation with a shape-mismatched donor
    # and synthesis can produce a more accurate layout.
    candidates_keys = [
        k for k, s in structs.items()
        if '<' in k and (
            (s['size'] == 0 and not s['fields'])
            or _all_fields_generic(s)
        )
    ]
    candidates = [n for n in candidates_keys if _is_safe_template_name(n)]
    empty = candidates_keys  # used below for the merge step
    if not candidates:
        return 0

    header_fwd = header_path.replace('\\', '/')
    lines = ['#include "{}"'.format(header_fwd),
             'namespace __force_template_layouts {']
    for i, name in enumerate(sorted(candidates)):
        lines.append('  struct s{} {{ {} _; }};'.format(i, name))
    lines.append('}')
    src = '\n'.join(lines) + '\n'

    tmp_dir = tempfile.mkdtemp(prefix='ghidra_force_tmpl_')
    tmp_path = os.path.join(tmp_dir, 'force_template_layouts.cpp')
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(src)

        if verbose:
            print('Pass 3: forcing layouts for {} template placeholders...'.format(len(candidates)))
        cmd = [clang_binary] + parse_args + [
            '-fsyntax-only', '-ferror-limit=0',
            '-Xclang', '-fdump-record-layouts-complete',
            '-Xclang', '-fdump-record-layouts-canonical',
            tmp_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace')
        # This pass compiles with -ferror-limit=0 precisely because the
        # candidate set always contains un-instantiable names, so clang
        # always exits nonzero.  Every layout clang *did* dump comes from a
        # record it completed, so partial output is safe -- gate only on
        # producing nothing at all.
        layouts = _parse_layouts_with_bases(
            result.stdout, root_ns=root_ns, pointer_size=pointer_size)
        if result.returncode != 0 and not layouts:
            if verbose:
                print('  forced-layout clang pass produced no layouts '
                      '(exit {}); skipping'.format(result.returncode))
            return 0
        if verbose:
            if result.returncode != 0:
                print('  Forced layout dump: {} new layouts ({} '
                      'un-instantiable candidates tolerated)'.format(
                          len(layouts), result.stderr.count(': error:')))
            else:
                print('  Forced layout dump: {} new layouts'.format(len(layouts)))
    finally:
        try:
            os.unlink(tmp_path)
            os.rmdir(tmp_dir)
        except OSError:
            pass

    ns_pre = (root_ns + '::') if root_ns else ''
    filled = 0
    for key in empty:
        ldata = (layouts.get(key)
                 or layouts.get(ns_pre + key)
                 or (layouts.get(key[len(ns_pre):]) if key.startswith(ns_pre) else None))
        if not ldata or ldata['size'] == 0:
            continue
        st = structs[key]
        st['size']       = ldata['size']
        st['fields']     = ldata['fields']
        st['bases']      = [bname for bname, _ in ldata['bases']]
        st['pdb_bases']  = ldata['bases']
        st['has_vtable'] = ldata['has_vtable']
        st['record_kind'] = ldata.get('record_kind', st.get('record_kind', 'struct'))
        filled += 1
    return filled


def _propagate_template_methods(structs, ast_classes, root_ns='RE'):
    """Copy vmethods/methods from each template definition onto every
    instantiation that doesn't have them yet.

    Template instantiations enter ``structs`` from three sources — the layout
    dump, ``_propagate_template_layouts``, and ``template_types``' alias map —
    and only the first path runs through the merge that copies AST methods.
    Running this pass at the end ensures every ``T<args>`` entry carries the
    same ``vmethods``/``methods`` dictionaries as its template definition
    ``T``, which is what vtable-struct generation needs to produce typed
    ``__vftable`` pointers for instantiations.
    """
    ns_pre = (root_ns + '::') if root_ns else ''
    propagated = 0
    for key, st in structs.items():
        if '<' not in key:
            continue
        if st.get('vmethods') and st.get('methods'):
            continue
        tmpl_base = _strip_outer_template(key)
        tmpl_def  = ast_classes.get(tmpl_base)
        if tmpl_def is None and tmpl_base.startswith(ns_pre):
            tmpl_def = ast_classes.get(tmpl_base[len(ns_pre):])
        if tmpl_def is None:
            continue
        if not st.get('vmethods'):
            st['vmethods'] = dict(tmpl_def.get('vmethods', {}))
            if tmpl_def.get('_overload_aliases'):
                st['_overload_aliases'] = dict(tmpl_def.get('_overload_aliases', {}))
        if not st.get('methods'):
            st['methods']  = dict(tmpl_def.get('methods', {}))
        if tmpl_def.get('has_vtable'):
            st['has_vtable'] = True
        propagated += 1
    return propagated


def _propagate_template_layouts(structs):
    """Fill empty template placeholders from known instantiations of the same template.

    For each empty template instantiation (size 0, no fields), find another
    instantiation of the same template base that has layout data. If ALL known
    instantiations share the same size, propagate the field layout.
    """
    by_base = {}
    for key, st in structs.items():
        base = _tmpl_base(key)
        if base is None:
            continue
        by_base.setdefault(base, []).append((key, st))

    propagated = 0
    for base, entries in by_base.items():
        has_layout = [(k, s) for k, s in entries if s['size'] > 0 and s['fields']]
        empty = [(k, s) for k, s in entries if s['size'] == 0 and not s['fields']]
        if not has_layout or not empty:
            continue
        sizes = set(s['size'] for _, s in has_layout)
        if len(sizes) != 1:
            continue
        donor_size = sizes.pop()
        donor_key, donor = has_layout[0]
        donor_args = _tmpl_args_of(donor_key) or []
        # If a donor template arg appears anywhere in the donor's field types,
        # the field shape depends on the arg — propagating to a sibling
        # instantiation would require substitution.  Skip when substitution
        # can't replicate the shape exactly so the synthesis pass downstream
        # can produce an accurate layout instead of leaving generic ``ptr``.
        donor_field_text = ' '.join(f.get('type', '') for f in donor['fields'])
        donor_arg_appears = any(
            a and a in donor_field_text for a in donor_args
        )
        for key, st in empty:
            recipient_args = _tmpl_args_of(key) or []
            # If the donor's args reference fields but the recipient's args
            # have a different shape (e.g. donor ``void*`` vs recipient
            # ``RE::Actor``), defer to synthesis instead of polluting the
            # entry with un-substituted fields.
            if donor_arg_appears and not _args_substitutable(donor_args, recipient_args):
                continue
            st['size'] = donor_size
            st['fields'] = [
                _retype_field_for_instantiation(f, donor_args, recipient_args)
                for f in donor['fields']
            ]
            st['bases'] = [
                _retype_base_for_instantiation(b, donor_args, recipient_args)
                for b in donor['bases']
            ]
            st['has_vtable'] = donor['has_vtable']
            propagated += 1
    return propagated


def _args_substitutable(donor_args, recipient_args):
    """Return True iff donor->recipient template-arg substitution can be
    expressed as token-level rewrites (same shape: same pointer/reference
    suffixes on each positional argument).  Differing shapes must be left to
    the synthesis pass, since substring substitution would mismatch indirection
    levels (e.g. donor ``void *`` vs recipient ``RE::Actor``).
    """
    if len(donor_args) != len(recipient_args):
        return False
    def _suffix(s):
        s = s.rstrip()
        n = 0
        while s.endswith(('*', '&')):
            n += 1
            s = s[:-1].rstrip()
        return n
    return all(_suffix(d) == _suffix(r) for d, r in zip(donor_args, recipient_args))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_types(header_path, include_path, parse_args,
                  verbose=False, clang_binary=None,
                  root_namespace='RE', category_prefix='/CommonLibSSE',
                  extra_scope_paths=None, target_arch=None,
                  allow_partial=False):
    """Parse C++ headers via clang.exe and collect type definitions.

    Two-pass approach:
      Pass 1: clang -ast-dump (text)                       → enums, bases, virtual methods
      Pass 2: clang -fdump-record-layouts-complete/canonical → field offsets, sizes, bases

    After merging, discovers template instantiation names and propagates
    layouts from known instantiations to empty ones of the same template base.

    Parameters
    ----------
    header_path:
        Path to the main header file to parse (e.g. Skyrim.h).
    include_path:
        Path to the include directory containing the source headers.
        Only types from files under this path are collected.
    parse_args:
        Clang command-line arguments (include paths, defines).
    verbose:
        Print progress information.
    clang_binary:
        Path to clang.exe. Auto-detected via find_clang_binary() if None.
    root_namespace:
        The root C++ namespace to qualify types with (default 'RE').
    category_prefix:
        Ghidra Data Type Manager category prefix (default '/CommonLibSSE').

    Returns
    -------
    (enums, structs, template_source) where template_source is embeddable
    Python source for the TEMPLATE_TYPE_MAP dict.
    """
    if not clang_binary:
        clang_binary = find_clang_binary()
    if not clang_binary:
        print('ERROR: clang.exe not found. Install LLVM or set PATH.')
        sys.exit(1)

    if verbose:
        print('Using clang: {}'.format(clang_binary))

    parse_args, abi = _normalize_abi_args(parse_args, target_arch)
    if verbose:
        print('Target ABI: {} ({}-byte pointers, {})'.format(
            abi['arch'], abi['pointer_size'], abi['triple']))

    header_fwd = header_path.replace('\\', '/')

    # --- Pass 1: AST dump for enums and virtual methods ---
    if verbose:
        print('Pass 1: AST dump (enums, virtual methods)...')
    cmd_ast = [clang_binary] + parse_args + [
        '-fsyntax-only', '-ferror-limit=0',
        '-Xclang', '-ast-dump',
        header_fwd,
    ]
    result_ast = subprocess.run(cmd_ast, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result_ast.returncode != 0 and not allow_partial:
        raise RuntimeError('clang AST extraction failed (exit {}):\n{}'.format(
            result_ast.returncode, result_ast.stderr[-8000:]))
    ast_text = result_ast.stdout
    if verbose:
        print('  AST dump: {} lines'.format(ast_text.count('\n')))

    enums, ast_classes, ast_aliases = _parse_ast_dump(ast_text, include_path,
                                                      root_ns=root_namespace,
                                                      category_prefix=category_prefix,
                                                      extra_scope_paths=extra_scope_paths)
    if verbose:
        print('  Parsed {} enums, {} classes, {} type aliases from AST'.format(
            len(enums), len(ast_classes), len(ast_aliases)))

    # --- Pass 2: Record layouts for field offsets and sizes ---
    if verbose:
        print('Pass 2: Record layouts (field offsets, sizes)...')
    cmd_layout = [clang_binary] + parse_args + [
        '-fsyntax-only', '-ferror-limit=0',
        '-Xclang', '-fdump-record-layouts-complete',
        '-Xclang', '-fdump-record-layouts-canonical',
        header_fwd,
    ]
    result_layout = subprocess.run(cmd_layout, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result_layout.returncode != 0 and not allow_partial:
        raise RuntimeError('clang record-layout extraction failed (exit {}):\n{}'.format(
            result_layout.returncode, result_layout.stderr[-8000:]))
    layout_text = result_layout.stdout
    if verbose:
        print('  Layout dump: {} lines'.format(layout_text.count('\n')))

    layouts = _parse_layouts_with_bases(
        layout_text, root_ns=root_namespace, pointer_size=abi['pointer_size'])
    if verbose:
        if root_namespace:
            ns_prefix = root_namespace + '::'
            ns_layouts = {k: v for k, v in layouts.items() if k.startswith(ns_prefix)}
            print('  Parsed {} record layouts ({} {}::)'.format(
                len(layouts), len(ns_layouts), root_namespace))
        else:
            print('  Parsed {} record layouts (global scope)'.format(len(layouts)))

    # --- Merge AST + layouts ---
    structs = _merge_ast_and_layouts(ast_classes, layouts, include_path,
                                     root_ns=root_namespace,
                                     category_prefix=category_prefix)
    if verbose:
        print('  Merged: {} structs'.format(len(structs)))

    _compute_vfuncs(structs, root_ns=root_namespace)

    # --- Apply AST type aliases (using X = Y;) ---
    if ast_aliases:
        _apply_aliases_to_structs(structs, ast_aliases, verbose=verbose)

    # --- Enrich vfuncs with clang -fdump-vtable-layouts (when available) ---
    try:
        _vt_primary, _vt_secondary = _dump_vtable_layouts(
            structs, header_path, parse_args, clang_binary,
            root_ns=root_namespace, verbose=verbose)
        if _vt_primary:
            _apply_vtable_dump(structs, _vt_primary, root_ns=root_namespace, verbose=verbose)
        if _vt_secondary:
            _store_vtable_secondaries(structs, _vt_secondary, verbose=verbose)
    except Exception as _e:
        if verbose:
            print('  vtable dump pass skipped: {}'.format(_e))

    # --- Template instantiation types ---
    tmpl_category = (category_prefix + '/' + root_namespace
                     if root_namespace else category_prefix)
    template_source = ''
    try:
        from template_types import process_template_types as _process_templates
        tmpl = _process_templates(structs)
        template_source = tmpl.map_source

        _created = 0
        _skipped = 0
        for _orig, _display in tmpl.template_map.items():
            # Skip clang-internal lambda-numbered names (e.g. 'Allocator<24, RE::8>')
            if not _is_safe_template_name(_display):
                _skipped += 1
                continue
            if _display not in structs and _display not in enums:
                structs[_display] = {
                    'name': _display, 'full_name': _display, 'size': 0,
                    'record_kind': 'struct',
                    'category': tmpl_category, 'fields': [], 'bases': [],
                    'has_vtable': False,
                }
                _created += 1
        if tmpl.template_map:
            extra = (' [{} unsafe names skipped]'.format(_skipped)) if _skipped else ''
            print('Discovered {} template instantiation aliases ({} new placeholders){}'.format(
                len(tmpl.template_map), _created, extra))

        _propagated = _propagate_template_layouts(structs)
        if _propagated:
            print('Propagated layout to {} empty template instantiations'.format(_propagated))

        _forced = _force_template_layouts(
            structs, header_path, parse_args, clang_binary,
            root_ns=root_namespace, verbose=verbose,
            pointer_size=abi['pointer_size'])
        if _forced:
            print('Forced layout for {} template instantiations via synthesis pass'.format(_forced))
    except ImportError:
        pass

    # --- Propagate vmethods/methods from template definitions onto every
    # instantiation that doesn't have them yet (covers ones that came in
    # via _propagate_template_layouts / template_map / forced layouts).
    _propagated_methods = _propagate_template_methods(
        structs, ast_classes, root_ns=root_namespace)
    if verbose and _propagated_methods:
        print('Propagated template-definition methods to {} instantiations'.format(
            _propagated_methods))

    # --- Re-run vfunc computation so newly-populated vmethods get vtable slots.
    _compute_vfuncs(structs, root_ns=root_namespace)

    # --- Strip clang-internal anonymous types (lambdas, unnamed structs) ---
    # Their names embed absolute paths (``(lambda at D:\path\file.h:LINE:COL)``)
    # which aren't portable, and they're not user-meaningful in Ghidra anyway.
    # Drop the entries themselves and rewrite any field/method descriptor
    # that referenced them so callers don't see a dangling ``struct:<anon>``.
    _strip_anonymous_types(structs, verbose=verbose)

    # --- Generate opaque structs for forward-declared types still referenced ---
    _add_opaque_for_forward_decls(
        structs, enums, root_ns=root_namespace,
        category_prefix=category_prefix, verbose=verbose)

    for st in structs.values():
        st['pointer_size'] = abi['pointer_size']

    return enums, structs, template_source
