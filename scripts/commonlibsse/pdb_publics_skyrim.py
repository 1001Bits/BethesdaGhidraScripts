"""Checked-in Skyrim PDB publics loader via llvm-pdbutil pretty --externals.

This remains a reproducible pre-extracted corpus alongside the native MSF 7
reader in ``core/pdb_symbols.py``; it does not require a third-party PDB parser.

Source: ``extras/SkyrimSE.pdb`` dumped via
``llvm-pdbutil pretty --externals`` and checked into refs/.  Format:

    public [0xRVA] DemangledQualifiedName(args)

The SkyrimSE.exe image base is 0x140000000; the RVAs in the dump are
already image-relative offsets that the import script consumes as-is.

Returns ``{rva: name}`` matching the native loader's shape so
``commonlibsse/parse_commonlib_types.py`` doesn't need to know which
backend it's talking to.
"""
from __future__ import annotations

import os
import re
from typing import Dict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REFS_DIR   = os.path.join(SCRIPT_DIR, 'refs')
PUBLICS_TXT = os.path.join(REFS_DIR, 'skyrimse_pdb_publics.txt')


_LINE_RE = re.compile(
    r'^\s*public\s+\[0x(?P<rva>[0-9A-Fa-f]+)\]\s+(?P<name>\S.*?)\s*$')

_BAD_SUBSTR = (
    '`vector-deleting-destructor', '<lambda_',
    'anonymous namespace',
)
_NAME_RE = re.compile(r'^[A-Za-z_][\w:<>~]*$')
_ADDR_SUFFIX_RE = re.compile(r'_14[0-9A-Fa-f]{6,12}$')


def _clean(name: str) -> str | None:
    # Strip args ``Foo::Bar(args)`` -> ``Foo::Bar``.  Stops at the first
    # unparenthesised '('; templated identifiers with angle brackets keep
    # their template args.
    base = name.split('(', 1)[0].strip()
    if not base:
        return None
    base = _ADDR_SUFFIX_RE.sub('', base)
    base = re.sub(r':{3,}', '::', base)
    if not base:
        return None
    # Discard obvious compiler/RTTI noise we can't safely place; everything
    # else stays.  '<' is allowed (templated names like ``BSTArray<T>``).
    return base


def load_pdb_names(file_path: str | None = None) -> Dict[int, str]:
    """Return ``{rva: name}`` parsed from the llvm-pdbutil externals dump.

    The ``file_path`` argument is accepted for API compatibility with the
    native loader; the actual data comes from
    ``refs/skyrimse_pdb_publics.txt``.  Falls back to an empty dict when
    that refs file isn't present.
    """
    if not os.path.isfile(PUBLICS_TXT):
        return {}
    out: Dict[int, str] = {}
    with open(PUBLICS_TXT, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            m = _LINE_RE.match(ln)
            if not m:
                continue
            try:
                rva = int(m.group('rva'), 16)
            except ValueError:
                continue
            if rva == 0:
                continue
            raw = m.group('name')
            if any(b in raw for b in _BAD_SUBSTR):
                continue
            name = _clean(raw)
            if name is None:
                continue
            out.setdefault(rva, name)
    return out


if __name__ == '__main__':
    syms = load_pdb_names()
    print(f'SkyrimSE PDB publics: {len(syms):,} unique entries')
