#!/usr/bin/env python3
"""Plain-C function name anchoring (extends string_anchor_lift).

Of the 6,121 plain-C (non-mangled, non-class-method) public symbols in
Fallout_Debug.pdb, many are utility/runtime functions whose name is
printed verbatim in assert/log strings -- ``hk1dLinearVelocityMotor``,
``XGRAPHICS::Extra::Set``, etc.  When such a name appears as a NUL-
terminated string in PC FalloutNV.exe, the function referencing that
string is almost always the named function itself.

For each plain-C public name N:
  1. Locate every string in PC FNV that is exactly ``N`` or contains
     ``N(`` (a logged function-call prefix).
  2. Find x86 xrefs to those strings in .text.
  3. Walk backwards from the xref to the function start (INT3 padding
     heuristic).
  4. Emit (PC_RVA, N) if there's a unique resolution.

Output: ``fnv_plain_c_names.csv`` with ``RVA|name|source_string`` per line.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'

sys.path.insert(0, str(SCRIPT_DIR))
from extract_pc_fnv_string_xrefs import (
    parse_pe_x86, load_strings, find_function_start_for_offset,
)


from paths import PC_EXE, artifact
XBOX_PUBLICS = artifact('Fallout_Debug_publics.txt')
PC_STRINGS   = artifact('fnv_pc_strings.txt')


_PUB_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S+)\s*$')


def load_plain_c_publics(path: Path) -> List[str]:
    """Plain-C = doesn't start with ``?``.  Filters out IAT thunks,
    floating-point literals (``__real@HEX``), Xbox-specific function-
    pointer constants, etc."""
    out = []
    seen = set()
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            m = _PUB_RE.match(ln)
            if not m:
                continue
            name = m.group(2)
            if name.startswith('?'):  # mangled -- handled by class-method path
                continue
            if name.startswith(('__imp_', '_imp_', '__real@',
                                'D3DDevice_', 'D3DQuery_', 'XShader',
                                'XMA', '_Xbox', 'XMP_')):
                continue
            # Drop names that are too short to anchor uniquely
            if len(name) < 6:
                continue
            # Drop names that look like compiler-internals
            if name.startswith('__'):
                continue
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
    return out


def main():
    print(f'Loading plain-C publics from {XBOX_PUBLICS.name}')
    plain_c = load_plain_c_publics(XBOX_PUBLICS)
    print(f'  candidates: {len(plain_c):,}')
    plain_c_set = set(plain_c)

    print(f'Loading PC strings...')
    strings = load_strings(PC_STRINGS)
    print(f'  strings: {len(strings):,}')

    # For each plain-C name, find strings that ARE the name or start with name(
    print('Matching strings to plain-C names...')
    name_to_str_vas: Dict[str, List[int]] = {}
    for va, text in strings.items():
        if not text:
            continue
        # Exact name match
        if text in plain_c_set:
            name_to_str_vas.setdefault(text, []).append(va)
            continue
        # ``name(`` prefix -- common in logged ``Func(arg1, arg2)`` strings
        first_paren = text.find('(')
        if first_paren > 0:
            candidate = text[:first_paren]
            if candidate in plain_c_set:
                name_to_str_vas.setdefault(candidate, []).append(va)
                continue
        # ``name :`` or ``name -`` prefixes (very loose)
    print(f'  names matched: {len(name_to_str_vas):,}')

    # Drop names that ended up in too many strings (>5) -- too generic
    name_to_str_vas = {n: vs for n, vs in name_to_str_vas.items()
                       if len(vs) <= 5}
    print(f'  after generic filter (<=5 strings each): {len(name_to_str_vas):,}')

    # Byte-scan PC FNV.exe .text for xrefs to those string VAs
    print(f'Scanning {PC_EXE.name}...')
    data, image_base, sects = parse_pe_x86(PC_EXE)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']

    target_vas: Set[int] = {va for vas in name_to_str_vas.values() for va in vas}
    print(f'  target string VAs: {len(target_vas):,}')

    # Build {target_va: name}
    va_to_name = {}
    for n, vas in name_to_str_vas.items():
        for va in vas:
            va_to_name[va] = n  # last wins, but each VA is unique to one string

    # Find xrefs + map to fn starts
    name_to_fns: Dict[str, Set[int]] = {}
    for i in range(0, len(text_bytes) - 4):
        v = (text_bytes[i] | (text_bytes[i+1] << 8) |
             (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if v in target_vas:
            fn = find_function_start_for_offset(text_bytes, text_vaddr, i)
            if fn:
                name = va_to_name.get(v)
                if name:
                    name_to_fns.setdefault(name, set()).add(fn)

    print(f'  names with at least one xref: {len(name_to_fns):,}')

    # Emit unique 1:1 (name has exactly one xref-er fn)
    out_path = REFS_DIR / 'fnv_plain_c_names.csv'
    written = 0
    skipped_multi = 0
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# plain-C anchored names: 0x<rva>|<name>|<source string>\n')
        IMAGE_BASE = 0x00400000
        for name, fns in sorted(name_to_fns.items()):
            if len(fns) == 1:
                fn = next(iter(fns))
                rva = fn - IMAGE_BASE
                # Pick first source string for context
                src_va = next(va for va in name_to_str_vas[name])
                src = strings.get(src_va, '')
                src = src.replace('|', '\\|').replace('\n', '\\n')[:80]
                f.write(f'0x{rva:08X}|{name}|{src}\n')
                written += 1
            else:
                skipped_multi += 1
    print(f'Wrote {out_path}: {written:,} unique anchors '
          f'({skipped_multi:,} skipped as multi-fn)')


if __name__ == '__main__':
    main()
