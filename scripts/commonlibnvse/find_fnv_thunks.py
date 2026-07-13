#!/usr/bin/env python3
"""Find thunks in PC FalloutNV.exe -- functions that are a single
unconditional jump to another function, often Ghidra-typed as
``FUN_<addr>`` and clogging the function list.

x86 thunk patterns:
    E9 RR RR RR RR           jmp rel32
    EB BB                    jmp rel8   (rare, usually inlined)
    FF 25 II II II II        jmp dword ptr [imm32]   (IAT thunk)
    FF E1/E2/E3...           jmp r32 (computed; not constant target)

We focus on the E9 (rel32 jmp) form which is what MSVC emits for
``__declspec(naked)`` thunks and ICF-folded redirects.

For each detected thunk:
  - Resolve the rel32 target
  - If the target has a name in our fallback set, emit
    ``j_<target_name>`` at the thunk's RVA.

Output: ``fnv_thunk_names.csv`` -- ``RVA|j_<name>|target_rva``.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
from paths import PC_EXE

sys.path.insert(0, str(SCRIPT_DIR))
from extract_pc_fnv_string_xrefs import parse_pe_x86


def load_anchors_set() -> set:
    """Anchors = every known PC FNV function-start RVA (from
    fnv_pc_anchors.txt + fallback symbols)."""
    out = set()
    p = REFS_DIR / 'fnv_pc_anchors.txt'
    if p.is_file():
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            ln = ln.strip()
            if ln.startswith('0x'):
                try: out.add(int(ln, 16))
                except ValueError: pass
    return out


def load_existing_names() -> Dict[int, str]:
    """RVAs already named via fallback symbols."""
    from pdb_naming import build_fallback_symbols
    return {s['a']: s['n'] for s in build_fallback_symbols() if s.get('a')}


_PAD = {0xCC, 0x90}


def main():
    print('Loading function-start anchors...')
    anchors = load_anchors_set()
    print(f'  anchors: {len(anchors):,}')

    print('Loading existing names...')
    names_by_rva = load_existing_names()
    # Add IMAGE_BASE since anchors are VAs not RVAs (depends on source)
    print(f'  named: {len(names_by_rva):,}')

    print(f'Parsing PE: {PC_EXE}')
    data, image_base, sects = parse_pe_x86(PC_EXE)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    text_end = text_vaddr + len(text_bytes)
    print(f'  .text: 0x{text_vaddr:08X} ({len(text_bytes):,} bytes)')

    # Walk anchors: at each anchor, check if first instruction is JMP rel32
    # and there's nothing else before the next INT3 padding.
    matches: List = []
    n_scanned = 0
    n_e9 = 0
    n_named_targets = 0
    IMAGE_BASE = image_base
    # Need anchor as VA. fnv_pc_anchors.txt is in VA form (0x004XXXXX).
    for fn_va in anchors:
        off = fn_va - text_vaddr
        if off < 0 or off + 5 >= len(text_bytes):
            continue
        n_scanned += 1
        if text_bytes[off] != 0xE9:
            continue
        n_e9 += 1
        # Read rel32, compute target
        rel = struct.unpack_from('<i', text_bytes, off + 1)[0]
        target_va = (fn_va + 5 + rel) & 0xFFFFFFFF
        # Validate target is in .text
        if not (text_vaddr <= target_va < text_end):
            continue
        # Verify the jmp is followed by padding (proper thunk shape)
        end = off + 5
        if end < len(text_bytes) and text_bytes[end] not in _PAD:
            # Allow up to 3 bytes of slack (alignment ret/leave)
            slack = sum(1 for k in range(end, min(end+4, len(text_bytes)))
                        if text_bytes[k] not in _PAD)
            if slack > 1:
                continue
        target_rva = target_va - IMAGE_BASE
        target_name = names_by_rva.get(target_rva)
        if not target_name:
            continue
        n_named_targets += 1
        thunk_rva = fn_va - IMAGE_BASE
        if thunk_rva in names_by_rva:
            continue  # already named
        matches.append((thunk_rva, f'j_{target_name}', target_rva))

    print(f'  anchors with E9-jmp opcode at start: {n_e9:,}')
    print(f'  thunks pointing to a named target:   {n_named_targets:,}')
    print(f'  new thunk names (target named, thunk not): {len(matches):,}')

    out_path = REFS_DIR / 'fnv_thunk_names.csv'
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# thunk names: 0x<rva>|j_<target_name>|0x<target_rva>\n')
        for rva, name, trva in sorted(matches):
            f.write(f'0x{rva:08X}|{name}|0x{trva:08X}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
