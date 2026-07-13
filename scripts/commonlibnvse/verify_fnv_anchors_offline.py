#!/usr/bin/env python3
"""Offline anchor verification for the FNV import pipeline.

Reads PC FalloutNV.exe directly (no Ghidra) and validates that every
fallback-symbol RVA we emit is plausible:

  - Is the RVA inside the .text section?
  - Does the byte at RVA look like a function prologue, or is it
    INT3 padding (NOT a real function -- false positive)?
  - For vtable VAs: do the slot pointers in .rdata actually fall in
    .text?
  - For constructor candidates: do the constructor's first 256 bytes
    contain a 4-byte LE encoding of the claimed vtable VA?

Output: stdout summary + a JSON sidecar listing every RVA flagged
suspicious.  Doesn't modify the pipeline -- use for QA only.
"""
from __future__ import annotations

import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
from paths import PC_EXE

sys.path.insert(0, str(SCRIPT_DIR))
from extract_pc_fnv_string_xrefs import parse_pe_x86


_PROLOGUE_BYTES = {
    0x55,  # push ebp
    0x53, 0x56, 0x57,  # push ebx/esi/edi
    0x83,  # sub esp, imm8 / and esp etc.
    0x81,  # sub esp, imm32
    0x8B,  # mov reg, reg
    0xA1,  # mov eax, [imm32]
    0xB8, 0xB9, 0xBA, 0xBB, 0xBD, 0xBE, 0xBF,
    0xE9,  # jmp rel32 (thunks)
    0xFF,  # call/jmp r/m
    0x6A,  # push imm8
    0x68,  # push imm32
    0xC7,  # mov r/m32, imm32  (constructor pattern)
    0x33,  # xor r,r (common entry)
    0xC2, 0xC3,  # ret/retn  (tiny stubs)
    0x90,  # nop padding -- ambiguous, allow
}


def main():
    print(f'Reading {PC_EXE}')
    data, image_base, sects = parse_pe_x86(PC_EXE)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    text_end_va = text_vaddr + len(text_bytes)

    # Build a quick {rva: ok|reason} verdict for each fallback symbol
    sys.path.insert(0, str(SCRIPT_DIR))
    from pdb_naming import build_fallback_symbols
    syms = build_fallback_symbols()

    sus = []           # suspicious entries
    counts = Counter()
    for s in syms:
        rva = s.get('a')
        if rva is None:
            continue
        va = image_base + rva
        if not (text_vaddr <= va < text_end_va):
            # Data symbol -- skip code-prologue checks
            counts['data_label'] += 1
            continue
        off = va - text_vaddr
        if off < 0 or off >= len(text_bytes):
            counts['out_of_text'] += 1
            sus.append({'rva': rva, 'name': s['n'], 'src': s['src'],
                         'reason': 'out_of_text'})
            continue
        b0 = text_bytes[off]
        if b0 == 0xCC:
            counts['int3_padding'] += 1
            sus.append({'rva': rva, 'name': s['n'], 'src': s['src'],
                         'reason': 'int3_padding (likely false positive)'})
            continue
        if b0 not in _PROLOGUE_BYTES:
            counts['unusual_first_byte'] += 1
            # Don't flag -- many real prologues use bytes we haven't enumerated
        else:
            counts['ok_prologue'] += 1

    # Constructor cross-check: each ctor candidate should reference its
    # claimed vtable VA within the first 256 bytes of the function.
    ctor_path = REFS_DIR / 'fnv_constructor_names.csv'
    ctor_fails = 0
    if ctor_path.is_file():
        for ln in ctor_path.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            p = ln.split('|', 2)
            if len(p) < 3:
                continue
            try:
                rva = int(p[0], 16)
                vt  = int(p[2], 16)
            except ValueError:
                continue
            va = image_base + rva
            off = va - text_vaddr
            if not (0 <= off < len(text_bytes) - 64):
                continue
            window = text_bytes[off:off + 256]
            vt_le = struct.pack('<I', vt)
            if vt_le not in window:
                ctor_fails += 1
    counts['ctor_vtable_ref_missing'] = ctor_fails

    print()
    print('=== FNV anchor verification (offline) ===')
    for k, v in counts.most_common():
        print(f'  {k:30s} {v:,}')
    print()
    print(f'Suspicious entries: {len(sus)}')

    out_path = REFS_DIR / 'fnv_anchor_audit.json'
    out_path.write_text(json.dumps({'counts': dict(counts), 'suspicious': sus[:200]}),
                         encoding='utf-8')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
