#!/usr/bin/env python3
"""Find string xrefs in PC FalloutNV.exe and assign each xref to its
enclosing function.

PRECISION: when an --anchors file is supplied (list of known function-
start RVAs, one per line), each xref snaps to the LARGEST anchor RVA
<= xref_va within 0x4000 bytes.  This is much more precise than the
INT3-padding heuristic alone, because intra-function padding (cold
paths, alignment) is common and would otherwise create fake "starts".

Anchors should be supplied -- the existing FNV pipeline can dump them
from already-known function RVAs (vtable slots, NVSE-known, etc.).

x86 references a string literal via a 4-byte LE absolute VA embedded
in instructions like ``push imm32`` or ``mov reg, imm32``.  We scan
.text for byte runs equal to any known string VA and walk back from
each hit to the nearest function prologue (preceded by INT3 padding
or 16-byte aligned).

Output: ``<escaped string>|0x<function_rva>|count`` per line.  Used by
``match_string_xrefs.py`` to pair with the Xbox-side xref table.

Run:
    python extract_pc_fnv_string_xrefs.py <FalloutNV.exe> <strings.txt> <out.txt> [anchors.txt]
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


def parse_pe_x86(path: Path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    coff = pe_off + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt = coff + 20
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    image_base = struct.unpack_from('<I', data, opt + 28)[0]
    sect_off = opt + opt_sz
    sects = []
    for i in range(nsec):
        so = sect_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin-1', 'replace')
        vsize = struct.unpack_from('<I', data, so + 8)[0]
        vaddr = struct.unpack_from('<I', data, so + 12)[0]
        rsize = struct.unpack_from('<I', data, so + 16)[0]
        rptr  = struct.unpack_from('<I', data, so + 20)[0]
        chars = struct.unpack_from('<I', data, so + 36)[0]
        sects.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                       'rptr': rptr, 'rsize': rsize, 'chars': chars})
    return data, image_base, sects


def load_strings(path: Path) -> Dict[int, str]:
    """0xVA|len|text per line -> {va: text}."""
    out = {}
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 2)
        if len(p) < 3:
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        text = (p[2].replace('\\r', '\r').replace('\\n', '\n')
                .replace('\\t', '\t').replace('\\\\', '\\'))
        out[va] = text
    return out


def find_xref_byte_offsets(text_bytes: bytes, string_va_set: Set[int]):
    """Yield (text_byte_offset, target_va) for every 4-byte LE window in
    .text whose value is in string_va_set.

    Scans byte-by-byte (not 4-byte aligned) since x86 instruction operands
    are not aligned in code.
    """
    n = len(text_bytes)
    for i in range(0, n - 4):
        va = (text_bytes[i] | (text_bytes[i+1] << 8) |
              (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if va in string_va_set:
            yield i, va


_PADDING_BYTES = {0xCC, 0x90}


def find_function_start_via_anchors(anchors_sorted: list, xref_va: int,
                                     max_gap: int = 0x4000) -> int:
    """Snap xref_va back to the largest anchor RVA <= xref_va within max_gap."""
    import bisect
    i = bisect.bisect_right(anchors_sorted, xref_va) - 1
    if i < 0:
        return 0
    candidate = anchors_sorted[i]
    if xref_va - candidate <= max_gap:
        return candidate
    return 0


def find_function_start_for_offset(text_bytes: bytes, text_vaddr: int,
                                    xref_off: int, max_back: int = 0x2000) -> int:
    """Walk backwards from xref_off to nearest function start.

    Heuristic: function starts immediately follow a run of 0xCC (INT3)
    padding OR 0x90 (NOP) padding, optionally followed by alignment NOPs.
    Falls back to the most recent INT3 in [xref_off - max_back, xref_off].
    """
    start_off = max(0, xref_off - max_back)
    # Walking backwards means the first padding-to-code transition we see is
    # the nearest candidate.  The previous implementation kept overwriting
    # the candidate and returned the oldest transition in an 8 KiB window.
    i = xref_off
    while i > start_off:
        b = text_bytes[i - 1]
        if b in _PADDING_BYTES:
            # Walk back past padding run
            j = i - 1
            while j > start_off and text_bytes[j] in _PADDING_BYTES:
                j -= 1
            # j+1..i-1 is padding run; function starts at i (the byte after padding)
            # If padding run is >= 1 byte and what follows isn't padding,
            # that's a function start.
            if j + 1 < i:
                return text_vaddr + i
            i = j
        else:
            i -= 1
    return 0


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path     = Path(sys.argv[1])
    strings_path = Path(sys.argv[2])
    out_path     = Path(sys.argv[3])
    anchors_path = Path(sys.argv[4]) if len(sys.argv) > 4 else None

    anchors_sorted = []
    if anchors_path and anchors_path.is_file():
        for ln in anchors_path.read_text(encoding='utf-8', errors='replace').splitlines():
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            try:
                anchors_sorted.append(int(ln, 16) if ln.lower().startswith('0x') else int(ln))
            except ValueError:
                continue
        anchors_sorted.sort()
        print(f'Loaded {len(anchors_sorted):,} function anchors from {anchors_path.name}')

    print(f'Loading strings: {strings_path}')
    va_to_text = load_strings(strings_path)
    print(f'  {len(va_to_text):,} strings')

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_pe_x86(exe_path)
    text_sect = None
    for s in sects:
        if s['chars'] & 0x20000000:
            text_sect = s
            break
    assert text_sect is not None
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    print(f'  .text: 0x{text_vaddr:08X} ({len(text_bytes):,} bytes)')

    string_va_set = set(va_to_text.keys())
    print('Scanning .text for string VA xrefs...')

    # Aggregate per (string_text, function_va) -> count
    string_to_funcs: Dict[str, Dict[int, int]] = {}
    n_xrefs = 0
    n_resolved = 0
    for off, target_va in find_xref_byte_offsets(text_bytes, string_va_set):
        n_xrefs += 1
        xref_va = text_vaddr + off
        # Prefer anchor-snap (precise); fall back to heuristic.
        fn_va = (find_function_start_via_anchors(anchors_sorted, xref_va)
                 if anchors_sorted else 0)
        if fn_va == 0:
            fn_va = find_function_start_for_offset(text_bytes, text_vaddr, off)
        if fn_va == 0:
            continue
        n_resolved += 1
        text = va_to_text[target_va]
        d = string_to_funcs.setdefault(text, {})
        d[fn_va] = d.get(fn_va, 0) + 1

    print(f'  xrefs found: {n_xrefs:,}  (resolved to a function: {n_resolved:,})')
    n_strings = len(string_to_funcs)
    total_pairs = sum(len(v) for v in string_to_funcs.values())
    print(f'  unique strings xref\'d: {n_strings:,}  edges: {total_pairs:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# PC FNV string xrefs: <escaped string>|0x<fn_va>|count\n')
        for text, fn_counts in sorted(string_to_funcs.items()):
            esc = text.replace('|', '\\|').replace('\n', '\\n').replace('\r', '\\r')[:200]
            for fn_va, count in sorted(fn_counts.items(), key=lambda kv: -kv[1]):
                f.write(f'{esc}|0x{fn_va:08X}|{count}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
