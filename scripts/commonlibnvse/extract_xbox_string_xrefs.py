#!/usr/bin/env python3
"""Find string xrefs in the Xbox PowerPC Fallout.exe and pair them with
PDB function names.

For each string in Xbox .rdata, locate all (lis, addi/ori) instruction
pairs in Xbox .text that materialize the string's VA, and report the
enclosing function name from the PDB.

PowerPC encodes 32-bit absolute addresses across two instructions:

  lis  rD, hi16   (opcode 15)   ; rD = hi16 << 16  (sign-extended)
  addi rD, rA, lo16 (opcode 14) ; rD = rA + sign_ext(lo16)
  ori  rD, rA, lo16 (opcode 24) ; rD = rA | lo16   (unsigned)

If ``lo16`` (used by addi) has the high bit set, the sign-extension
turns it negative, so the matching ``hi16`` must be incremented by 1.

We scan .text, track per-register ``lis`` immediates as anchors, and
when we see a matching addi/ori pairing producing a target VA in
.rdata that equals a string VA, we record the xref.

Output: ``string_text|xbox_function_name|count`` per line.

Run:
    python extract_xbox_string_xrefs.py <Fallout.exe> <publics_dump> <out.txt>
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Xbox PE parsing (PowerPC BE, PE32)
# ---------------------------------------------------------------------------

def parse_xbox_pe(path: Path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe_off:pe_off + 4] == b'PE\x00\x00'
    coff = pe_off + 4
    machine = struct.unpack_from('<H', data, coff)[0]
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
    assert machine == 0x1F2, f'expected PowerPC BE (0x1F2), got 0x{machine:X}'
    return data, image_base, sects


def get_section_data(data, sects, name):
    for s in sects:
        if s['name'] == name:
            return s, data[s['rptr']:s['rptr'] + s['rsize']]
    return None, b''


def is_text(sect):
    return bool(sect['chars'] & 0x20000000)


# ---------------------------------------------------------------------------
# String extraction (Xbox)
# ---------------------------------------------------------------------------

def extract_strings(data, sects, image_base, min_len=4):
    """Same scanner as PC side but scoped to read-only data."""
    out: List[Tuple[int, str]] = []
    for s in sects:
        if is_text(s) or s['rsize'] == 0:
            continue
        if s['name'] not in ('.rdata', '.data', 'XBLD', 'XBMOVIE'):
            # Only scan typical data sections; skip resources/discardable
            if not (s['chars'] & 0x40000000):  # IMAGE_SCN_MEM_READ
                continue
        section = data[s['rptr']:s['rptr'] + s['rsize']]
        i = 0
        n = len(section)
        while i < n:
            j = i
            while j < n:
                b = section[j]
                if 0x20 <= b <= 0x7E or b == 0x09:
                    j += 1
                else:
                    break
            if j - i >= min_len and j < n and section[j] == 0:
                text = section[i:j].decode('latin-1', 'replace')
                va = image_base + s['vaddr'] + i
                out.append((va, text))
                i = j + 1
            else:
                i = j + 1 if j > i else i + 1
    return out


# ---------------------------------------------------------------------------
# PDB publics → ordered list of (function_va, demangled_name)
# ---------------------------------------------------------------------------

_PUB_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S+)\s*$')


def load_publics(path: Path) -> Dict[int, str]:
    """RVA → mangled name (earlier wins on collision)."""
    out = {}
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _PUB_RE.match(line)
            if m:
                rva = int(m.group(1), 16)
                out.setdefault(rva, m.group(2))
    return out


def build_function_ranges(publics: Dict[int, str], text_start: int,
                           text_end: int) -> List[Tuple[int, int, str]]:
    """From publics, derive contiguous ranges where each starts at one
    function symbol and ends at the next.

    Filters to symbols in .text and non-vtable.
    """
    in_text = sorted((rva, name) for rva, name in publics.items()
                     if text_start <= rva < text_end and not name.startswith('??_'))
    ranges = []
    for i, (rva, name) in enumerate(in_text):
        end = in_text[i + 1][0] if i + 1 < len(in_text) else text_end
        ranges.append((rva, end, name))
    return ranges


def function_at_rva(ranges, rva):
    """Binary search for the range containing rva."""
    import bisect
    keys = [r[0] for r in ranges]
    i = bisect.bisect_right(keys, rva) - 1
    if 0 <= i < len(ranges) and ranges[i][0] <= rva < ranges[i][1]:
        return ranges[i][2]
    return None


# ---------------------------------------------------------------------------
# PowerPC string xref scanner
# ---------------------------------------------------------------------------

def scan_ppc_string_xrefs(
    text_bytes: bytes, text_vaddr: int,
    string_va_set,
) -> List[Tuple[int, int]]:
    """Scan .text for (lis r,hi)(addi/ori r,r,lo) pairs producing a VA
    in ``string_va_set``.

    Returns [(insn_rva_of_completing_instruction, target_va), ...].

    PPC primary opcodes:
      addis (lis when rA==0) = 15 = 0xF       -> top 6 bits = 0b001111
      addi  (li when rA==0)  = 14 = 0xE       -> top 6 bits = 0b001110
      ori                    = 24 = 0x18      -> top 6 bits = 0b011000

    Instruction format for these D-form ops:
      [opcode:6][rD:5][rA:5][imm:16 SIMM/UIMM]

    We keep a per-register cache of the last `lis` immediate (high16
    component plus its source instruction address), then on addi/ori
    using the same register as rA, combine and check against the
    string VA set.

    The cache is reset at known function boundaries (we treat each new
    `bl` / `blr` / branch as a soft reset, but really we just walk
    forward and clear when registers are written by other instructions
    -- conservative but cheap).
    """
    pairs = []
    n = len(text_bytes)

    # Per-register high16 anchor.  None = no live `lis` for that reg.
    hi_anchor = [None] * 32  # type: List[int|None]

    i = 0
    while i + 4 <= n:
        insn = struct.unpack_from('>I', text_bytes, i)[0]
        op = (insn >> 26) & 0x3F
        rD = (insn >> 21) & 0x1F
        rA = (insn >> 16) & 0x1F
        imm = insn & 0xFFFF
        # Sign-extend 16-bit immediate
        simm = imm - 0x10000 if imm & 0x8000 else imm

        if op == 0x0F:  # addis (lis = addis rD, 0, hi)
            if rA == 0:
                # lis: rD = simm << 16
                hi_anchor[rD] = simm << 16
            else:
                # addis rD, rA, simm: usually relocations -- we don't track
                hi_anchor[rD] = None
        elif op == 0x0E and rA != 0:  # addi rD, rA, simm
            if hi_anchor[rA] is not None:
                target_va = (hi_anchor[rA] + simm) & 0xFFFFFFFF
                if target_va in string_va_set:
                    pairs.append((text_vaddr + i, target_va))
            # addi modifies rD; if rD != rA, original rA anchor still valid
            if rD != rA:
                hi_anchor[rD] = None
        elif op == 0x18:  # ori rA, rS, uimm (source/dest fields differ from addi)
            rS = rD
            dest = rA
            if hi_anchor[rS] is not None:
                target_va = (hi_anchor[rS] | imm) & 0xFFFFFFFF
                if target_va in string_va_set:
                    pairs.append((text_vaddr + i, target_va))
            if dest != rS:
                hi_anchor[dest] = None
        else:
            # If this instruction writes to a tracked register, invalidate
            # its anchor (we only conservatively invalidate D-form writes).
            # Branches/blrs reset everything.
            primary = op
            if primary in (0x10, 0x12, 0x13):  # bc, b, bclr/bcctr group
                hi_anchor = [None] * 32
            else:
                # Most arithmetic/load ops write rD or rT (bits 21-25).
                # Be conservative: if D-form (opcodes 14-47), invalidate rD.
                if 0x0E <= primary <= 0x2F and primary not in (0x0F,):
                    hi_anchor[rD] = None
        i += 4
    return pairs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path  = Path(sys.argv[1])
    pub_path  = Path(sys.argv[2])
    out_path  = Path(sys.argv[3])

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_xbox_pe(exe_path)
    print(f'  image_base=0x{image_base:X}  sections={len(sects)}')

    print('Extracting strings from data sections...')
    strings = extract_strings(data, sects, image_base, min_len=4)
    print(f'  {len(strings):,} strings')
    va_to_text = dict(strings)
    string_va_set = set(va_to_text)

    print(f'Loading publics: {pub_path}')
    publics = load_publics(pub_path)
    print(f'  {len(publics):,} unique publics')

    # Find text section -- there may be multiple; the main one is largest
    text_sects = [s for s in sects if is_text(s)]
    if not text_sects:
        print('ERROR: no .text section found'); sys.exit(2)
    text_sect = max(text_sects, key=lambda s: s['rsize'])
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    text_end = text_vaddr + text_sect['vsize']
    print(f'  .text: 0x{text_vaddr:08X}..0x{text_end:08X} ({len(text_bytes):,} bytes)')

    # Build function ranges (RVAs)
    ranges = build_function_ranges(publics, text_sect['vaddr'], text_sect['vaddr'] + text_sect['vsize'])
    print(f'  function ranges: {len(ranges):,}')

    print('Scanning PowerPC instructions for string xrefs...')
    pairs = scan_ppc_string_xrefs(text_bytes, text_vaddr, string_va_set)
    print(f'  {len(pairs):,} xref pairs found')

    # Map each xref to its enclosing function name; aggregate by string text
    string_to_funcs: Dict[str, Dict[str, int]] = {}
    for insn_va, target_va in pairs:
        text = va_to_text.get(target_va, '')
        if not text:
            continue
        fn_rva = insn_va - image_base
        fn_name = function_at_rva(ranges, fn_rva)
        if not fn_name:
            continue
        d = string_to_funcs.setdefault(text, {})
        d[fn_name] = d.get(fn_name, 0) + 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_strings = len(string_to_funcs)
    total_pairs = sum(len(v) for v in string_to_funcs.values())
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# Xbox string xrefs: <escaped string>|<xbox mangled func>|count\n')
        for text, fn_counts in sorted(string_to_funcs.items()):
            esc = text.replace('|', '\\|').replace('\n', '\\n').replace('\r', '\\r')[:200]
            for fn, count in sorted(fn_counts.items(), key=lambda kv: -kv[1]):
                f.write(f'{esc}|{fn}|{count}\n')
    print(f'Wrote {out_path}: {n_strings:,} unique strings, '
          f'{total_pairs:,} (string,function) edges')


if __name__ == '__main__':
    main()
