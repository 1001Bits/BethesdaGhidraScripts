#!/usr/bin/env python3
"""Extract rare 32-bit immediates from Xbox Fallout.exe + pair with the
PC-side ``fnv_pc_rare_imms.txt`` to lift names for non-vtable functions.

For each PPC instruction in Xbox .text, recover the 32-bit value it
materializes:

  lis  rD, simm    (op=15, rA=0)   ->  rD = simm << 16
  li   rD, simm    (op=14, rA=0)   ->  rD = sign_ext(simm)
  lis rD,hi; addi rD,rD,lo         ->  rD = (hi << 16) + sign_ext(lo)
  lis rD,hi; ori  rD,rD,lo         ->  rD = (hi << 16) | lo

We record (xbox_fn_name, value) edges, filter:
  - drop values inside any image section (those are addresses, handled
    by the string/data/global xref pipelines)
  - drop "boring" values: small integers, power-of-2-aligned bitmasks,
    well-known constants -- they have too many xref-ers to be useful

The remaining values are unique-ish 32-bit constants -- format magic,
hash seeds, game-specific IDs.  We then load the PC-side rare-imm
list and for each (imm, single Xbox fn, single PC fn) tuple, lift the
PC fn's name from the Xbox PDB.

Output: ``fnv_imm_paired_names.csv`` -- ``0x<pc_rva>|<qname>|<imm>|<mangled>``.

Run:
    python extract_xbox_rare_immediates.py
"""
from __future__ import annotations

import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
IMAGE_BASE = 0x00400000  # PC FNV image base

from paths import XBOX_EXE, artifact
XBOX_PUBLICS = artifact('Fallout_Debug_publics.txt')
PC_RARE_IMM  = artifact('fnv_pc_rare_imms.txt')

sys.path.insert(0, str(SCRIPT_DIR))
from extract_xbox_string_xrefs import (
    parse_xbox_pe, is_text,
    load_publics, build_function_ranges, function_at_rva,
)
sys.path.insert(0, str(SCRIPT_DIR.parent / 'core'))
from pdb_symbols import undecorate  # noqa: E402


# "Boring" values that produce too many xref-ers to be useful as fingerprints.
_BORING_IMMS = set(range(-256, 1024)) | {
    0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8,
    0x00010000, 0xFFFF0000, 0x0000FFFF, 0x80000000,
    0x7FFFFFFF, 0x40000000, 0x20000000, 0x10000000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
}


def section_contains(sects, image_base, va):
    for s in sects:
        start = image_base + s['vaddr']
        end   = start + max(s['vsize'], s['rsize'])
        if start <= va < end:
            return True
    return False


def scan_all_ppc_immediates(text_bytes: bytes, text_vaddr: int):
    """Yield (insn_va, value) for every 32-bit (or sign-extended 16-bit)
    immediate materialized by a PPC instruction or instruction pair."""
    hi_anchor = [None] * 32   # per-register live `lis` immediate (hi16<<16)
    n = len(text_bytes)
    i = 0
    while i + 4 <= n:
        insn = struct.unpack_from('>I', text_bytes, i)[0]
        op   = (insn >> 26) & 0x3F
        rD   = (insn >> 21) & 0x1F
        rA   = (insn >> 16) & 0x1F
        imm  = insn & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm

        if op == 0x0F:  # addis / lis (when rA=0)
            if rA == 0:
                hi_anchor[rD] = (simm << 16) & 0xFFFFFFFF
                # Standalone `lis r,hi` yields the value (hi<<16) by itself
                yield text_vaddr + i, hi_anchor[rD]
            else:
                hi_anchor[rD] = None
        elif op == 0x0E:  # addi / li (when rA=0)
            if rA == 0:
                # li r, simm
                yield text_vaddr + i, simm & 0xFFFFFFFF
                if rD != rA:
                    hi_anchor[rD] = None
            elif hi_anchor[rA] is not None:
                # addi r, rA, simm  -- combine with prior lis
                target = (hi_anchor[rA] + simm) & 0xFFFFFFFF
                yield text_vaddr + i, target
                if rD != rA:
                    hi_anchor[rD] = None
            else:
                if rD != rA:
                    hi_anchor[rD] = None
        elif op == 0x18:  # ori rA, rS, uimm (rS=bits21, rA=bits16)
            rS = rD
            dest = rA
            if hi_anchor[rS] is not None:
                target = (hi_anchor[rS] | imm) & 0xFFFFFFFF
                yield text_vaddr + i, target
                if dest != rS:
                    hi_anchor[dest] = None
        elif op == 0x1C or op == 0x1D:  # andi./andis.
            # don't materialize new values; just invalidate rD
            hi_anchor[rD] = None
        else:
            # Conservative invalidation for D-form writes
            if 0x0E <= op <= 0x2F:
                hi_anchor[rD] = None
            if op in (0x10, 0x12):  # bc/b -- reset all
                hi_anchor = [None] * 32
        i += 4


def load_pc_rare_imms(path: Path) -> Dict[int, Set[int]]:
    """0x<imm>|<count>|<fn_vas comma-separated> -> {imm: {pc_fn_va}}"""
    out: Dict[int, Set[int]] = {}
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|')
        if len(p) != 3:
            continue
        try:
            imm = int(p[0], 16)
        except ValueError:
            continue
        fns = set()
        for v in p[2].split(','):
            v = v.strip()
            if v.startswith('0x'):
                try:
                    fns.add(int(v, 16))
                except ValueError:
                    pass
        if fns:
            out[imm] = fns
    return out


def load_existing_known_rvas() -> Set[int]:
    """All RVAs we already have a name for (any source)."""
    from pdb_naming import build_fallback_symbols
    return {s['a'] for s in build_fallback_symbols() if s.get('a')}


def main():
    print(f'Parsing Xbox PE: {XBOX_EXE.name}')
    data, image_base, sects = parse_xbox_pe(XBOX_EXE)
    text_sect = max((s for s in sects if is_text(s)), key=lambda s: s['rsize'])
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    print(f'  .text: 0x{text_vaddr:08X} ({len(text_bytes):,} bytes)')

    print(f'Loading publics: {XBOX_PUBLICS.name}')
    publics = load_publics(XBOX_PUBLICS)
    print(f'  {len(publics):,} publics')
    ranges = build_function_ranges(publics, text_sect['vaddr'],
                                    text_sect['vaddr'] + text_sect['vsize'])
    print(f'  function ranges: {len(ranges):,}')

    print('Scanning PPC for 32-bit immediates...')
    imm_to_fns: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    n_yielded = 0
    n_image = 0
    n_boring = 0
    for insn_va, value in scan_all_ppc_immediates(text_bytes, text_vaddr):
        n_yielded += 1
        if value in _BORING_IMMS:
            n_boring += 1
            continue
        if section_contains(sects, image_base, value):
            n_image += 1
            continue
        fn_rva = insn_va - image_base
        fn_name = function_at_rva(ranges, fn_rva)
        if not fn_name:
            continue
        imm_to_fns[value][fn_name] += 1
    print(f'  immediates yielded: {n_yielded:,}')
    print(f'  filtered boring:    {n_boring:,}')
    print(f'  filtered image-VA:  {n_image:,}')
    print(f'  distinct rare values w/ named fn: {len(imm_to_fns):,}')

    # Keep only values appearing in 1-3 Xbox fns (true fingerprints)
    rare_xbox = {imm: fns for imm, fns in imm_to_fns.items() if 1 <= len(fns) <= 3}
    print(f'  rare on Xbox side (<=3 fns):     {len(rare_xbox):,}')

    print(f'Loading PC rare imms: {PC_RARE_IMM.name}')
    pc_imms = load_pc_rare_imms(PC_RARE_IMM)
    print(f'  PC rare imms: {len(pc_imms):,}')

    # Intersection: imm appears in both rare lists
    common_imms = set(rare_xbox.keys()) & set(pc_imms.keys())
    print(f'  imms rare in BOTH: {len(common_imms):,}')

    print('Loading existing PC mapping (to avoid re-naming)...')
    known_rvas = load_existing_known_rvas()
    print(f'  already-named PC RVAs: {len(known_rvas):,}')

    # Pair: 1 PC fn + 1 Xbox fn for the same rare imm = candidate match.
    candidates: Dict[int, Tuple[str, int]] = {}  # pc_fn_va -> (xbox_mangled, imm)
    claimed_xbox: Set[str] = set()
    # Sort by Xbox-rarity then PC-rarity (more unique first)
    sorted_imms = sorted(common_imms,
                         key=lambda x: (len(rare_xbox[x]), len(pc_imms[x])))
    for imm in sorted_imms:
        xbs = list(rare_xbox[imm])
        pcs = list(pc_imms[imm])
        # Only consider clean 1:1 pairs to avoid noise
        if len(xbs) != 1 or len(pcs) != 1:
            continue
        xn = xbs[0]
        pv = pcs[0]
        if xn in claimed_xbox:
            continue
        if pv in candidates:
            continue
        rva = pv - IMAGE_BASE
        if rva in known_rvas:
            continue
        candidates[pv] = (xn, imm)
        claimed_xbox.add(xn)
    print(f'1:1 imm-fingerprint pairs (new only): {len(candidates):,}')

    print('Demangling...')
    demangled = {}
    for xn, _ in candidates.values():
        if xn not in demangled:
            try:
                demangled[xn] = undecorate(xn)
            except Exception:
                demangled[xn] = xn

    def qualify(d):
        toks = d.split()
        if not toks: return d
        # Drop parens / args
        s = toks[-1]
        depth = 0
        for i in range(len(s) - 1, -1, -1):
            if s[i] == ')': depth += 1
            elif s[i] == '(':
                depth -= 1
                if depth == 0:
                    s = s[:i].rstrip()
                    break
        return s

    out_path = REFS_DIR / 'fnv_imm_paired_names.csv'
    written = 0
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# imm-paired names: 0x<rva>|<qname>|0x<imm>|<mangled>\n')
        for pv, (xn, imm) in sorted(candidates.items()):
            rva = pv - IMAGE_BASE
            qname = qualify(demangled.get(xn, xn))
            if not qname or qname.startswith('?') or '::' not in qname:
                continue
            f.write(f'0x{rva:08X}|{qname}|0x{imm:08X}|{xn}\n')
            written += 1
    print(f'Wrote {out_path}: {written} symbols')


if __name__ == '__main__':
    main()
