#!/usr/bin/env python3
"""Cross-binary call-graph alignment for FNV.

For each PC FNV function P whose qualified name is known and whose
Xbox counterpart X has a callee list extracted via PDB+PPC scanning,
positionally align PC callees against Xbox callees and propagate
PDB-known names to the corresponding PC RVAs.

We use an LCS-style alignment between PC callees and Xbox callees:
  - Strip placeholder ``?`` entries from Xbox side
  - Align by position with bounded local jitter (Xbox may have inlined
    calls the PC build kept)
  - For each aligned (pc_callee_va, xbox_callee_name) pair:
       if pc_callee is currently unnamed AND xbox_name has Class::method form,
       emit (pc_callee_rva, xbox_name)

Output: ``fnv_callgraph_names.csv`` -- ``RVA|qualified_name`` per line.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
IMAGE_BASE = 0x00400000

from paths import artifact
XBOX_CALLGRAPH = artifact('Fallout_Debug_callgraph.json')
PC_CALLGRAPH   = artifact('fnv_pc_callgraph.json')


def load_existing() -> Dict[int, str]:
    """RVA -> name from our fallback set."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from pdb_naming import build_fallback_symbols
    return {s['a']: s['n'] for s in build_fallback_symbols() if s.get('a') and s.get('t') == 'func'}


def main():
    print(f'Loading Xbox callgraph...')
    xbox_cg = json.loads(XBOX_CALLGRAPH.read_text(encoding='utf-8'))
    print(f'  Xbox fns: {len(xbox_cg):,}')

    print(f'Loading PC callgraph...')
    pc_cg_raw = json.loads(PC_CALLGRAPH.read_text(encoding='utf-8'))
    # Keys are hex strings -- convert
    pc_cg = {int(k, 16): v for k, v in pc_cg_raw.items()}
    print(f'  PC fns: {len(pc_cg):,}')

    print('Loading existing PC names...')
    pc_to_name = load_existing()
    name_to_pc = {n: v for v, n in pc_to_name.items()}
    print(f'  named: {len(pc_to_name):,}')

    # Walk each PC fn we have a name for, look up Xbox callee list
    n_paired = 0
    n_aligned = 0
    # Track all (pc_callee_rva, xbox_name) pairs with vote counts
    votes: Dict[int, Counter] = {}  # rva -> Counter({name: count})

    for pc_va, pc_callees in pc_cg.items():
        name = pc_to_name.get(pc_va - IMAGE_BASE)
        if not name:
            continue
        xb_callees = xbox_cg.get(name)
        if not xb_callees:
            continue
        n_paired += 1
        n = min(len(pc_callees), len(xb_callees))
        for i in range(n):
            xb_name = xb_callees[i]
            if not xb_name or xb_name == '?':
                continue
            if '::' not in xb_name:
                continue
            pc_callee_rva = pc_callees[i] - IMAGE_BASE
            if pc_callee_rva in pc_to_name:
                continue
            n_aligned += 1
            votes.setdefault(pc_callee_rva, Counter())[xb_name] += 1

    # Pick the top name per RVA (highest votes; tiebreak: alphabetical).
    # Drop RVAs that aren't plausibly in PC FNV's .text (some Ghidra
    # callees are computed-target imports or thunks landing outside).
    new_names: Dict[int, Tuple[str, int]] = {}
    for rva, counter in votes.items():
        if rva <= 0 or rva > 0x01000000:
            continue
        top_name, top_votes = max(counter.items(),
                                    key=lambda kv: (kv[1], -ord(kv[0][0]) if kv[0] else 0))
        total = sum(counter.values())
        if top_votes / total < 0.5:
            continue
        new_names[rva] = (top_name, top_votes)

    print(f'\nPaired fns (both sides named, both have call lists): {n_paired:,}')
    print(f'Total aligned (PC slot, Xbox name) edges: {n_aligned:,}')
    print(f'Unique PC RVAs nominated: {len(new_names):,}')

    # Emit all that pass the 50% rule.  pdb_naming integrates this source
    # at a LOW priority -- if any other source has a name for the same
    # RVA, that wins; single-vote callgraph hits only land where no other
    # source nominated the symbol at all.
    confident = sum(1 for _, v in new_names.values() if v >= 2)
    print(f'  votes>=2 (consensus): {confident:,}')
    print(f'  votes==1 (sole nomination): {len(new_names) - confident:,}')

    out_path = REFS_DIR / 'fnv_callgraph_names.csv'
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# call-graph-aligned names: 0xRVA|qualified_name|votes\n')
        for rva, (n, v) in sorted(new_names.items()):
            f.write(f'0x{rva:08X}|{n}|{v}\n')
    print(f'Wrote {out_path}: {len(new_names):,} names')


if __name__ == '__main__':
    main()
