#!/usr/bin/env python3
"""Iterative cross-binary call-graph alignment.

Each iteration of ``match_callgraph.py`` produces new (PC RVA -> name)
mappings.  Those newly-named functions can serve as anchors for the
NEXT iteration: their xbox counterparts have call lists, and at slot i
of those lists is the Xbox name we can now apply to the corresponding
PC callee.

Iterate until no new names are added.

We re-use match_callgraph.py's logic but feed it an accumulating
named-set each iteration via a side-channel file the loader reads.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
IMAGE_BASE = 0x00400000

from paths import artifact
XBOX_CG = artifact('Fallout_Debug_callgraph.json')
PC_CG   = artifact('fnv_pc_callgraph.json')
OUT_CSV = REFS_DIR / 'fnv_callgraph_names.csv'


def run_one_pass(xbox_cg, pc_cg, pc_named):
    """One iteration of the alignment.  Returns dict {rva: (name, votes)}."""
    votes: Dict[int, Counter] = {}
    n_paired = 0
    n_aligned = 0
    for pc_va, pc_callees in pc_cg.items():
        name = pc_named.get(pc_va - IMAGE_BASE)
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
            pc_rva = pc_callees[i] - IMAGE_BASE
            if pc_rva in pc_named:
                continue  # already named
            if pc_rva <= 0 or pc_rva > 0x01000000:
                continue
            n_aligned += 1
            votes.setdefault(pc_rva, Counter())[xb_name] += 1

    # Pick the top name per RVA with 50% rule
    new_names: Dict[int, Tuple[str, int]] = {}
    for rva, counter in votes.items():
        top_name, top_votes = max(counter.items(),
                                    key=lambda kv: (kv[1], -ord(kv[0][0]) if kv[0] else 0))
        total = sum(counter.values())
        if top_votes / total < 0.5:
            continue
        new_names[rva] = (top_name, top_votes)
    return n_paired, n_aligned, new_names


def main():
    print('Loading Xbox callgraph...')
    xbox_cg = json.loads(XBOX_CG.read_text(encoding='utf-8'))
    print(f'  {len(xbox_cg):,} Xbox fns')

    print('Loading PC callgraph...')
    pc_cg_raw = json.loads(PC_CG.read_text(encoding='utf-8'))
    pc_cg = {int(k, 16): v for k, v in pc_cg_raw.items()}
    print(f'  {len(pc_cg):,} PC fns')

    print('Loading existing fallback names...')
    sys.path.insert(0, str(SCRIPT_DIR))
    from pdb_naming import build_fallback_symbols
    base_names = {s['a']: s['n'] for s in build_fallback_symbols()
                  if s.get('a') and s.get('t') == 'func'}
    print(f'  starting named: {len(base_names):,}')

    # Iterate: accumulate names + re-pair using growing named set
    accumulated: Dict[int, Tuple[str, int]] = {}
    pc_named = dict(base_names)
    for it in range(1, 11):
        n_paired, n_aligned, new_names = run_one_pass(xbox_cg, pc_cg, pc_named)
        # Don't re-add names that already exist via base or earlier iter
        truly_new = {rva: (n, v) for rva, (n, v) in new_names.items()
                     if rva not in pc_named}
        if not truly_new:
            print(f'\niter {it}: converged (no new names)')
            break
        print(f'iter {it}: paired={n_paired:,}  aligned={n_aligned:,}  '
              f'new={len(truly_new):,}')
        for rva, (n, v) in truly_new.items():
            cur = accumulated.get(rva)
            if cur is None or cur[1] < v:
                accumulated[rva] = (n, v)
            pc_named[rva] = n

    # Write
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open('w', encoding='utf-8') as f:
        f.write('# iterative call-graph alignment: 0xRVA|qualified_name|votes\n')
        for rva, (n, v) in sorted(accumulated.items()):
            f.write(f'0x{rva:08X}|{n}|{v}\n')
    print(f'\nTotal accumulated: {len(accumulated):,} names')
    print(f'Wrote {OUT_CSV}')


if __name__ == '__main__':
    main()
