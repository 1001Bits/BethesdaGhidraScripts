#!/usr/bin/env python3
"""Pair PC FalloutNV function RVAs with Xbox PDB function names by
matching string xrefs in both binaries.

For each string that appears in both Xbox + PC FNV xref tables,
collect the {xbox_fn -> count} and {pc_fn_va -> count} mappings.

Three confidence tiers:

  TIER 1 -- unique-1-to-1: string has exactly one xrefer on each side.
    Direct name transfer.  Highest confidence.

  TIER 2 -- co-occurrence: PC function P shares >= K strings with
    Xbox function X, AND X is P's top Xbox match (no other Xbox
    function shares more strings with P).  Robust to noisy single-
    string matches.

  TIER 3 -- top-1 with margin: P's top Xbox match X shares >= K
    strings, and (count_for_X / count_for_runner_up) >= ratio.
    Allows naming functions whose only signal is one strong cluster.

Output: ``string_xref_names.csv`` with ``RVA|name|tier|votes`` per line.

Run:
    python match_string_xrefs.py \\
        <xbox_xrefs.txt> <pc_xrefs.txt> <publics.txt> [out.csv]
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def load_xbox_xrefs(path: Path) -> Dict[str, Dict[str, int]]:
    """<text>|<xbox_fn>|<count> -> {text: {xbox_fn: count}}"""
    out: Dict[str, Dict[str, int]] = {}
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.rsplit('|', 2)
        if len(p) != 3:
            continue
        text, fn, count_s = p
        try:
            c = int(count_s)
        except ValueError:
            continue
        out.setdefault(text, {})[fn] = c
    return out


def load_pc_xrefs(path: Path) -> Dict[str, Dict[int, int]]:
    """<text>|0x<fn_va>|<count> -> {text: {fn_va: count}}"""
    out: Dict[str, Dict[int, int]] = {}
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.rsplit('|', 2)
        if len(p) != 3:
            continue
        text, fn_va_s, count_s = p
        try:
            va = int(fn_va_s, 16)
            c = int(count_s)
        except ValueError:
            continue
        out.setdefault(text, {})[va] = c
    return out


_PUB_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S+)\s*$')


def load_publics_for_demangle(path: Path) -> Dict[int, str]:
    out = {}
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _PUB_RE.match(line)
            if m:
                out.setdefault(int(m.group(1), 16), m.group(2))
    return out


def demangle_batch(mangled_list):
    """Demangle MSVC names via dbghelp.UnDecorateSymbolName."""
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
    from pdb_symbols import undecorate
    return {m: undecorate(m) for m in mangled_list}


def strip_args(d: str) -> str:
    depth = 0
    for i in range(len(d) - 1, -1, -1):
        if d[i] == ')':
            depth += 1
        elif d[i] == '(':
            depth -= 1
            if depth == 0:
                return d[:i].rstrip()
    return d


def to_qualified(demangled: str) -> str:
    """Take ``ret_type Class::method(args) qual`` -> ``Class::method``."""
    s = strip_args(demangled)
    toks = s.split()
    return toks[-1] if toks else s


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    xbox_path = Path(sys.argv[1])
    pc_path   = Path(sys.argv[2])
    pub_path  = Path(sys.argv[3])
    out_path  = Path(sys.argv[4]) if len(sys.argv) > 4 else \
                Path('string_xref_names.csv')

    print(f'Loading Xbox xrefs: {xbox_path}')
    xbox_xrefs = load_xbox_xrefs(xbox_path)
    print(f'  strings: {len(xbox_xrefs):,}')

    print(f'Loading PC xrefs: {pc_path}')
    pc_xrefs = load_pc_xrefs(pc_path)
    print(f'  strings: {len(pc_xrefs):,}')

    common = set(xbox_xrefs) & set(pc_xrefs)
    print(f'  strings in BOTH: {len(common):,}')

    # Build a co-occurrence matrix: for each pc_fn_va, count how many
    # times each xbox_fn appears across all the strings that pc_fn references.
    # Each shared string contributes a vote for every (pc_fn x xbox_fn) pair
    # observed in it.
    pc_to_xbox_votes: Dict[int, Counter] = defaultdict(Counter)
    xbox_to_pc_votes: Dict[str, Counter] = defaultdict(Counter)
    pc_total_strings: Counter = Counter()  # how many shared strings each PC fn touches
    xbox_total_strings: Counter = Counter()

    for text in common:
        pc_fns  = pc_xrefs[text]
        xb_fns  = xbox_xrefs[text]
        for pv in pc_fns:
            pc_total_strings[pv] += 1
            for xn in xb_fns:
                pc_to_xbox_votes[pv][xn] += 1
                xbox_to_pc_votes[xn][pv] += 1
        for xn in xb_fns:
            xbox_total_strings[xn] += 1

    # Greedy bipartite matching: each PC fn pairs with at most one Xbox fn.
    # Iterate edges sorted by score (votes), claim greedy unless either side
    # is already claimed.  Score function weights both shared count and the
    # SIGNAL ratio (top votes / total votes for that PC fn).
    #
    # This kills the D3D-sink problem: D3D::DisassembleShader can only win
    # ONE PC fn (the one with highest votes).  Every other PC fn that voted
    # for it is free to pick a runner-up.

    # Build all candidate edges: (score, pc_va, xbox_fn, votes, signal)
    edges = []
    for pv, ctr in pc_to_xbox_votes.items():
        pc_total = pc_total_strings[pv]
        if pc_total == 0:
            continue
        for xn, votes in ctr.items():
            xb_total = xbox_total_strings[xn]
            # Signal: high when both sides "mostly agree" on each other.
            #   pc_signal = votes / pc_total
            #   xb_signal = votes / xb_total
            # Use the smaller of the two as the score (so a PC fn with 10
            # strings 9 of which go to Xbox-X scores high, even if Xbox-X
            # is the top destination for 100 PC fns).
            score_pc = votes / pc_total
            score_xb = votes / max(xb_total, 1)
            edges.append((min(score_pc, score_xb), votes, pv, xn))

    edges.sort(reverse=True)
    print(f'Total candidate edges: {len(edges):,}')

    # ----- Tier 1: reciprocal-unique high-signal pairs -----
    # Greedy claiming can assign an edge even when either endpoint has an
    # equally-good alternative.  Require the same strict top edge in both
    # directions so table/order accidents cannot force a name.
    eligible = [e for e in edges if e[0] >= 0.5 and e[1] >= 2]
    by_pc = defaultdict(list)
    by_xb = defaultdict(list)
    for e in eligible:
        score, votes, pv, xn = e
        by_pc[pv].append(e)
        by_xb[xn].append(e)

    def strict_best(items):
        ranked = sorted(items, reverse=True)
        if not ranked:
            return None
        if len(ranked) > 1 and ranked[0][:2] == ranked[1][:2]:
            return None
        return ranked[0]

    pc_claimed: Dict[int, Tuple[str, int]] = {}
    xb_claimed: Dict[str, int] = {}
    for pv, items in by_pc.items():
        edge = strict_best(items)
        if edge is None:
            continue
        score, votes, _pv, xn = edge
        reverse = strict_best(by_xb[xn])
        if reverse is None or reverse[2] != pv:
            continue
        pc_claimed[pv] = (xn, votes)
        xb_claimed[xn] = pv
    tier1 = dict(pc_claimed)
    print(f'Tier 1 (signal>=0.5, votes>=2, greedy): {len(tier1):,}')

    # ----- Tier 2: medium-signal -----
    for score, votes, pv, xn in edges:
        if score < 0.20 or votes < 1:
            break
        if pv in pc_claimed or xn in xb_claimed:
            continue
        pc_claimed[pv] = (xn, votes)
        xb_claimed[xn] = pv
    tier2 = {k: v for k, v in pc_claimed.items() if k not in tier1}
    print(f'Tier 2 (signal>=0.20, greedy): {len(tier2):,}')

    # ----- Tier 3: low-signal "best available" -----
    # Greedy edges sorted by score, no min threshold beyond claiming
    for score, votes, pv, xn in edges:
        if score <= 0.0:
            break
        if pv in pc_claimed or xn in xb_claimed:
            continue
        pc_claimed[pv] = (xn, votes)
        xb_claimed[xn] = pv
    tier3 = {k: v for k, v in pc_claimed.items() if k not in tier1 and k not in tier2}
    print(f'Tier 3 (any positive-signal, greedy): {len(tier3):,}')

    # ----- Tier 4: unique-1:1 string fallback -----
    for text in common:
        pcs = pc_xrefs[text]
        xbs = xbox_xrefs[text]
        if len(pcs) == 1 and len(xbs) == 1:
            pv = next(iter(pcs))
            xn = next(iter(xbs))
            if pv in pc_claimed or xn in xb_claimed:
                continue
            pc_claimed[pv] = (xn, pc_to_xbox_votes[pv][xn])
            xb_claimed[xn] = pv
    tier4 = {k: v for k, v in pc_claimed.items()
             if k not in tier1 and k not in tier2 and k not in tier3}
    print(f'Tier 4 (unique 1:1 string, greedy): {len(tier4):,}')

    # Tiers 2-4 remain useful as analyst review queues but are quarantined
    # from the automatic symbol corpus.  Emit only reciprocal Tier 1.
    all_matches = dict(tier1)
    print(f'Automatic PC functions named: {len(all_matches):,}')
    print(f'  quarantined weak candidates: '
          f'{len(tier2) + len(tier3) + len(tier4):,}')

    # Tier source mapping
    pv_to_tier = {pv: 1 for pv in tier1}
    pv_to_tier.update({pv: 2 for pv in tier2 if pv not in pv_to_tier})
    pv_to_tier.update({pv: 3 for pv in tier3 if pv not in pv_to_tier})
    pv_to_tier.update({pv: 4 for pv in tier4 if pv not in pv_to_tier})

    # Demangle all xbox names that won
    won_names = sorted({xn for xn, _ in all_matches.values()})
    print(f'Demangling {len(won_names):,} winning Xbox names...')
    demangled = demangle_batch(won_names)

    # Convert demangled -> Class::method (drop args/ret_type)
    qualified = {m: to_qualified(d) for m, d in demangled.items()}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# string-xref names: 0x<rva>|<qualified name>|tier|votes|<mangled>\n')
        f.write('# EVIDENCE=reciprocal-unique;min-signal=0.5;min-votes=2\n')
        IMAGE_BASE = 0x00400000
        for pv in sorted(all_matches):
            xn, votes = all_matches[pv]
            tier = pv_to_tier[pv]
            qname = qualified.get(xn, xn)
            # Skip names that don't look like qualified C++ (e.g. plain mangled left over)
            if not qname or '::' not in qname or qname.startswith('?'):
                continue
            rva = pv - IMAGE_BASE
            f.write(f'0x{rva:08X}|{qname}|T{tier}|{votes}|{xn}\n')
            written += 1
    print(f'Wrote {out_path}: {written:,} symbols')


if __name__ == '__main__':
    main()
