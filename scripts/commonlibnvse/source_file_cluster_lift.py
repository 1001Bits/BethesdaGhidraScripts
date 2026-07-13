#!/usr/bin/env python3
"""Source-file-anchored positional name lift.

PC FNV strings contain ~160 ``__FILE__`` source-path literals like
``<source-root>\\Fallout Shared\\BaseExtraList.cpp``.

Every function whose source lives in BaseExtraList.cpp embeds an xref
to that path string (from an ``assert``/``LOG`` macro using __FILE__).
We use these to:

  1. Cluster PC functions by .cpp file (xref-er = compiland member).
  2. Pull every Xbox PDB function name whose ``Class::`` prefix matches
     a class that's primarily in that .cpp (filename match).
  3. Sort both lists by RVA (PC text order == Xbox PDB-emission order
     within a compiland), and pair UNMAPPED PC RVAs to UNCLAIMED PDB
     names positionally.

Only assigns names that aren't already in the existing fallback set.

Output: ``fnv_source_file_names.csv`` with ``RVA|name|cpp_basename|<mangled>``.

Run:
    python source_file_cluster_lift.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
IMAGE_BASE = 0x00400000

from paths import artifact
PC_STRINGS         = artifact('fnv_pc_strings.txt')
PC_STRING_XREFS    = artifact('fnv_pc_string_xrefs.txt')
PDB_PUBLICS        = artifact('Fallout_Debug_publics.txt')
PDB_FUNCS_JSON     = artifact('Fallout_Debug_funcs.json')

sys.path.insert(0, str(SCRIPT_DIR.parent / 'core'))
from pdb_symbols import undecorate  # noqa: E402


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_pc_strings_with_cpp(path: Path) -> Dict[int, Tuple[str, str]]:
    """Return {string_va: (full_text, cpp_basename)} for strings that
    look like a __FILE__ path (end in .cpp)."""
    out = {}
    rx = re.compile(r'([A-Za-z][A-Za-z0-9_]*)\.cpp', re.IGNORECASE)
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
        text = p[2].replace('\\\\', '\\')
        if '.cpp' not in text.lower():
            continue
        m = rx.search(text)
        if not m:
            continue
        out[va] = (text, m.group(1))
    return out


def load_pc_string_xrefs(path: Path) -> Dict[int, Dict[int, int]]:
    """Returns {string_va_int: {fn_va: count}}.  Re-derives string_va by
    looking up text in a passed-in map (since the file is keyed by text)."""
    # NB: re-key on string text -> we don't have VA in the xrefs file.
    # Instead we collect by text and let caller index.
    pass


def load_pc_xrefs_by_text(path: Path) -> Dict[str, Dict[int, int]]:
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
            c  = int(count_s)
        except ValueError:
            continue
        out.setdefault(text, {})[va] = c
    return out


_PUB_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S+)\s*$')


def load_publics(path: Path) -> List[Tuple[int, str]]:
    """[(rva, mangled), ...] sorted by rva.  Drops vtable symbols (??_*)."""
    out = []
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _PUB_RE.match(line)
            if not m:
                continue
            mangled = m.group(2)
            if mangled.startswith('??_'):
                continue
            out.append((int(m.group(1), 16), mangled))
    out.sort()
    return out


def load_existing_fallback_addrs() -> Set[int]:
    """Every RVA already named via OTHER fallback sources (not source_file
    itself -- otherwise prior runs of this script would self-suppress
    every subsequent run)."""
    from pdb_naming import build_fallback_symbols
    return {s['a'] for s in build_fallback_symbols()
            if s.get('a') and s.get('src') != 'source_file'}


def load_anchors(path: Path) -> List[int]:
    """Anchors from dump_fnv_anchors.py."""
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        try:
            out.append(int(ln, 16) if ln.lower().startswith('0x') else int(ln))
        except ValueError:
            continue
    return sorted(out)


# ---------------------------------------------------------------------------
# Demangle PDB names -> Class::method
# ---------------------------------------------------------------------------

def to_qualified(demangled: str) -> str:
    """``ret_type Class::method(args) qual`` -> ``Class::method``."""
    s = demangled
    depth = 0
    for i in range(len(s) - 1, -1, -1):
        if s[i] == ')':
            depth += 1
        elif s[i] == '(':
            depth -= 1
            if depth == 0:
                s = s[:i].rstrip()
                break
    toks = s.split()
    return toks[-1] if toks else s


def class_of(qname: str) -> str:
    """``Class::method`` -> ``Class`` (last :: prefix)."""
    if '::' in qname:
        return qname.rsplit('::', 1)[0]
    return ''


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f'Loading PC .cpp source-path strings...')
    cpp_strings = load_pc_strings_with_cpp(PC_STRINGS)
    print(f'  {len(cpp_strings):,} .cpp path strings')

    print(f'Loading PC string xrefs...')
    pc_xrefs_by_text = load_pc_xrefs_by_text(PC_STRING_XREFS)

    # Build {cpp_basename: set(pc_rvas)} from .cpp string xrefs
    cpp_to_pc_rvas: Dict[str, Set[int]] = {}
    cpp_path_for_basename: Dict[str, str] = {}
    n_paths_with_xrefs = 0
    for va, (text, base) in cpp_strings.items():
        # The xrefs table is keyed by escaped string text
        esc = text.replace('|', '\\|').replace('\n', '\\n').replace('\r', '\\r')[:200]
        # Try both forms (escaped/not) since extract_pc_fnv_string_xrefs
        # writes escaped
        hits = pc_xrefs_by_text.get(esc) or pc_xrefs_by_text.get(text) or {}
        if not hits:
            continue
        n_paths_with_xrefs += 1
        cpp_to_pc_rvas.setdefault(base, set()).update(hits.keys())
        cpp_path_for_basename[base] = text
    print(f'  .cpp paths with PC xrefs: {n_paths_with_xrefs}')
    print(f'  distinct .cpp basenames: {len(cpp_to_pc_rvas)}')

    # Prefer pretty-dump JSON (precise per-class function lists with VAs)
    # over publics (heuristic demangle + class-prefix split).
    class_to_funcs: Dict[str, List[Tuple[int, str, str]]] = {}
    if PDB_FUNCS_JSON.is_file():
        import json
        print(f'Loading {PDB_FUNCS_JSON.name} (pretty-dump funcs)...')
        data = json.loads(PDB_FUNCS_JSON.read_text(encoding='utf-8'))
        for cls, fns in data.items():
            for fn in fns:
                class_to_funcs.setdefault(cls, []).append(
                    (fn['va'], fn['name'], fn.get('sig', fn['name'])))
        print(f'  classes (from pretty): {len(class_to_funcs):,}')
    else:
        print(f'Loading Xbox PDB publics (fallback)...')
        publics = load_publics(PDB_PUBLICS)
        print(f'  {len(publics):,} publics (non-vtable)')
        print('Demangling + grouping by class...')
        for rva, mangled in publics:
            try:
                demangled = undecorate(mangled)
            except Exception:
                continue
            qname = to_qualified(demangled)
            cls = class_of(qname)
            if not cls:
                continue
            class_to_funcs.setdefault(cls, []).append((rva, qname, mangled))
        print(f'  classes: {len(class_to_funcs):,}')

    print('Loading already-known RVAs to exclude from positional assignment...')
    known_rvas = load_existing_fallback_addrs()
    print(f'  {len(known_rvas):,} RVAs already named')

    print('Performing per-.cpp positional matching...')
    matches: List[Tuple[int, str, str, str]] = []  # (rva, qname, base, mangled)
    classes_used: Set[str] = set()
    skipped_no_match = 0

    for base, pc_rvas in cpp_to_pc_rvas.items():
        # PDB candidates: every class whose name == base, or starts with base
        # (e.g. BaseExtraList.cpp may define BaseExtraList, BaseExtraListImpl)
        pdb_funcs = []
        for cls, fns in class_to_funcs.items():
            if cls == base or cls.startswith(base + '<'):
                pdb_funcs.extend(fns)
        if not pdb_funcs:
            skipped_no_match += 1
            continue

        # Sort both lists by RVA (compiler emits in source order; linker
        # preserves order within a compiland)
        pc_sorted = sorted(pc_rvas)  # absolute VAs from xrefs file
        pdb_sorted = sorted(pdb_funcs, key=lambda x: x[0])

        # Filter PC VAs whose RVA is already in the known set
        pc_unmapped = [r for r in pc_sorted if (r - IMAGE_BASE) not in known_rvas]
        if not pc_unmapped:
            continue

        # Filter PDB funcs whose qname's PC counterpart is already named
        # (i.e. this name has already been assigned to some RVA in known_rvas)
        # Build a quick reverse lookup of "qualified names already in use"
        # to avoid assigning the same name to a 2nd RVA.
        from pdb_naming import build_fallback_symbols
        already_assigned_names = {s['n'] for s in build_fallback_symbols()}
        pdb_unclaimed = [f for f in pdb_sorted if f[1] not in already_assigned_names]
        if not pdb_unclaimed:
            continue

        # Positional pair (truncate to shorter list).  Allow n=1 since
        # many .cpp files contain only one or two non-virtual methods.
        n = min(len(pc_unmapped), len(pdb_unclaimed))
        if n < 1:
            continue
        # Loosened ratio: as long as the smaller set is not >5x smaller
        # than the larger, accept (positional assignment is robust to
        # missing items on either side -- they just shift the alignment).
        ratio = n / max(len(pc_unmapped), len(pdb_unclaimed))
        if ratio < 0.10:
            continue

        classes_used.add(base)
        for i in range(n):
            rva = pc_unmapped[i]
            _, qname, mangled = pdb_unclaimed[i]
            matches.append((rva, qname, base, mangled))

    print(f'  classes positionally matched: {len(classes_used)}')
    print(f'  classes skipped (no PDB candidate): {skipped_no_match}')

    # Dedup matches by RVA (keep first)
    seen = set()
    final = []
    for rva, qname, base, mangled in matches:
        if rva in seen:
            continue
        seen.add(rva)
        final.append((rva, qname, base, mangled))

    out_path = REFS_DIR / 'fnv_source_file_names.csv'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# source-file cluster names: 0x<rva>|qname|<cpp basename>|<mangled>\n')
        IMAGE_BASE_LOCAL = IMAGE_BASE
        for fn_va, qname, base, mangled in sorted(final):
            rva = fn_va - IMAGE_BASE_LOCAL
            f.write(f'0x{rva:08X}|{qname}|{base}|{mangled}\n')
    print(f'Wrote {out_path}: {len(final)} new positional names')


if __name__ == '__main__':
    main()
