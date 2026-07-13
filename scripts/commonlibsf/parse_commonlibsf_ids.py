#!/usr/bin/env python3
"""Parse CommonLibSF IDs*.h headers + versionlib bin -> CSV of (RVA, name, kind).

Inputs:
  - IDs.h        ~666 function IDs       e.g.  Actor::SetSkinTone -> ID 97400
  - IDs_RTTI.h   ~34k RTTI struct IDs    e.g.  RE::Actor -> ID NNN
  - IDs_VTABLE.h ~23k vtable IDs         e.g.  RE::Actor -> ID NNN (vtable address)
  - versionlib-1-16-236-0.bin (910k IDs)

Output: scripts/commonlibsf/refs/sf116_commonlib_names.csv
  columns: target_va, name, kind
  kinds: func | rtti | vtbl
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_DIR   = _SCRIPT_DIR.parent.parent

sys.path.insert(0, str(_SCRIPT_DIR))
from address_library import AddressLibrary

IDS_DIR       = _REPO_DIR / "extern" / "CommonLibSF" / "include" / "RE"
# Targets 1.16.236 by name (the "sf116_*" refs CSV namespace was authored
# against that build).  Override with --versionlib to point at a different
# bin -- e.g. for 1.16.242, pass
# ``--versionlib addresslibrary/starfield/versionlib-1-16-242-0.bin``.
VERSIONLIB    = _REPO_DIR / "addresslibrary" / "starfield" / "versionlib-1-16-236-0.bin"
OUT_CSV       = _SCRIPT_DIR / "refs" / "sf116_commonlib_names.csv"

IMAGE_BASE    = 0x140000000

# Each inline constexpr REL::ID looks like:
#   inline constexpr REL::ID Foo{ 12345 };
# or:
#   inline constexpr std::array<REL::ID, 1> Foo{ REL::ID(12345) };
# Track current namespace via 'namespace X::Y { ... }' nesting.

RE_NS_OPEN   = re.compile(r'namespace\s+([A-Za-z0-9_:]+)\s*\{')
RE_BRACE_OPEN  = re.compile(r'\{')
RE_BRACE_CLOSE = re.compile(r'\}')
RE_ID_DIRECT = re.compile(r'inline\s+constexpr\s+REL::ID\s+(\w+)\s*\{\s*([0-9]+)\s*\}')
RE_ID_ARRAY  = re.compile(r'inline\s+constexpr\s+std::array<\s*REL::ID,\s*\d+>\s*(\w+)\s*\{([^}]+)\}')
RE_ID_IN_ARRAY = re.compile(r'REL::ID\s*\(\s*([0-9]+)\s*\)')
RE_VERSIONLIB = re.compile(r'versionlib-(\d+)-(\d+)-(\d+)-(\d+)\.bin$', re.I)


def parse_ids_header(path: Path, kind: str) -> List[Tuple[int, str, str]]:
    """Return list of (id, full_qualified_name, kind)."""
    out: List[Tuple[int, str, str]] = []
    ns_stack: List[str] = []
    brace_depth = 0
    text = path.read_text(encoding="utf-8")
    # Strip line comments early to simplify
    text = re.sub(r'//[^\n]*', '', text)
    # Strip /* */ comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)

    # Walk char by char to track braces + namespaces
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == 'n' and text.startswith('namespace', i):
            m = RE_NS_OPEN.search(text, i)
            if m and m.start() == i:
                ns_name = m.group(1)
                # Move i past '{'
                i = m.end()
                ns_stack.append(ns_name)
                brace_depth += 1
                continue
        if c == '{':
            brace_depth += 1
            i += 1
            continue
        if c == '}':
            brace_depth -= 1
            if ns_stack and brace_depth < sum(len(x.split('::')) for x in ns_stack):
                ns_stack.pop()
            i += 1
            continue
        if text.startswith('inline', i):
            m = RE_ID_DIRECT.search(text, i, i + 200)
            if m and m.start() == i:
                ident, id_str = m.group(1), m.group(2)
                full = "::".join(ns_stack + [ident]) if ns_stack else ident
                out.append((int(id_str), full, kind))
                i = m.end()
                continue
            close = text.find('}', i)
            m2 = RE_ID_ARRAY.search(
                text, i, (close + 1) if close != -1 else len(text))
            if m2 and m2.start() == i:
                ident = m2.group(1)
                for index, id_str in enumerate(RE_ID_IN_ARRAY.findall(m2.group(2))):
                    element = ident if index == 0 else '{}_{}'.format(ident, index + 1)
                    full = "::".join(ns_stack + [element]) if ns_stack else element
                    out.append((int(id_str), full, kind))
                i = m2.end()
                continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--versionlib', default=str(VERSIONLIB),
                    help='Path to versionlib-X-Y-Z-W.bin (default: {})'.format(VERSIONLIB))
    ap.add_argument('--ids-dir', default=str(IDS_DIR),
                    help='CommonLibSF include/RE directory')
    ap.add_argument('--out', default=str(OUT_CSV), help='output CSV')
    args = ap.parse_args()
    ids_dir = Path(args.ids_dir)
    out_csv = Path(args.out)

    al = AddressLibrary()
    match = RE_VERSIONLIB.search(str(args.versionlib))
    if not match:
        raise RuntimeError('--versionlib must use versionlib-X-Y-Z-W.bin naming')
    expected_version = tuple(int(part) for part in match.groups())
    db = al.load_bin(args.versionlib, expected_version=expected_version)
    if not db:
        raise RuntimeError('version library contains no mappings')
    print(f"Loaded versionlib {Path(args.versionlib).name}: {len(db)} ID->RVA mappings")

    sources = [
        (ids_dir / "IDs.h", "func"),
        (ids_dir / "IDs_RTTI.h", "rtti"),
        (ids_dir / "IDs_VTABLE.h", "vtbl"),
    ]

    all_names: List[Tuple[int, str, str]] = []
    for path, kind in sources:
        if not path.is_file():
            print(f"  WARN: {path} missing")
            continue
        rows = parse_ids_header(path, kind)
        print(f"  parsed {len(rows):>6} entries from {path.name}")
        all_names.extend(rows)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    n_hit = 0
    n_no_rva = 0
    n_id_zero = 0
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["target_va", "name", "kind"])
        for rid, name, kind in all_names:
            if rid == 0:
                n_id_zero += 1
                continue
            rva = db.get(rid)
            if rva is None or rva == 0:
                n_no_rva += 1
                continue
            va = IMAGE_BASE + rva
            w.writerow([f"0x{va:x}", name, kind])
            n_hit += 1
    print(f"\nWrote {out_csv}")
    print(f"  hit:        {n_hit}")
    print(f"  id=0:       {n_id_zero}")
    print(f"  no_rva:     {n_no_rva}")
    # Kind breakdown
    kind_counts = {}
    with open(out_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            kind_counts[row["kind"]] = kind_counts.get(row["kind"], 0) + 1
    print("  by kind:")
    for k, c in kind_counts.items():
        print(f"    {k:6s} {c}")


if __name__ == "__main__":
    main()
