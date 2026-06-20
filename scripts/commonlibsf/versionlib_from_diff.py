#!/usr/bin/env python3
"""Generate a Starfield versionlib from a binary-diff tool's output.

Alternative to byte-sig porting (``bytesig_port_sf.py``).  Given a precomputed
Source->Target address diff (IDADiffCalculator-style: whitespace columns
``Source Target Offset Type ...`` where Source addresses are version A and
Target addresses are version B) plus version A's official versionlib, emit
version B's versionlib by mapping each id's A-offset through the diff to its
B-offset.

vs byte-sig: this needs an external diff tool, but is 100% accurate on every
entry the diff covers AND covers DATA (``var``) ids too -- byte-sig is
function-only and ~96% exact.  Coverage is bounded by what the diff tool
matched; ids absent from the diff are omitted (we don't assume they're
unchanged -- empirically many are not).

Diff format (hex VAs)::
    Source     Target     Offset  Type  Score  DifferenceComplexity  Debug
    140001000  140001000  0       func  1      0                     13

Usage:
  python versionlib_from_diff.py --source-version 1-16-242-0 \
      --target-version 1-16-244-0 --diff outputsorted.txt
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_PROJECT_DIR / "scripts" / "core"))
sys.path.insert(0, str(_SCRIPT_DIR))

from addrlib_emit   import write_versionlib_bin_v5, write_addrlib_csv  # noqa: E402
from address_library import AddressLibrary                            # noqa: E402

ADDRLIB_DIR  = _PROJECT_DIR / "addresslibrary" / "starfield"
DEFAULT_BASE = 0x140000000  # Starfield image base


def parse_diff(path: str, image_base: int):
    """Parse a Source/Target diff into {src_rva: tgt_rva} for func+var rows."""
    src2tgt = {}
    counts = {"func": 0, "var": 0}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            p = ln.split()
            if len(p) < 4 or p[3] not in ("func", "var"):
                continue
            try:
                s = int(p[0], 16) - image_base
                t = int(p[1], 16) - image_base
            except ValueError:
                continue
            counts[p[3]] += 1
            src2tgt[s] = t
    return src2tgt, counts


def run(source_ver: str, target_ver: str, diff_path: str,
        image_base: int = DEFAULT_BASE) -> int:
    print("=== Starfield versionlib generation (binary-diff) ===")
    print(f"  Source: {source_ver}   Target: {target_ver}")
    print(f"  Diff:   {diff_path}")

    L = AddressLibrary()
    src_db = L.load_bin(str(ADDRLIB_DIR / f"versionlib-{source_ver}.bin"))
    if not src_db:
        print(f"  ERROR: source versionlib not found/empty for {source_ver}")
        return 1
    print(f"  Source versionlib: {len(src_db):,} ids")

    src2tgt, counts = parse_diff(diff_path, image_base)
    print(f"  Diff entries: func={counts['func']:,} var={counts['var']:,} "
          f"(unique src {len(src2tgt):,})")

    id_to_rva = {}
    no_entry = 0
    for i, r in src_db.items():
        t = src2tgt.get(r)
        if t is None:
            no_entry += 1
        else:
            id_to_rva[i] = t
    print(f"  mapped id->target: {len(id_to_rva):,} "
          f"({no_entry:,} ids had no diff entry, omitted)")

    out_bin = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.bin"
    out_csv = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.csv"
    vt = tuple(int(x) for x in target_ver.split("-"))
    write_versionlib_bin_v5(str(out_bin), id_to_rva, vt,
                            name=f"Starfield {target_ver} (diff-generated)")
    write_addrlib_csv(str(out_csv), id_to_rva, version_label=target_ver,
                      note="diff-generated func+var")
    print(f"  wrote {out_bin}")
    print(f"  wrote {out_csv}")

    back = AddressLibrary().load_bin(str(out_bin))
    print(f"  round-trip: reloaded {len(back):,} ids, equal={back == id_to_rva}")

    official = AddressLibrary().load_bin(str(ADDRLIB_DIR / f"versionlib-{target_ver}.bin"))
    if official:
        overlap = sum(1 for s in id_to_rva if s in official)
        match = sum(1 for s, r in id_to_rva.items() if official.get(s) == r)
        rate = 100.0 * match / overlap if overlap else 0.0
        print(f"  vs official {target_ver}: overlap {overlap:,}, "
              f"match {match:,} ({rate:.2f}%), mismatch {overlap - match:,}, "
              f"net-new {len(id_to_rva) - overlap:,}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source-version", required=True, help="e.g. 1-16-242-0")
    ap.add_argument("--target-version", required=True, help="e.g. 1-16-244-0")
    ap.add_argument("--diff", required=True, help="Source/Target diff file")
    ap.add_argument("--image-base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    args = ap.parse_args()
    return run(args.source_version, args.target_version, args.diff,
               image_base=args.image_base)


if __name__ == "__main__":
    sys.exit(main())
