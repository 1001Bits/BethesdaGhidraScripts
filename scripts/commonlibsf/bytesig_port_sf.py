#!/usr/bin/env python3
"""Starfield cross-version address-library (versionlib) generator.

Generate a versionlib for an SF build that has NO official meh321 bin, by
byte-signature porting from the 1.16.236 anchor (which DOES ship one).  SF's
id namespace is append-only / consistent across the 1.16.x line, so a source
id refers to the same function in the target; byte-sig locates that function's
new address and we emit ``id -> target_rva`` as a drop-in **V5** versionlib.

This is the one place address-library *generation* is genuinely needed -- a
future SF patch has no official bin and a stable namespace (unlike F4 OG/VR,
whose disjoint namespaces make AE-id-keyed generation meaningless).

Scope: **function ids only** -- byte-sig matches code in ``.text``.  Data /
global ids don't byte-sig and are written as 0 (absent), which is exactly how
a function-only versionlib should present the ids it can't port.  Functions are
the bulk of what mods hook.

Validation: a 236 -> 236 self-port must reproduce the official 236 versionlib
for (nearly) every function id -- a binary matched to itself is exact, modulo
functions whose 32-byte prefix isn't unique (those need the masked retry).

Usage:
  python bytesig_port_sf.py --self-test [--limit N]
  python bytesig_port_sf.py --target-version 1-16-300-0 \
      --target-exe C:/path/to/Starfield.exe [--limit N]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_PROJECT_DIR / "scripts" / "core"))
sys.path.insert(0, str(_SCRIPT_DIR))

from bytesig_port  import load_pe_text, build_prefix_index, port_symbols  # noqa: E402
from addrlib_emit  import write_versionlib_bin_v5, write_addrlib_csv      # noqa: E402
from address_library import AddressLibrary                               # noqa: E402
from steamless     import ensure_unpacked                                # noqa: E402

ADDRLIB_DIR   = _PROJECT_DIR / "addresslibrary" / "starfield"
SOURCE_VER    = "1-16-236-0"
SOURCE_EXE    = _PROJECT_DIR / "exes" / "starfield" / "sf" / "Starfield.exe"
STEAMLESS_CLI = _PROJECT_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"


def _ver_tuple(ver_str: str):
    return tuple(int(x) for x in ver_str.split("-"))


def _load_text(exe_path):
    raw = Path(exe_path)
    unpacked = ensure_unpacked(raw, STEAMLESS_CLI) if STEAMLESS_CLI.is_file() else raw
    return load_pe_text(str(unpacked))


def run(target_ver: str, target_exe: str, limit: int = 0) -> int:
    print("=== Starfield versionlib generation (byte-sig port) ===")
    print(f"  Source: {SOURCE_VER} ({SOURCE_EXE.name})")
    print(f"  Target: {target_ver} ({Path(target_exe).name})")

    src_bin = ADDRLIB_DIR / f"versionlib-{SOURCE_VER}.bin"
    src_db = AddressLibrary().load_bin(str(src_bin))
    if not src_db:
        print(f"  ERROR: source versionlib not found/empty: {src_bin}")
        return 1
    print(f"  Source versionlib: {len(src_db):,} ids")

    _, src_text_rva, src_text = _load_text(SOURCE_EXE)
    text_end = src_text_rva + len(src_text)
    print(f"    source .text RVA={src_text_rva:#x} size={len(src_text):,}")

    func_ids = sorted(((str(i), r) for i, r in src_db.items()
                       if src_text_rva <= r < text_end), key=lambda t: t[1])
    print(f"  function ids (rva in .text): {len(func_ids):,} "
          f"({len(src_db) - len(func_ids):,} data/other ids omitted)")
    if limit:
        func_ids = func_ids[:limit]
        print(f"  --limit: porting first {len(func_ids):,}")

    _, tgt_text_rva, tgt_text = _load_text(target_exe)
    print(f"    target .text RVA={tgt_text_rva:#x} size={len(tgt_text):,}")
    print("  Building target prefix index ...")
    tgt_idx = build_prefix_index(tgt_text, k=6)

    print("  Pass 1: exact 32-byte match ...")
    ported, stats = port_symbols(func_ids, src_text_rva, src_text,
                                 tgt_text_rva, tgt_text, tgt_idx,
                                 window=32, prefix_k=6, masked=False,
                                 progress_every=0)
    print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
          f"ambig={stats['ambiguous_or_zero']:,}")
    done = {n for n, _ in ported}
    unmatched = [(n, r) for (n, r) in func_ids if n not in done]
    if unmatched:
        print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} ...")
        try:
            ported2, stats2 = port_symbols(unmatched, src_text_rva, src_text,
                                           tgt_text_rva, tgt_text, tgt_idx,
                                           window=48, prefix_k=6, masked=True,
                                           progress_every=0)
            ported.extend(ported2)
            print(f"    masked: ok={stats2['ok']:,}")
        except ImportError as e:
            print(f"    SKIPPED masked retry ({e}) -- install capstone+numpy")

    id_to_rva = {int(n): r for n, r in ported}
    pct = 100.0 * len(id_to_rva) / max(len(func_ids), 1)
    print(f"  ported: {len(id_to_rva):,} / {len(func_ids):,} ({pct:.1f}%)")

    out_bin = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.bin"
    out_csv = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.csv"
    write_versionlib_bin_v5(str(out_bin), id_to_rva, _ver_tuple(target_ver),
                            name=f"Starfield {target_ver} (bytesig-generated)")
    write_addrlib_csv(str(out_csv), id_to_rva, version_label=target_ver,
                      note="bytesig-generated function-only")
    print(f"  wrote {out_bin}")
    print(f"  wrote {out_csv}")

    back = AddressLibrary().load_bin(str(out_bin))
    print(f"  round-trip: reloaded {len(back):,} ids, equal={back == id_to_rva}")

    official = AddressLibrary().load_bin(str(ADDRLIB_DIR / f"versionlib-{target_ver}.bin"))
    if official:
        overlap = sum(1 for s in id_to_rva if s in official)
        match = sum(1 for s, r in id_to_rva.items() if official.get(s) == r)
        rate = 100.0 * match / overlap if overlap else 0.0
        print(f"  vs official {target_ver} bin: overlap {overlap:,}, "
              f"match {match:,} ({rate:.1f}%), mismatch {overlap - match:,}, "
              f"net-new {len(id_to_rva) - overlap:,}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true",
                    help="port 236->236 and compare to the official 236 bin")
    ap.add_argument("--target-version", help="e.g. 1-16-300-0")
    ap.add_argument("--target-exe", help="path to the target Starfield.exe")
    ap.add_argument("--limit", type=int, default=0,
                    help="port only the first N function ids (for testing)")
    args = ap.parse_args()
    if args.self_test:
        return run(SOURCE_VER, str(SOURCE_EXE), limit=args.limit)
    if not args.target_version or not args.target_exe:
        ap.error("provide --target-version and --target-exe, or --self-test")
    return run(args.target_version, args.target_exe, limit=args.limit)


if __name__ == "__main__":
    sys.exit(main())
