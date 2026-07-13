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
from collections import Counter
import hashlib
import json
import os
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
from pe_layout import PELayout, x64_runtime_function_starts              # noqa: E402
from pe_version import get_pe_version                                     # noqa: E402
from pe_unwind import extract_runtime_functions                          # noqa: E402

ADDRLIB_DIR   = _PROJECT_DIR / "addresslibrary" / "starfield"
SOURCE_VER    = "1-16-236-0"
SOURCE_EXE    = _PROJECT_DIR / "exes" / "starfield" / "sf" / "Starfield.exe"
SOURCE_SHA256 = '1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351'
SOURCE_VERSIONLIB_SHA256 = 'ab42252c1b8308897e9a2374c0e717dadbfd0e5cec514df809f1a7c26f930c43'
STEAMLESS_CLI = _PROJECT_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"


def _ver_tuple(ver_str: str):
    return tuple(int(x) for x in ver_str.split("-"))


def _load_text(exe_path):
    raw = Path(exe_path)
    unpacked = Path(ensure_unpacked(raw, STEAMLESS_CLI)) if STEAMLESS_CLI.is_file() else raw
    return unpacked, load_pe_text(str(unpacked))


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_boundaries(path):
    rows = extract_runtime_functions(str(path)).get('runtime_functions', [])
    if not rows:
        raise ValueError('{} has no validated AMD64 runtime functions'.format(path))
    return ({int(row['begin_rva']): int(row['size']) for row in rows},
            {int(row['begin_rva']) for row in rows})


def run(target_ver: str, target_exe: str, limit: int = 0) -> int:
    print("=== Starfield versionlib generation (byte-sig port) ===")
    print(f"  Source: {SOURCE_VER} ({SOURCE_EXE.name})")
    print(f"  Target: {target_ver} ({Path(target_exe).name})")

    detected = get_pe_version(str(target_exe))
    expected = _ver_tuple(target_ver)
    detected4 = (tuple(detected or ()) + (0, 0, 0, 0))[:4]
    expected4 = (expected + (0, 0, 0, 0))[:4]
    if detected4 != expected4:
        print(f"  ERROR: target PE version {detected4} != requested {expected4}")
        return 1

    src_bin = ADDRLIB_DIR / f"versionlib-{SOURCE_VER}.bin"
    if (_sha256(SOURCE_EXE) != SOURCE_SHA256 or
            get_pe_version(str(SOURCE_EXE)) != _ver_tuple(SOURCE_VER) or
            not src_bin.is_file() or
            _sha256(src_bin) != SOURCE_VERSIONLIB_SHA256):
        print('  ERROR: anchor PE/versionlib provenance does not match 1.16.236')
        return 1
    src_db = AddressLibrary().load_bin(
        str(src_bin), expected_version=_ver_tuple(SOURCE_VER))
    if not src_db:
        print(f"  ERROR: source versionlib not found/empty: {src_bin}")
        return 1
    print(f"  Source versionlib: {len(src_db):,} ids")

    src_path, (_, src_text_rva, src_text) = _load_text(SOURCE_EXE)
    src_function_sizes, src_starts = _runtime_boundaries(src_path)
    text_end = src_text_rva + len(src_text)
    print(f"    source .text RVA={src_text_rva:#x} size={len(src_text):,}")

    func_ids = sorted(((str(i), r) for i, r in src_db.items()
                       if src_text_rva <= r < text_end and r in src_starts),
                      key=lambda t: t[1])
    full_function_count = len(func_ids)
    print(f"  function ids (rva in .text): {len(func_ids):,} "
          f"({len(src_db) - len(func_ids):,} data/other ids omitted)")
    if limit:
        func_ids = func_ids[:limit]
        print(f"  --limit: porting first {len(func_ids):,}")

    tgt_path, (_, tgt_text_rva, tgt_text) = _load_text(target_exe)
    _tgt_sizes, tgt_starts = _runtime_boundaries(tgt_path)
    print(f"    target .text RVA={tgt_text_rva:#x} size={len(tgt_text):,}")
    print("  Building target prefix index ...")
    tgt_idx = build_prefix_index(tgt_text, k=6)

    print("  Pass 1: exact 32-byte match ...")
    ported, stats = port_symbols(func_ids, src_text_rva, src_text,
                                 tgt_text_rva, tgt_text, tgt_idx,
                                 window=32, prefix_k=6, masked=False,
                                 progress_every=0,
                                 src_function_sizes=src_function_sizes,
                                 target_function_starts=tgt_starts)
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
                                           progress_every=0,
                                           src_function_sizes=src_function_sizes,
                                           target_function_starts=tgt_starts)
            ported.extend(ported2)
            print(f"    masked: ok={stats2['ok']:,}")
        except ImportError as e:
            print(f"    SKIPPED masked retry ({e}) -- install capstone+numpy")

    # A signature must resolve one source ID to one exact target runtime
    # function entry.  Drop target collisions rather than first/last-win.
    target_counts = Counter(rva for _, rva in ported)
    ported = [(name, rva) for name, rva in ported
              if target_counts[rva] == 1 and rva in tgt_starts]

    id_to_rva = {int(n): r for n, r in ported}
    pct = 100.0 * len(id_to_rva) / max(len(func_ids), 1)
    print(f"  ported: {len(id_to_rva):,} / {len(func_ids):,} ({pct:.1f}%)")

    canonical_bin = ADDRLIB_DIR / f"versionlib-{target_ver}.bin"
    existing_generated = False
    if canonical_bin.is_file():
        raw_header = canonical_bin.read_bytes()[:96]
        existing_generated = (len(raw_header) >= 84 and
                              b'generated' in raw_header[20:84].lower())
    official = {}
    if canonical_bin.is_file() and not existing_generated:
        official = AddressLibrary().load_bin(
            str(canonical_bin), expected_version=expected4)
    if official:
        overlap = sum(1 for s in id_to_rva if s in official)
        match = sum(1 for s, r in id_to_rva.items() if official.get(s) == r)
        rate = 100.0 * match / overlap if overlap else 0.0
        print(f"  vs official {target_ver} bin: overlap {overlap:,}, "
              f"match {match:,} ({rate:.1f}%), mismatch {overlap - match:,}, "
              f"net-new {len(id_to_rva) - overlap:,}")
        if overlap and match != overlap:
            print("  ERROR: generated mappings disagree with the official database; no output written")
            return 1
        print("  Official database already exists; validation complete, no generated output written")
        return 0

    if not id_to_rva:
        print("  ERROR: no boundary-validated unique mappings; no output written")
        return 1
    if limit:
        print("  --limit is research/self-test only; canonical versionlib publication disabled")
        return 0
    full_rate = len(id_to_rva) / float(max(full_function_count, 1))
    if len(id_to_rva) < 10000 or full_rate < 0.50:
        print("  ERROR: canonical publication coverage is too low "
              "({:,}/{:,}, {:.1%}); existing output preserved".format(
                  len(id_to_rva), full_function_count, full_rate))
        return 1

    # Canonical naming is intentional: AddressLibrary discovery selects only
    # versionlib-X-Y-Z-W.bin.  Never create a parallel '-generated' artifact
    # that no consumer can discover.  Official files returned above and are
    # never overwritten.
    out_bin = canonical_bin
    out_csv = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.csv"
    out_manifest = Path(str(out_bin) + '.identity.json')
    tmp_bin = Path(str(out_bin) + '.tmp')
    tmp_csv = Path(str(out_csv) + '.tmp')
    write_versionlib_bin_v5(str(tmp_bin), id_to_rva, _ver_tuple(target_ver),
                            name=f"Starfield {target_ver} (bytesig-generated)")
    write_addrlib_csv(str(tmp_csv), id_to_rva, version_label=target_ver,
                      note="unique bytesig + .pdata-boundary generated functions")
    os.replace(tmp_bin, out_bin)
    os.replace(tmp_csv, out_csv)
    manifest = {
        'schema_version': 2,
        'artifact': out_bin.name,
        'artifact_sha256': _sha256(out_bin),
        'csv_artifact': out_csv.name,
        'csv_sha256': _sha256(out_csv),
        'source_version': SOURCE_VER,
        'target_version': target_ver,
        'source_sha256': PELayout.read(str(src_path)).sha256,
        'target_sha256': PELayout.read(str(tgt_path)).sha256,
        'source_versionlib': src_bin.name,
        'source_versionlib_sha256': _sha256(src_bin),
        'method': 'unique byte signature constrained to AMD64 .pdata starts',
        'mapping_count': len(id_to_rva),
    }
    tmp_manifest = Path(str(out_manifest) + '.tmp')
    tmp_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n',
                            encoding='utf-8')
    os.replace(tmp_manifest, out_manifest)
    print(f"  wrote {out_bin}")
    print(f"  wrote {out_csv}")
    print(f"  wrote {out_manifest}")

    back = AddressLibrary().load_bin(
        str(out_bin), expected_version=expected4,
        expected_sha256=manifest['target_sha256'])
    print(f"  round-trip: reloaded {len(back):,} ids, equal={back == id_to_rva}")
    if back != id_to_rva:
        return 1
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
