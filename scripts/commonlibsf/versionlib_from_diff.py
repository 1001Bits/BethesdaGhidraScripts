#!/usr/bin/env python3
"""Generate a Starfield versionlib from a binary-diff tool's output.

Alternative to byte-sig porting (``bytesig_port_sf.py``).  Given a precomputed
Source->Target address diff (IDADiffCalculator-style: whitespace columns
``Source Target Offset Type ...`` where Source addresses are version A and
Target addresses are version B) plus version A's official versionlib, emit
version B's versionlib by mapping each id's A-offset through the diff to its
B-offset.

Unlike byte signatures this can cover DATA (``var``) IDs as well as code.
Diff output is still heuristic evidence: only near-perfect, zero-complexity,
non-conflicting rows whose source and target PE section kinds agree are
accepted.  IDs absent from that conservative subset are omitted.

Diff format (hex VAs)::
    Source     Target     Offset  Type  Score  DifferenceComplexity  Debug
    140001000  140001000  0       func  1      0                     13

Usage:
  python versionlib_from_diff.py --source-version 1-16-242-0 \
      --target-version 1-16-244-0 --diff outputsorted.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_PROJECT_DIR / "scripts" / "core"))
sys.path.insert(0, str(_SCRIPT_DIR))

from addrlib_emit   import write_versionlib_bin_v5, write_addrlib_csv  # noqa: E402
from address_library import AddressLibrary                            # noqa: E402
from pe_layout import PELayout, x64_runtime_function_starts           # noqa: E402
from pe_version import get_pe_version                                 # noqa: E402

ADDRLIB_DIR  = _PROJECT_DIR / "addresslibrary" / "starfield"
DEFAULT_BASE = 0x140000000  # Starfield image base


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def parse_diff(path: str, source_base: int, target_base: int,
               source_layout: PELayout,
               target_layout: PELayout):
    """Parse only high-score, kind-consistent, non-conflicting diff rows."""
    src2tgt = {}
    counts = {"func": 0, "var": 0}
    conflicts = set()
    target_claims = {}
    source_starts = x64_runtime_function_starts(source_layout.path)
    target_starts = x64_runtime_function_starts(target_layout.path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            p = ln.split()
            if len(p) < 6 or p[3] not in ("func", "var"):
                continue
            try:
                s = int(p[0], 16) - source_base
                t = int(p[1], 16) - target_base
                score = float(p[4])
                complexity = float(p[5])
            except ValueError:
                continue
            if score < 0.99 or complexity != 0:
                continue
            expected_kind = 'func' if p[3] == 'func' else 'label'
            if (source_layout.classify_rva(s)[0] != expected_kind or
                    target_layout.classify_rva(t)[0] != expected_kind):
                continue
            if p[3] == 'func' and (s not in source_starts or
                                   t not in target_starts):
                continue
            previous = src2tgt.get(s)
            if previous is not None and previous != t:
                conflicts.add(s)
                continue
            counts[p[3]] += 1
            src2tgt[s] = t
            target_claims.setdefault(t, set()).add(s)
    for source in conflicts:
        src2tgt.pop(source, None)
    conflicting_targets = {
        target for target, sources in target_claims.items()
        if len(sources) != 1}
    if conflicting_targets:
        src2tgt = {source: target for source, target in src2tgt.items()
                   if target not in conflicting_targets}
    return src2tgt, counts


def run(source_ver: str, target_ver: str, diff_path: str,
        source_exe: str, target_exe: str,
        image_base: int = DEFAULT_BASE) -> int:
    print("=== Starfield versionlib generation (binary-diff) ===")
    print(f"  Source: {source_ver}   Target: {target_ver}")
    print(f"  Diff:   {diff_path}")

    source_layout = PELayout.read(source_exe)
    target_layout = PELayout.read(target_exe)
    if (source_layout.image_base != image_base or
            target_layout.image_base != image_base):
        print('  ERROR: --image-base does not match both exact PEs')
        return 1
    for label, exe, requested in (("source", source_exe, source_ver),
                                  ("target", target_exe, target_ver)):
        detected = get_pe_version(exe)
        detected4 = (tuple(detected or ()) + (0, 0, 0, 0))[:4]
        requested4 = (tuple(int(x) for x in requested.split('-')) +
                      (0, 0, 0, 0))[:4]
        if detected4 != requested4:
            print(f"  ERROR: {label} PE version {detected4} != requested {requested4}")
            return 1

    L = AddressLibrary()
    source_versionlib = ADDRLIB_DIR / f"versionlib-{source_ver}.bin"
    src_db = L.load_bin(
        str(source_versionlib),
        expected_version=tuple(int(x) for x in source_ver.split('-')),
        expected_sha256=source_layout.sha256)
    if not src_db:
        print(f"  ERROR: source versionlib not found/empty for {source_ver}")
        return 1
    print(f"  Source versionlib: {len(src_db):,} ids")

    src2tgt, counts = parse_diff(diff_path, source_layout.image_base,
                                 target_layout.image_base,
                                 source_layout, target_layout)
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

    canonical_bin = ADDRLIB_DIR / f"versionlib-{target_ver}.bin"
    existing_generated = False
    if canonical_bin.is_file():
        raw_header = canonical_bin.read_bytes()[:96]
        existing_generated = (len(raw_header) >= 84 and
                              b'generated' in raw_header[20:84].lower())
    official = (AddressLibrary().load_bin(
        str(canonical_bin),
        expected_version=tuple(int(x) for x in target_ver.split('-')))
        if canonical_bin.is_file() and not existing_generated else {})
    if official:
        overlap = sum(1 for s in id_to_rva if s in official)
        match = sum(1 for s, r in id_to_rva.items() if official.get(s) == r)
        rate = 100.0 * match / overlap if overlap else 0.0
        print(f"  vs official {target_ver}: overlap {overlap:,}, "
              f"match {match:,} ({rate:.2f}%), mismatch {overlap - match:,}, "
              f"net-new {len(id_to_rva) - overlap:,}")
        if overlap and match != overlap:
            print('  ERROR: diff mappings disagree with official target DB; no output written')
            return 1
        print('  Official database already exists; validation complete, no output written')
        return 0
    if not id_to_rva:
        print('  ERROR: no validated mappings; no output written')
        return 1
    coverage = len(id_to_rva) / float(max(len(src_db), 1))
    if len(id_to_rva) < 10000 or coverage < 0.05:
        print('  ERROR: canonical publication coverage is too low '
              '({:,}/{:,}, {:.1%}); existing output preserved'.format(
                  len(id_to_rva), len(src_db), coverage))
        return 1

    out_bin = canonical_bin
    out_csv = ADDRLIB_DIR / f"versionlib-{target_ver}-generated.csv"
    out_manifest = Path(str(out_bin) + '.identity.json')
    vt = tuple(int(x) for x in target_ver.split("-"))
    tmp_bin = Path(str(out_bin) + '.tmp')
    tmp_csv = Path(str(out_csv) + '.tmp')
    write_versionlib_bin_v5(str(tmp_bin), id_to_rva, vt,
                            name=f"Starfield {target_ver} (diff-generated)")
    write_addrlib_csv(str(tmp_csv), id_to_rva, version_label=target_ver,
                      note="score>=0.99, complexity=0, section-kind validated diff")
    os.replace(tmp_bin, out_bin)
    os.replace(tmp_csv, out_csv)
    manifest = {
        'schema_version': 2,
        'artifact': out_bin.name,
        'artifact_sha256': _sha256(out_bin),
        'csv_artifact': out_csv.name,
        'csv_sha256': _sha256(out_csv),
        'source_version': source_ver,
        'target_version': target_ver,
        'source_sha256': source_layout.sha256,
        'target_sha256': target_layout.sha256,
        'source_versionlib': source_versionlib.name,
        'source_versionlib_sha256': _sha256(source_versionlib),
        'diff_artifact': os.path.basename(diff_path),
        'diff_sha256': _sha256(diff_path),
        'mapping_count': len(id_to_rva),
        'method': 'binary diff score>=0.99 complexity=0 + PE section-kind validation',
    }
    tmp_manifest = Path(str(out_manifest) + '.tmp')
    tmp_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n',
                            encoding='utf-8')
    os.replace(tmp_manifest, out_manifest)
    print(f"  wrote {out_bin}")
    print(f"  wrote {out_csv}")
    print(f"  wrote {out_manifest}")

    back = AddressLibrary().load_bin(
        str(out_bin), expected_version=vt,
        expected_sha256=target_layout.sha256)
    print(f"  round-trip: reloaded {len(back):,} ids, equal={back == id_to_rva}")
    if back != id_to_rva:
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source-version", required=True, help="e.g. 1-16-242-0")
    ap.add_argument("--target-version", required=True, help="e.g. 1-16-244-0")
    ap.add_argument("--diff", required=True, help="Source/Target diff file")
    ap.add_argument("--source-exe", required=True,
                    help="exact source executable used by the diff")
    ap.add_argument("--target-exe", required=True,
                    help="exact target executable used by the diff")
    ap.add_argument("--image-base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    args = ap.parse_args()
    return run(args.source_version, args.target_version, args.diff,
               args.source_exe, args.target_exe,
               image_base=args.image_base)


if __name__ == "__main__":
    sys.exit(main())
