#!/usr/bin/env python3
"""Phase 2 of SF 1.7 -> SF 1.16.236 byte-sig naming port.

Inputs are explicit command-line arguments.  The XML/.bytes export is accepted
only when its .text bytes agree with an exact SHA-bound Starfield 1.7.36 PE;
the target must likewise be the exact SHA supplied by the caller.

Output:
  - scripts/commonlibsf/refs/sf116_ported_names.csv with columns
    target_va,name,pass (pass = "exact32" or "masked48").

Pipeline:
  1. Parse source XML MEMORY_SECTION elements to find .text RVA/length/
     FILE_OFFSET in the .bytes file.
  2. Stream the source XML for FUNCTION entries; filter noise (FUN_*,
     thunk_*, _dynamic_initializer*, _lambda_*).
  3. Load target .text via bytesig_port.load_pe_text + build_prefix_index.
  4. Pass 1: port with exact 32-byte match.
  5. Pass 2: re-port the misses with masked 48-byte match (wildcards
     rel32/rip-rel operands).
  6. Emit ported CSV.

Phase 3 (apply names to 1.16.236 Ghidra DB) is separate.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
import hashlib
import json
import os
import sys
import time
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(os.path.dirname(_SCRIPT_DIR))
sys.path.insert(0, os.path.join(_PROJECT_DIR, "scripts", "core"))

from bytesig_port import (  # noqa: E402
    load_pe_text, build_prefix_index, port_symbols,
)
from binary_identity import inspect_pe  # noqa: E402
from pe_unwind import extract_runtime_functions  # noqa: E402

DEFAULT_OUT = Path(_SCRIPT_DIR) / "refs" / "sf116_ported_names.csv"
SOURCE_VERSION = [1, 7, 36, 0]
TARGET_VERSION = [1, 16, 236, 0]
EVIDENCE_SCHEMA = "bgs-enrichment-evidence-v2"
EVIDENCE_KIND = "sf17-to-sf116-bytesig-names"

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")
NOISE_SUBSTRINGS = (
    "_dynamic_initializer_for_",
    "_lambda_",
    "API-MS-",
)


def is_noise(name: str) -> bool:
    return (any(name.startswith(p) for p in NOISE_PREFIXES)
            or any(s in name for s in NOISE_SUBSTRINGS))


def _address_int(s: str) -> int:
    """Parse an address from Ghidra XML (bare addresses are hexadecimal)."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def _quantity_int(s: str) -> int:
    """Parse XML LENGTH/FILE_OFFSET, whose unprefixed form is decimal."""
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_text_section(xml_path: str):
    """Return (text_start_va, text_length, text_file_offset, bytes_name).

    First .text MEMORY_SECTION that has a MEMORY_CONTENTS file-offset
    pointer wins (some XMLs have additional uninitialized .text segments
    without backing bytes -- we don't care about those).
    """
    for _event, elem in ET.iterparse(xml_path, events=("end",)):
        # Keep MEMORY_CONTENTS attributes alive until its parent
        # MEMORY_SECTION end event.  Clearing it here would make a perfectly
        # valid section look unbacked.
        if _local_tag(elem.tag) == "MEMORY_CONTENTS":
            continue
        if _local_tag(elem.tag) != "MEMORY_SECTION" \
                or elem.attrib.get("NAME") != ".text":
            elem.clear()
            continue
        contents = next((child for child in elem
                         if _local_tag(child.tag) == "MEMORY_CONTENTS"), None)
        if contents is not None and contents.attrib.get("FILE_OFFSET") is not None:
            try:
                return (_address_int(elem.attrib["START_ADDR"]),
                        _quantity_int(elem.attrib["LENGTH"]),
                        _quantity_int(contents.attrib["FILE_OFFSET"]),
                        contents.attrib.get("FILE_NAME", ""))
            except (KeyError, ValueError) as exc:
                raise RuntimeError("invalid .text MEMORY_SECTION in XML") from exc
        elem.clear()
    raise RuntimeError("no .text MEMORY_SECTION with FILE_OFFSET found in XML")


def stream_function_entries(xml_path: str):
    """Yield (rva, name) for non-noise FUNCTION elements."""
    for _event, elem in ET.iterparse(xml_path, events=("end",)):
        if _local_tag(elem.tag) == "FUNCTION":
            name = elem.attrib.get("NAME", "").strip()
            entry = elem.attrib.get("ENTRY_POINT")
            if entry and name and not is_noise(name):
                try:
                    yield _address_int(entry), name
                except ValueError:
                    pass
        elem.clear()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _runtime_boundaries(path: Path):
    rows = extract_runtime_functions(str(path)).get("runtime_functions", [])
    if not rows:
        raise RuntimeError(f"{path} has no validated AMD64 runtime functions")
    return ({int(row["begin_rva"]): int(row["size"]) for row in rows},
            {int(row["begin_rva"]) for row in rows})


def _reconcile_proposals(proposals, token_to_name, token_to_source,
                         target_starts, image_base):
    """Keep a reciprocal one-name/one-source/one-target relation."""
    target_counts = Counter(rva for _token, rva, _method in proposals)
    # Count ownership across the complete eligible source corpus, not just
    # successful matches.  Otherwise one of two same-name/source aliases can
    # fail matching and make the survivor look falsely unique.
    name_counts = Counter(token_to_name.values())
    source_counts = Counter(token_to_source.values())
    rows = [
        (f"0x{image_base + rva:x}", token_to_name[token], method)
        for token, rva, method in proposals
        if (target_counts[rva] == 1 and
            name_counts[token_to_name[token]] == 1 and
            source_counts[token_to_source[token]] == 1 and
            rva in target_starts)]
    return sorted(rows, key=lambda row: (int(row[0], 16), row[1]))


def _atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".sf-port-", suffix=".tmp",
                                dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-xml", required=True, type=Path)
    parser.add_argument("--source-bytes", required=True, type=Path)
    parser.add_argument("--source-exe", required=True, type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--target-exe", required=True, type=Path)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args()


def main():
    args = _parse_args()
    src_xml = args.source_xml.resolve()
    src_bytes_path = args.source_bytes.resolve()
    src_pe = args.source_exe.resolve()
    tgt_pe = args.target_exe.resolve()
    out_csv = args.out.resolve()
    for path in (src_xml, src_bytes_path, src_pe, tgt_pe):
        if not path.is_file():
            raise SystemExit(f"ERROR: input missing: {path}")
    source_manifest = inspect_pe(str(src_pe))
    target_manifest = inspect_pe(str(tgt_pe))
    if source_manifest["sha256"] != args.source_sha256.lower():
        raise SystemExit("ERROR: source PE SHA-256 mismatch")
    if target_manifest["sha256"] != args.target_sha256.lower():
        raise SystemExit("ERROR: target PE SHA-256 mismatch")
    if source_manifest.get("file_version") != SOURCE_VERSION:
        raise SystemExit(f"ERROR: source must be Starfield {SOURCE_VERSION}")
    if target_manifest.get("file_version") != TARGET_VERSION:
        raise SystemExit(f"ERROR: target must be Starfield {TARGET_VERSION}")

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    print(f"SRC_XML   = {src_xml}")
    print(f"SRC_BYTES = {src_bytes_path}")
    print(f"SRC_PE    = {src_pe}")
    print(f"TGT_PE    = {tgt_pe}")
    print(f"OUT_CSV   = {out_csv}")
    print()

    # 1. Parse source .text mapping
    t0 = time.time()
    print("Parsing source .text MEMORY_SECTION header...")
    src_text_va, src_text_len, src_text_file_off, xml_bytes_name = \
        parse_text_section(str(src_xml))
    if (not xml_bytes_name or
            Path(xml_bytes_name.replace('\\', '/')).name != src_bytes_path.name):
        raise SystemExit(
            "ERROR: source XML MEMORY_CONTENTS names a different .bytes file")
    print(f"  .text VA          = 0x{src_text_va:x}")
    print(f"  .text length      = 0x{src_text_len:x}  ({src_text_len/1024/1024:.1f} MB)")
    print(f"  .text file offset = 0x{src_text_file_off:x}")
    print(f"  parsed in {time.time()-t0:.1f}s")

    # 2. Load source .text bytes
    print("Loading source .text bytes...")
    with open(src_bytes_path, "rb") as fh:
        fh.seek(src_text_file_off)
        exported_text = fh.read(src_text_len)
    if len(exported_text) != src_text_len:
        raise SystemExit(f"ERROR: source bytes truncated ({len(exported_text)} != {src_text_len})")
    src_image_base, src_text_rva, src_text = load_pe_text(str(src_pe))
    if src_text_va - src_image_base != src_text_rva:
        raise SystemExit("ERROR: XML .text address does not match source PE")
    if len(exported_text) < len(src_text) or exported_text[:len(src_text)] != src_text:
        raise SystemExit("ERROR: XML .bytes .text does not match exact source PE")
    if any(exported_text[len(src_text):]):
        raise SystemExit("ERROR: XML .bytes has nonzero data beyond PE raw .text")
    src_function_sizes, src_starts = _runtime_boundaries(src_pe)
    _target_sizes, target_starts = _runtime_boundaries(tgt_pe)
    print(f"  src_text_rva = 0x{src_text_rva:x} ({len(src_text)} verified bytes)")

    # 3. Stream-parse FUNCTION entries
    print("Streaming source FUNCTION entries...")
    t1 = time.time()
    src_named = []
    token_to_name = {}
    token_to_source = {}
    n_total = 0
    seen_source = set()
    for rva_va, name in stream_function_entries(str(src_xml)):
        n_total += 1
        rva = rva_va - src_image_base
        if rva not in src_starts or (rva, name) in seen_source:
            continue
        seen_source.add((rva, name))
        token = str(len(token_to_name))
        token_to_name[token] = name
        token_to_source[token] = rva
        src_named.append((token, rva))
    print(f"  {n_total} named (post-filter) functions")
    print(f"  parsed in {time.time()-t1:.1f}s")

    # 4. Load target .text
    print(f"\nLoading target .text from PE: {tgt_pe}")
    tgt_image_base, tgt_text_rva, tgt_text = load_pe_text(str(tgt_pe))
    print(f"  tgt image_base = 0x{tgt_image_base:x}")
    print(f"  tgt .text rva  = 0x{tgt_text_rva:x}")
    print(f"  tgt .text size = 0x{len(tgt_text):x}  ({len(tgt_text)/1024/1024:.1f} MB)")

    # 5. Build prefix index for target
    print("Building target prefix index (k=6)...")
    t2 = time.time()
    tgt_idx = build_prefix_index(tgt_text, k=6)
    print(f"  {len(tgt_idx)} unique 6-byte prefixes  ({time.time()-t2:.1f}s)")

    # 6. Pass 1: exact 32-byte match
    print("\n=== Pass 1: exact 32-byte match ===")
    t3 = time.time()
    pass1_ported, pass1_stats = port_symbols(
        src_named, src_text_rva, src_text,
        tgt_text_rva, tgt_text, tgt_idx,
        window=32, prefix_k=6, masked=False,
        progress_every=5000,
        src_function_sizes=src_function_sizes,
        target_function_starts=target_starts,
    )
    print(f"Pass 1: {len(pass1_ported)}/{len(src_named)} ported  "
          f"(noprefix={pass1_stats['no_prefix']}  ambig={pass1_stats['ambiguous_or_zero']}  "
          f"missing_src={pass1_stats['missing_src']})  ({time.time()-t3:.0f}s)")

    pass1_tokens = {n for n, _ in pass1_ported}
    misses = [(n, r) for (n, r) in src_named if n not in pass1_tokens]
    print(f"  misses to retry: {len(misses)}")

    # 7. Pass 2: masked 48-byte match on misses
    print("\n=== Pass 2: masked 48-byte match on misses ===")
    t4 = time.time()
    try:
        pass2_ported, pass2_stats = port_symbols(
            misses, src_text_rva, src_text,
            tgt_text_rva, tgt_text, tgt_idx,
            window=48, prefix_k=6, masked=True,
            progress_every=5000,
            src_function_sizes=src_function_sizes,
            target_function_starts=target_starts,
        )
    except ImportError as e:
        print(f"  capstone not available ({e}); skipping masked pass")
        pass2_ported, pass2_stats = [], {'ok': 0, 'no_prefix': 0, 'ambiguous_or_zero': 0, 'missing_src': 0}
    print(f"Pass 2: {len(pass2_ported)} additional matches  "
          f"(noprefix={pass2_stats['no_prefix']}  ambig={pass2_stats['ambiguous_or_zero']})  "
          f"({time.time()-t4:.0f}s)")

    # 8. Combine + dedupe (Pass 1 wins on duplicates)
    proposals = [(token, rva, "exact32") for token, rva in pass1_ported]
    proposals.extend((token, rva, "masked48") for token, rva in pass2_ported)
    rows = _reconcile_proposals(
        proposals, token_to_name, token_to_source,
        target_starts, tgt_image_base)
    minimum = max(1, min(1000, len(src_named) // 10))
    if len(rows) < minimum:
        raise SystemExit(
            f"ERROR: only {len(rows)} reciprocal boundary-valid matches; "
            f"minimum coverage is {minimum}; existing output preserved")

    fd, temp_csv = tempfile.mkstemp(prefix=".sf-port-", suffix=".tmp",
                                    dir=str(out_csv.parent))
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["target_va", "name", "pass"])
            w.writerows(rows)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_csv, out_csv)
    finally:
        if os.path.exists(temp_csv):
            os.unlink(temp_csv)

    identity = {
        "schema": EVIDENCE_SCHEMA,
        "kind": EVIDENCE_KIND,
        "program_name": tgt_pe.name,
        "target_sha256": target_manifest["sha256"],
        "evidence_sha256": _sha256(out_csv),
        "source_sha256": source_manifest["sha256"],
        "source_version": source_manifest["file_version"],
        "source_xml_sha256": _sha256(src_xml),
        "source_bytes_sha256": _sha256(src_bytes_path),
        "target_version": target_manifest["file_version"],
        "address_coordinate": "VA",
        "image_base": tgt_image_base,
        "pointer_size": 8,
        "method": "reciprocal unique bytesig constrained to AMD64 runtime starts",
        "mapping_count": len(rows),
    }
    _atomic_json(Path(str(out_csv) + ".identity.json"), identity)

    print(f"\n=== Summary ===")
    print(f"  source named functions: {len(src_named)}")
    print(f"  pass 1 (exact32):       {len(pass1_ported)}")
    print(f"  pass 2 (masked48):      {len(pass2_ported)}")
    print(f"  total ported:           {len(rows)}")
    print(f"  hit rate:               {100.0 * len(rows) / max(len(src_named), 1):.1f}%")
    print(f"  output:                 {out_csv}")
    print(f"  identity:               {out_csv}.identity.json")


if __name__ == "__main__":
    main()
