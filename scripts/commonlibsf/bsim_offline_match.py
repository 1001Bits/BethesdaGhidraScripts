#!/usr/bin/env python3
"""Offline BSim LSH similarity matcher.

Reads `bsim dumpsigs` XML output for a target binary + N source binaries
and finds the best-matching source function for every target function
via LSH-cosine intersection / sqrt(|A| * |B|).

Output:
  scripts/commonlibsf/refs/bsim_matches_<target_md5>.csv
  columns: target_va, source_name, source_exe, similarity, num_shared_hashes

The matcher is order-of-magnitude faster than calling BSim's per-function
re-decompile path because both sides' signatures are already pre-computed
in the DB and dumped to XML.
"""
from __future__ import annotations

import csv
import os
import re
import sys
import time
from collections import defaultdict
from xml.etree.ElementTree import iterparse
from html import unescape
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent.parent
SIGS_DIR = str(REPO_DIR / "bsim" / "sigs")
OUT_DIR  = str(Path(__file__).resolve().parent / "refs")

# Default: target = SF 1.16.236, sources = everything else.
TARGET_MD5  = "839927232f7cb161b4c304882ce3e3df"
SOURCE_MD5S = [
    "4005ad9140ddfc1b75687d3c0202f432",  # SF 1.7 (same engine -- highest signal)
    "2951ac9444071d4df472a3814e035612",  # F4 OG
    "6267efcc615708f0f648a0b462ca53fc",  # F4 AE
    "9f5eb140eb54eb8d3ae613f0f395cb13",  # Skyrim AE
    "a23c24cfaf891c248315d06b6e19c56d",  # F4 VR2
]

MIN_SIMILARITY  = 0.85  # this is an approximation, so accept only strong hits
MIN_OVERLAP     = 8     # two shared hashes produced pervasive false positives
MIN_NAME_MARGIN = 0.08  # best qualified name must beat a competing name
MAX_PER_HASH    = 100   # aggressively suppress generic compiler idioms
EXACT_SINGLE_SOURCE_SIM = 0.98
EXACT_SINGLE_SOURCE_OVERLAP = 16

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_", "SUB_")
NOISE_SUBSTRINGS = ("_dynamic_initializer_for_", "_lambda_", "API-MS-")
PLACEHOLDER_METHOD_RE = re.compile(r'(?:^|::)(?:Func|Method|VFunc)\d+$', re.I)


def is_noise(name: str) -> bool:
    if not name:
        return True
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    if any(s in name for s in NOISE_SUBSTRINGS):
        return True
    return bool(PLACEHOLDER_METHOD_RE.search(name))


def stream_fdesc(xml_path: str):
    """Stream-parse a sigs XML.  Yields (addr_int, name, exe_name, [hashes])."""
    exe_name = None
    context = iterparse(xml_path, events=("start", "end"))
    for event, elem in context:
        if event == "end":
            if elem.tag == "name" and exe_name is None:
                exe_name = elem.text or ""
            elif elem.tag == "fdesc":
                addr = elem.get("addr") or "0"
                name = elem.get("name") or ""
                addr_int = int(addr, 16) if addr.startswith("0x") else int(addr, 16)
                hashes = []
                lsh = elem.find("lshcosine")
                if lsh is not None:
                    for h in lsh.findall("hash"):
                        if h.text:
                            t = h.text.strip()
                            hashes.append(int(t, 16) if t.startswith("0x") else int(t))
                yield addr_int, name, exe_name, hashes
                elem.clear()


def load_target(md5: str):
    path = os.path.join(SIGS_DIR, f"sigs_{md5}")
    print(f"Loading target {md5} from {path} ...")
    t0 = time.time()
    funcs = []
    for addr, name, exe, hashes in stream_fdesc(path):
        hashes = frozenset(hashes)
        if len(hashes) < MIN_OVERLAP:
            continue
        funcs.append((addr, name, hashes))
    print(f"  loaded {len(funcs)} target functions in {time.time()-t0:.1f}s")
    return funcs


def load_source(md5: str, hash_index, name_db):
    """Add a source binary's signatures to the inverted index + name DB."""
    path = os.path.join(SIGS_DIR, f"sigs_{md5}")
    print(f"Loading source {md5} from {path} ...")
    t0 = time.time()
    n = 0
    exe_name = "?"
    for addr, name, exe, hashes in stream_fdesc(path):
        exe_name = exe
        hashes = frozenset(hashes)
        if len(hashes) < MIN_OVERLAP:
            continue
        if is_noise(name):
            continue
        fid = (md5, addr)
        name_db[fid] = (name, len(hashes), exe_name)
        for h in hashes:
            hash_index[h].append(fid)
        n += 1
    print(f"  added {n} source functions in {time.time()-t0:.1f}s")
    return n, exe_name


def best_match(target_hashes, hash_index, name_db):
    """Return a strong, name-unambiguous match or ``None``.

    Offline set overlap is not Ghidra's full BSim scoring model.  Require
    either agreement from two independent source binaries or a near-exact
    single-source hit, and reject a close runner-up with a different name.
    """
    if len(target_hashes) < MIN_OVERLAP:
        return None
    overlap_counter: dict[tuple[str, int], int] = defaultdict(int)
    for h in target_hashes:
        cands = hash_index.get(h)
        if cands is None:
            continue
        if len(cands) > MAX_PER_HASH:
            continue  # skip too-generic hashes
        for fid in cands:
            overlap_counter[fid] += 1
    if not overlap_counter:
        return None
    scored = []
    target_n = len(target_hashes)
    target_sqn = target_n ** 0.5
    for fid, overlap in overlap_counter.items():
        if overlap < MIN_OVERLAP:
            continue
        _, src_n, _ = name_db[fid]
        sim = overlap / (target_sqn * (src_n ** 0.5))
        if sim >= MIN_SIMILARITY:
            scored.append((sim, overlap, fid))
    if not scored:
        return None
    scored.sort(reverse=True)
    best_sim, best_overlap, best_fid = scored[0]
    best_name = name_db[best_fid][0]
    competing = next((sim for sim, _, fid in scored
                      if name_db[fid][0] != best_name), None)
    margin = best_sim - competing if competing is not None else 1.0
    if margin < MIN_NAME_MARGIN:
        return None
    consensus_sources = len({fid[0] for sim, _, fid in scored
                             if name_db[fid][0] == best_name
                             and sim >= best_sim - 0.05})
    near_exact = (best_sim >= EXACT_SINGLE_SOURCE_SIM and
                  best_overlap >= EXACT_SINGLE_SOURCE_OVERLAP)
    if consensus_sources < 2 and not near_exact:
        return None
    return best_fid, best_sim, best_overlap, margin, consensus_sources


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    out_csv = os.path.join(OUT_DIR, f"bsim_matches_{TARGET_MD5}.csv")
    print(f"Target MD5:   {TARGET_MD5}")
    print(f"Source MD5s:  {SOURCE_MD5S}")
    print(f"Min similarity: {MIN_SIMILARITY}  Min overlap: {MIN_OVERLAP}  Max per-hash: {MAX_PER_HASH}")
    print(f"Output:       {out_csv}\n")

    # Phase A: build inverted index over all sources
    hash_index: dict[int, list] = defaultdict(list)
    name_db: dict[tuple, tuple] = {}
    total_src = 0
    for md5 in SOURCE_MD5S:
        n, exe = load_source(md5, hash_index, name_db)
        total_src += n
    print(f"\nTotal source functions: {total_src}")
    print(f"Total unique hashes:    {len(hash_index)}")

    # Phase B: load target and match
    target = load_target(TARGET_MD5)

    n_matched = 0
    n_no_match = 0
    sample = []
    rows = []
    t0 = time.time()
    for i, (addr, _name, hashes) in enumerate(target):
        m = best_match(hashes, hash_index, name_db)
        if m is None:
            n_no_match += 1
        else:
            fid, sim, overlap, margin, consensus = m
            src_name, src_n, exe = name_db[fid]
            rows.append((f"0x{addr:x}", src_name, exe, fid[0],
                         f"{sim:.4f}", overlap, f"{margin:.4f}", consensus))
            n_matched += 1
            if len(sample) < 12:
                sample.append((addr, src_name, exe, sim, overlap))
        if (i + 1) % 2000 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / max(elapsed, 0.001)
            print(f"  matched {i+1}/{len(target)}  hits={n_matched}  no_match={n_no_match}  rate={rate:.0f}/s")

    print(f"\nDone matching in {time.time()-t0:.0f}s")
    print(f"  hits:     {n_matched}")
    print(f"  no match: {n_no_match}")
    print(f"  hit rate: {100.0 * n_matched / max(len(target), 1):.1f}%")

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["target_va", "name", "source_exe", "source_md5",
                    "similarity", "overlap", "different_name_margin",
                    "consensus_sources"])
        w.writerows(rows)
    print(f"  wrote {out_csv}")

    if sample:
        print("\nSample matches (first 12):")
        for addr, src_name, exe, sim, overlap in sample:
            print(f"  0x{addr:x}  ->  {src_name[:60]:60s}  sim={sim:.3f}  overlap={overlap}  src={exe[:15]}")


if __name__ == "__main__":
    main()
