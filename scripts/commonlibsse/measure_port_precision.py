#!/usr/bin/env python3
"""Measure a name port's precision against CommonLibSSE's own address pairs.

CommonLibSSE gives many functions an ID in BOTH namespaces
(``RELOCATION_ID(se, ae)``), so a generated importer knows the exact SE and AE
addresses of the same function.  Every port proposal whose source address is
one of those functions can therefore be graded: the target address it chose
either equals the known one (correct) or not (wrong).

Usage:
  python measure_port_precision.py EVIDENCE.csv IMPORTER.py \
      --source-key a --target-key s [--source-column source_rva]
"""
from __future__ import annotations

import argparse
import collections
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import diff_importer_symbols  # noqa: E402


def truth_pairs(importer, source_key, target_key):
    """{source rva: target rva} for functions with both offsets, unambiguous."""
    pairs = collections.defaultdict(set)
    for symbols in diff_importer_symbols.load_symbols(importer).values():
        for symbol in symbols:
            if symbol.get("t") == "func" and source_key in symbol and target_key in symbol:
                pairs[int(symbol[source_key])].add(int(symbol[target_key]))
    return {rva: next(iter(targets)) for rva, targets in pairs.items()
            if len(targets) == 1}


def grade(rows, truth, source_column, target_column, decision_column, accepted):
    counts = collections.Counter()
    wrong = []
    for row in rows:
        if row.get(decision_column) not in accepted:
            continue
        source = int(row[source_column], 16)
        if source not in truth:
            counts["ungraded"] += 1
            continue
        if int(row[target_column], 16) == truth[source]:
            counts["correct"] += 1
        else:
            counts["wrong"] += 1
            wrong.append(row)
    return counts, wrong


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evidence")
    ap.add_argument("importer")
    ap.add_argument("--source-key", required=True)
    ap.add_argument("--target-key", required=True)
    ap.add_argument("--source-column", default="source_rva")
    ap.add_argument("--target-column", default="target_rva")
    ap.add_argument("--decision-column", default="decision")
    # ``create`` rows (port_ae_family_by_id --create-missing) are the riskiest
    # proposals -- a new function AND a name -- so they are graded too.
    ap.add_argument("--accepted", nargs="+", default=["accepted", "applied",
                                                        "would_apply", "apply",
                                                        "create"])
    args = ap.parse_args()
    truth = truth_pairs(args.importer, args.source_key, args.target_key)
    with open(args.evidence, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    decisions = collections.Counter(row.get(args.decision_column) for row in rows)
    counts, wrong = grade(rows, truth, args.source_column, args.target_column,
                          args.decision_column, set(args.accepted))
    graded = counts["correct"] + counts["wrong"]
    print("ground-truth function pairs: {}".format(len(truth)))
    print("evidence decisions: {}".format(dict(decisions)))
    print("graded accepted proposals: {}  correct={}  wrong={}  precision={:.4f}".format(
        graded, counts["correct"], counts["wrong"],
        counts["correct"] / graded if graded else float("nan")))
    for row in wrong[:15]:
        print("  WRONG", {k: row.get(k) for k in ("qualified_name", "name", args.source_column,
                                                   args.target_column)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
