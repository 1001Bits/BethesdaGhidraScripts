#!/usr/bin/env python3
"""Build the curated F4 1.11.240 community public-symbol PDB bundle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parents[1]
CORE_DIR = REPO_DIR / "scripts" / "core"
for directory in (SCRIPT_DIR, CORE_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from binary_identity import inspect_pe  # noqa: E402
from pdb_identity import read_pe_codeview  # noqa: E402
from pdb_publics_f4_240 import (  # noqa: E402
    IDENTITY_JSON,
    PUBLICS_TXT,
    load_publics,
)
from symbol_export import (  # noqa: E402
    _classify_label,
    _module_basename,
    _write_text_atomic,
    build_fakepdb_root,
    collect_segments,
    generate_shareable_pdb,
    package_symbol_bundle,
    select_shareable_symbols,
    write_outputs,
)


DEFAULT_TARGET = REPO_DIR / "exes" / "f4" / "240" / "Fallout4.exe"
DEFAULT_OUTPUT = REPO_DIR / "symbols" / "f4" / "1.11.240"
# r2 is the 2026-08-30 community-corpus revision (source SHA-256
# 76fbdead...).  Keep the revision explicit because every synthetic PDB for
# this executable intentionally shares its CodeView GUID/age; archive names
# are the only safe way to distinguish revisions before extraction.
CORPUS_REVISION = 1


def build(target: Path, output_dir: Path) -> dict:
    manifest = inspect_pe(str(target))
    if tuple(manifest.get("file_version") or ()) != (1, 11, 221, 0):
        raise ValueError("target is not Fallout 4 1.11.240.0")
    records = load_publics(str(target), manifest["sha256"])
    functions = [{"rva": int(row["240"]), "name": row["n"],
                  "source": "ANALYSIS"}
                 for row in records if row["t"] == "func"]
    labels = [{"rva": int(row["240"]), "name": row["n"],
               "source": "ANALYSIS", "kind": _classify_label(row["n"])}
              for row in records if row["t"] != "func"]
    safe_functions, safe_labels, selection = select_shareable_symbols(
        functions, labels, manifest, include_analysis=True)
    if (len(safe_functions) != len(functions) or
            len(safe_labels) != len(labels)):
        raise RuntimeError("reviewed F4 corpus changed after ambiguity quarantine")
    output_dir.mkdir(parents=True, exist_ok=True)
    module = _module_basename(target.name)
    json_path, map_path, dd64_path = write_outputs(
        output_dir, module, int(manifest["image_base"]),
        functions, labels, manifest)
    root = build_fakepdb_root(
        module, int(manifest["pointer_size"]) * 8,
        collect_segments(manifest), safe_functions, safe_labels)
    fakepdb_json = output_dir / (
        os.path.splitext(module)[0] + ".fakepdb.json")
    _write_text_atomic(fakepdb_json, json.dumps(root) + "\n")
    corpus_identity = json.loads(
        Path(IDENTITY_JSON).read_text(encoding="utf-8"))
    source_provenance = {
        "kind": "identity-bound F4 1.11.240 community corpus",
        "corpus_revision": CORPUS_REVISION,
        "artifact": Path(PUBLICS_TXT).name,
        "artifact_sha256": corpus_identity["artifact_sha256"],
        "source_pdb_sha256": corpus_identity["source"]["sha256"],
        "source_author": corpus_identity["source"]["author"],
        "source_license": corpus_identity["source"]["license"],
        "source_origin": corpus_identity["source"].get("origin"),
        "source_attribution_note": corpus_identity["source"].get(
            "attribution_note"),
        "source_redistribution": corpus_identity["source"].get(
            "redistribution"),
        "records_before_quarantine": corpus_identity["counts"]["publics"],
        "records_after_quarantine": len(records),
    }
    codeview = read_pe_codeview(str(target))
    pdb_name = _module_basename(os.path.basename(
        str(codeview["pdb_path"]).replace("\\", "/")))
    pdb_path, pdb_identity = generate_shareable_pdb(
        target, fakepdb_json, output_dir / pdb_name,
        safe_functions, safe_labels, manifest, selection,
        source_provenance=source_provenance)
    bundle = package_symbol_bundle(
        output_dir, module, pdb_path, pdb_identity, json_path, manifest,
        revision=CORPUS_REVISION)
    result = {
        "pdb": str(pdb_path), "pdb_identity": str(pdb_identity),
        "symbols_json": str(json_path), "map": str(map_path),
        "dd64": str(dd64_path), "fakepdb_json": str(fakepdb_json),
        "bundle": str(bundle), "functions": len(safe_functions),
        "labels": len(safe_labels),
    }
    print(json.dumps(result, indent=2))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    build(args.target, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
