#!/usr/bin/env python3
"""Regenerate the exact F4 1.11.221 public-symbol corpus from a PDB.

The raw community PDB is deliberately not required at import time.  This tool
turns it into a reviewable, deterministic text corpus and a sidecar that binds
the source PDB hash, CodeView identity, extractor, and every accepted target PE.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parents[1]
CORE_DIR = REPO_DIR / "scripts" / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from binary_identity import inspect_pe  # noqa: E402
from pdb_identity import read_pe_codeview  # noqa: E402
from pdb_msf import PDBPublicCorpus, read_pdb_publics  # noqa: E402
from pe_unwind import validated_runtime_function_starts  # noqa: E402


DEFAULT_OUTPUT = SCRIPT_DIR / "refs" / "f4_221_pdb_publics.txt"
CANONICAL_PDB_NAME = "Fallout4_1_11_221_for_debug.pdb"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _verify_sections(corpus: PDBPublicCorpus, target: dict) -> None:
    target_sections = target.get("sections", [])
    if len(corpus.sections) > len(target_sections):
        raise ValueError("PDB has more sections than its target PE")
    fields = ("name", "rva", "virtual_size", "raw_size", "raw_offset",
              "characteristics")
    for index, pdb_section in enumerate(corpus.sections):
        expected = target_sections[index]
        actual = {
            "name": pdb_section.name,
            "rva": pdb_section.rva,
            "virtual_size": pdb_section.virtual_size,
            "raw_size": pdb_section.raw_size,
            "raw_offset": pdb_section.raw_offset,
            "characteristics": pdb_section.characteristics,
        }
        if any(actual[field] != expected[field] for field in fields):
            raise ValueError(
                "PDB section {} does not match target PE".format(index + 1))


def _ambiguity_counts(corpus: PDBPublicCorpus) -> dict[str, int]:
    by_rva: dict[int, set[str]] = defaultdict(set)
    by_name: dict[str, set[int]] = defaultdict(set)
    for public in corpus.publics:
        by_rva[public.rva].add(public.name)
        by_name[public.name].add(public.rva)
    ambiguous_rvas = {rva for rva, names in by_rva.items() if len(names) > 1}
    ambiguous_names = {
        name for name, rvas in by_name.items() if len(rvas) > 1}
    safe = sum(public.rva not in ambiguous_rvas and
               public.name not in ambiguous_names
               for public in corpus.publics)
    return {
        "same_rva_alias_groups": len(ambiguous_rvas),
        "same_name_multi_rva_groups": len(ambiguous_names),
        "quarantined_records": len(corpus.publics) - safe,
        "unambiguous_records": safe,
    }


def regenerate(pdb_path: Path, target_paths: list[Path], output: Path,
               source_author: str = "unknown",
               source_license: str = "unknown",
               previous_pdb: Path | None = None) -> dict:
    corpus = read_pdb_publics(pdb_path)
    if not corpus.publics:
        raise ValueError("PDB contains no public symbols")
    targets = []
    runtime_starts = set()
    for target_path in target_paths:
        manifest = inspect_pe(str(target_path))
        codeview = read_pe_codeview(str(target_path))
        if (codeview["guid"] != corpus.guid or
                int(codeview["age"]) != corpus.age):
            raise ValueError("PDB GUID/age does not match {}".format(target_path))
        if int(manifest["machine"]) != corpus.machine:
            raise ValueError("PDB machine does not match {}".format(target_path))
        _verify_sections(corpus, manifest)
        targets.append({
            "file": target_path.name,
            "sha256": manifest["sha256"],
            "file_version": manifest.get("file_version"),
            "image_size": manifest["image_size"],
            "machine": manifest["machine"],
        })
        runtime_starts.update(validated_runtime_function_starts(
            str(target_path)))
    pairs = sorted({(public.rva, public.name) for public in corpus.publics})
    if len(pairs) != len(corpus.publics):
        raise ValueError("PDB contains duplicate public records")
    lines = [
        "Summary for {}".format(CANONICAL_PDB_NAME),
        "  Size: {} bytes".format(pdb_path.stat().st_size),
        "  Guid: {{{}}}".format(corpus.guid),
        "  Age: {}".format(corpus.age),
        "  Attributes: CommunityReconstruction PublicSymbolsOnly",
        "---EXTERNALS---",
    ]
    lines.extend("  public [0x{:08x}] {}".format(rva, name)
                 for rva, name in pairs)
    _write_atomic(output, "\n".join(lines) + "\n")
    ambiguity = _ambiguity_counts(corpus)
    supersedes = None
    if previous_pdb is not None:
        previous = read_pdb_publics(previous_pdb)
        if (previous.guid != corpus.guid or previous.age != corpus.age or
                previous.machine != corpus.machine):
            raise ValueError("previous PDB has a different target identity")
        previous_pairs = {(public.rva, public.name)
                          for public in previous.publics}
        current_pairs = set(pairs)
        if not previous_pairs < current_pairs:
            raise ValueError("new PDB is not a strict public-symbol superset")
        supersedes = {
            "sha256": _sha256(previous_pdb),
            "size": previous_pdb.stat().st_size,
            "publics": len(previous_pairs),
            "added_publics": len(current_pairs - previous_pairs),
            "removed_publics": len(previous_pairs - current_pairs),
        }
    identity = {
        "schema_version": 2,
        "artifact": output.name,
        "artifact_sha256": _sha256(output),
        "source": {
            "canonical_filename": CANONICAL_PDB_NAME,
            "original_filename": pdb_path.name,
            "sha256": _sha256(pdb_path),
            "size": pdb_path.stat().st_size,
            "author": source_author,
            "license": source_license,
            "redistribution": (
                "raw PDB not bundled; obtain author permission/license before "
                "redistribution"),
            "kind": "community-generated public-symbol-only PDB",
        },
        "pdb": {
            "guid": corpus.guid,
            "age": corpus.age,
            "signature": corpus.signature,
            "signature_utc": datetime.fromtimestamp(
                corpus.signature, timezone.utc).isoformat(),
            "version": corpus.pdb_version,
            "machine": corpus.machine,
            "type_record_count": corpus.type_record_count,
            "module_info_size": corpus.module_info_size,
        },
        "counts": {
            "publics": len(corpus.publics),
            "executable_section_publics": sum(
                public.executable for public in corpus.publics),
            "data_section_publics": sum(
                not public.executable for public in corpus.publics),
            "runtime_function_starts": sum(
                public.rva in runtime_starts and public.executable
                for public in corpus.publics),
            **ambiguity,
        },
        "targets": sorted(targets, key=lambda target: target["sha256"]),
        "extractor": {
            "script": Path(__file__).resolve().relative_to(REPO_DIR).as_posix(),
            "script_sha256": _sha256(Path(__file__).resolve()),
            "msf_reader": (CORE_DIR / "pdb_msf.py").relative_to(
                REPO_DIR).as_posix(),
            "msf_reader_sha256": _sha256(CORE_DIR / "pdb_msf.py"),
        },
    }
    if supersedes is not None:
        identity["supersedes"] = supersedes
    sidecar = Path(str(output) + ".identity.json")
    _write_atomic(sidecar, json.dumps(identity, indent=2, sort_keys=True) + "\n")
    return identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pdb", type=Path)
    parser.add_argument("targets", nargs="+", type=Path,
                        help="all exact PE variants accepted by the corpus")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-author", default="unknown")
    parser.add_argument("--source-license", default="unknown")
    parser.add_argument("--previous-pdb", type=Path,
                        help="verify and record a strict-superset predecessor")
    args = parser.parse_args()
    identity = regenerate(args.pdb, args.targets, args.output,
                          args.source_author, args.source_license,
                          args.previous_pdb)
    print("Wrote {} publics to {}".format(
        identity["counts"]["publics"], args.output))
    print("Quarantined ambiguity records: {}".format(
        identity["counts"]["quarantined_records"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
