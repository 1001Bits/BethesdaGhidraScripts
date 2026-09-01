#!/usr/bin/env python3
"""Stamp existing generated importers without rerunning Clang."""
import argparse
import json
from pathlib import Path
import re

from importer_binding import extract_target_manifests
from provenance import (GHIDRA_PROVENANCE_APPLY_SNIPPET, build_manifest,
                        canonical_json)


REPO_DIR = Path(__file__).resolve().parents[2]
GENERATOR = Path(__file__).with_name("ghidra_import_gen.py")
_PROVENANCE_RE = re.compile(
    r"^BGS_PROVENANCE = _json_target\.loads\(.+\)$", re.M)


def stamp(path):
    path = Path(path)
    manifest = build_manifest(
        REPO_DIR, GENERATOR, extract_target_manifests(path))
    assignment = ("BGS_PROVENANCE = _json_target.loads(" +
                  repr(canonical_json(manifest)) + ")")
    text = path.read_text(encoding="utf-8")
    if _PROVENANCE_RE.search(text):
        text = _PROVENANCE_RE.sub(assignment, text, count=1)
    else:
        lineage = re.search(r"^TARGET_LINEAGE = .+$", text, re.M)
        if lineage is None:
            raise ValueError("TARGET_LINEAGE assignment not found in " + str(path))
        text = text[:lineage.end()] + "\n" + assignment + text[lineage.end():]
    if "def _apply_bgs_provenance():" not in text:
        call = text.rfind("\nrun()")
        if call < 0:
            raise ValueError("final run() call not found in " + str(path))
        text = (text[:call] + "\n" + GHIDRA_PROVENANCE_APPLY_SNIPPET.rstrip() +
                text[call:])
        text = text.rstrip() + "\n_apply_bgs_provenance()\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    paths = [Path(value) for value in args.paths]
    if not paths:
        paths = sorted((REPO_DIR / "ghidrascripts").glob("CommonLibImport*.py"))
    for path in paths:
        manifest = stamp(path)
        print("{}  {}".format(path, manifest["provenance_id"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
