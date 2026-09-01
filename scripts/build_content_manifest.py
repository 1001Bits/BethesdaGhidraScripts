#!/usr/bin/env python3
"""Write an atomic SHA-256 inventory for a staged release tree."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(root: Path, output: Path) -> int:
    root = root.resolve(strict=True)
    output = output.resolve(strict=False)
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise ValueError("manifest output must be inside the staged tree") from exc

    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved == output:
            continue
        relative = resolved.relative_to(root).as_posix()
        if relative.startswith(".BUNDLE_CONTENTS.sha256."):
            continue
        files.append((relative, resolved))
    files.sort(key=lambda item: (item[0].casefold(), item[0]))

    temporary = output.with_name(
        ".BUNDLE_CONTENTS.sha256.{}.tmp".format(os.getpid()))
    try:
        with temporary.open("w", encoding="ascii", newline="\n") as handle:
            for relative, path in files:
                handle.write("{}  {}\n".format(_sha256(path), relative))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    count = write_manifest(args.root, args.output)
    print("Content manifest: {} files".format(count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
