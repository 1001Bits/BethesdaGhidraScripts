#!/usr/bin/env python3
"""Generate offline Ed25519 keys or sign a BGS provenance JSON manifest."""
import argparse
import json
from pathlib import Path

from provenance import (canonical_json, generate_keypair, sign_manifest,
                        validate_manifest, verify_manifest_signature)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("manifest")
    sign.add_argument("--private", required=True)
    sign.add_argument("--out", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("manifest")
    verify.add_argument("--public", required=True)
    args = parser.parse_args()

    if args.command == "keygen":
        key_id = generate_keypair(args.private, args.public)
        print("Generated Ed25519 provenance key ID " + key_id)
        return 0
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if args.command == "sign":
        signed = sign_manifest(validate_manifest(manifest), args.private)
        Path(args.out).write_text(canonical_json(signed) + "\n",
                                  encoding="ascii", newline="\n")
        print("Signed BGS provenance with key " + signed["signature"]["key_id"])
        return 0
    validate_manifest(manifest, public_key=args.public)
    verify_manifest_signature(manifest, args.public)
    print("Valid trusted BGS provenance signature")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
