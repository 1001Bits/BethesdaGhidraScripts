#!/usr/bin/env python3
"""Bind an improvement-evidence file to its exact target executable.

The identity-gated appliers (``apply_idc_labels``, ``apply_og_names``,
``apply_vcall_xrefs``) refuse ``--apply`` without a ``<evidence>.identity.json``
sidecar proving which binary the evidence was mined against.  This CLI is the
producer: point it at the evidence file and the target executable and it
writes the sidecar (and prints the SHA-256 to pass as ``--target-sha256``).

Two sidecar shapes:
  * default: the ``bgs-enrichment-evidence-v2`` binding written by
    ``evidence_identity.bind_for_hash`` (used by apply_idc_labels /
    apply_og_names).
  * ``--trace-session-id``: the trace manifest expected by
    ``apply_vcall_xrefs`` -- a full ``inspect_pe`` target manifest plus
    ``trace.session_id`` (use the TTD SessionID from the recorder output).

Usage:
  python bind_evidence.py <evidence_file> --exe <target_exe> --kind <kind> \
      [--coordinate VA|RVA|NONE] [--program-name NAME] \
      [--trace-session-id ID]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from binary_identity import inspect_pe  # noqa: E402
from evidence_identity import (bind_for_hash, sidecar_path,  # noqa: E402
                               _atomic_json)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence_file")
    ap.add_argument("--exe", required=True,
                    help="the exact executable the evidence addresses target")
    ap.add_argument("--kind", required=True,
                    help="evidence kind label, e.g. f4_idc_labels, "
                         "og_funcs_json, ttd_vcall_edges")
    ap.add_argument("--coordinate", default="VA",
                    choices=("VA", "RVA", "NONE"),
                    help="address coordinate system used in the evidence")
    ap.add_argument("--program-name", default="",
                    help="Ghidra program name (informational)")
    ap.add_argument("--trace-session-id",
                    help="write the apply_vcall_xrefs trace-manifest shape "
                         "instead, with this TTD session id")
    args = ap.parse_args()

    manifest = inspect_pe(args.exe)
    if args.trace_session_id:
        payload = {
            "kind": args.kind,
            "target": manifest,
            "trace": {"session_id": args.trace_session_id},
        }
        _atomic_json(sidecar_path(args.evidence_file), payload)
    else:
        payload = bind_for_hash(
            args.evidence_file, args.kind, manifest["sha256"],
            program_name=args.program_name,
            image_base=manifest["image_base"],
            pointer_size=manifest["pointer_size"],
            address_coordinate=args.coordinate)

    print("wrote %s" % sidecar_path(args.evidence_file))
    print("target sha256: %s" % manifest["sha256"])
    print(json.dumps({k: payload[k] for k in payload
                      if k not in ("target",)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
