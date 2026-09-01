#!/usr/bin/env python3
r"""Port analyzed Fallout 4 game names into Fallout 4 Creation Kit 1.11.137.0.

The target is pinned to the exact Steam executable SHA-256.  Source programs
are opened read-only by exact ExampleProject project path.  Matching requires an
exact or relocation-masked unique signature at analyzed function entries,
enforces artifact-wide reciprocal name/address ownership, and never replaces
an existing non-default target name.  Dry-run is the default; ``--apply`` is
required to save accepted names.

Standalone usage (the project must not be open elsewhere)::

    python scripts/creationkit/bytesig_port_fallout4_to_ck.py \
      --project-dir C:\\GhidraProjects --project-name ExampleProject

The default target is
``/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe``.  The default sources
are the analyzed Fallout 4 1.11.221 and 1.10.163 programs. Select/relabel a
configured SHA-pinned source with repeatable exact
``--source TAG=/PROJECT/PATH`` arguments; unconfigured paths are rejected.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

import reciprocal_bytesig_port as shared


SCRIPT_DIR = Path(__file__).resolve().parent
TARGET_SHA256 = (
    "222fd0aad949e76721d85c922ae508ada6816ba2f3e1fc11647c7239c24c2e13")
TARGET_PRODUCT_VERSION = "1.11.137.0"
DEFAULT_EVIDENCE = (
    SCRIPT_DIR / "refs" / "fallout4_to_creationkit_1_11_137_0.csv")
DEFAULT_SOURCES = (
    ("Fallout4-1.11.221", "/Fallout4/Fallout4_1_11_221.exe"),
    ("Fallout4-1.10.163", "/Fallout4/Fallout4_OG_1_10_163.exe"),
)
DEFAULT_TARGET_PATH = (
    "/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe")

CONFIG = shared.PortConfig(
    target_sha256=TARGET_SHA256,
    target_product_version=TARGET_PRODUCT_VERSION,
    default_sources=DEFAULT_SOURCES,
    default_evidence=DEFAULT_EVIDENCE,
    target_display_name="Fallout 4 Creation Kit 1.11.137.0",
    default_target_path=DEFAULT_TARGET_PATH,
    transaction_name=(
        "Fallout 4 Creation Kit reciprocal-unique byte-signature names"),
    save_description=(
        "Fallout 4 Creation Kit reciprocal-unique game byte-signature names"),
    source_help=(
        "repeatable configured identity-pinned source; defaults to analyzed "
        "Fallout 4 1.11.221 and 1.10.163 programs in ExampleProject"),
    allowed_source_sha256=(
        ("/Fallout4/Fallout4_1_11_221.exe",
         "488015e2010308bfa164d3720cb618deea7e1c098b1d61af530d258a6f17d27b"),
        ("/Fallout4/Fallout4_OG_1_10_163.exe",
         "5b2a58004f1856e51235132ab304b20c1434017067703e4282e8b0d5bc539623"),
    ),
)

# Stable public types/helpers for consumers and focused offline tests.
PortConfig = shared.PortConfig
SourceName = shared.SourceName
Proposal = shared.Proposal
resolve_proposals = shared.resolve_proposals


def run_live(
        target_program, state, monitor=None,
        source_specs: Sequence[tuple[str, str]] | None = None,
        evidence_path: str | os.PathLike | None = None,
        apply: bool = False, save: bool = False) -> dict:
    """Run the exact-identity F4CK workflow against ``currentProgram``."""
    return shared.run_live(
        target_program=target_program,
        state=state,
        monitor=monitor,
        source_specs=source_specs,
        evidence_path=evidence_path,
        apply=apply,
        save=save,
        config=CONFIG,
    )


def main(argv: Sequence[str] | None = None) -> int:
    return shared.main(argv=argv, config=CONFIG, description=__doc__)


if __name__ == "__main__":
    raise SystemExit(main())
