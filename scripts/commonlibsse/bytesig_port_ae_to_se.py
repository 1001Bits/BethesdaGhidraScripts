#!/usr/bin/env python3
r"""Port Skyrim AE function names onto Skyrim SE 1.5.97 by code bytes.

SE (1.5.97) and AE (1.6.x / 1.7.x) are DIFFERENT address-library ID
namespaces, so names cannot travel between them by ID -- the July 2026 attempt
did exactly that and put 70,389 wrong names on the SE program.  This port uses
the reciprocal-unique byte-signature matcher of
``scripts/creationkit/reciprocal_bytesig_port.py`` instead:

* the target is pinned to the exact SE executable SHA-256, every source to its
  exact AE executable SHA-256;
* a name is proposed only when the first 32 bytes (or a relocation-masked
  48-byte window) of its AE function occur exactly once in the AE image AND
  exactly once in SE, at an analyzed SE function entry;
* all sources together must form a one-to-one (name <-> SE address) mapping;
  a name claimed at two addresses, or an address claimed by two names, is
  rejected;
* an existing non-default SE name is never replaced;
* vtable-slot placeholders (``Class::FuncN``, ``Class::Unk_XX``) are never
  ported: their slot numbers are AE-specific and SE's tables differ.

Dry-run is the default and writes an identity-bound evidence CSV.  Measure it
with ``--measure`` against CommonLibSSE's dual-ID symbols before ``--apply``.

Usage (the project must not be open in the Ghidra GUI)::

    python scripts/commonlibsse/bytesig_port_ae_to_se.py \
        --project-dir C:/GhidraProjects --project-name Combined [--apply]
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
CK_DIR = SCRIPT_DIR.parent / "creationkit"
if str(CK_DIR) not in sys.path:
    sys.path.insert(0, str(CK_DIR))

import reciprocal_bytesig_port as shared  # noqa: E402

TARGET_PATH = "/Skyrim/SkyrimSE_1_5_97.exe"
TARGET_SHA256 = (
    "5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12")
DEFAULT_EVIDENCE = (SCRIPT_DIR.parents[1] / "build" / "evidence" /
                    "bytesig_ae_to_se_1_5_97.csv")
DEFAULT_SOURCES = (
    ("SkyrimAE-1.6.1170", "/Skyrim/SkyrimAE_1_6_1170.exe"),
    ("SkyrimAE-1.7.104", "/Skyrim/SkyrimAE_1_7_104.exe"),
)
# Slot-numbered placeholders: ``X::Func12``, ``X::Func3_v8`` (vtable walk)
# and CommonLib's ``X::Unk_A3``.  The number is an AE vtable index.
SLOT_PLACEHOLDER_RE = (
    r"(?:^|::)(?:Func\d+(?:_v\d+)?(?:_[0-9A-Fa-f]+)?|Unk_[0-9A-Fa-f]+)$")
SE_IMAGE_BASE = 0x140000000
_AE_ADDRESS_SUFFIX = re.compile(
    r"^(?:(sub|FUN)|(.+?))([_@])(14[0-9A-Fa-f]{7})$")


def se_local_name(local_name: str, target_rva: int) -> str:
    """Replace an AE address embedded in a name with the SE address.

    AE names such as ``sub_1400FBA60``, ``ReadFromStream_14053EB00`` or the
    MSVC funclet ``Unwind@1415c4354`` carry the AE virtual address; on SE that
    number would point somewhere else.  The separator and letter case are
    kept (like ``port_ae_family_by_id.retarget_local_name``); ``FUN_`` becomes
    ``sub_``.
    """
    match = _AE_ADDRESS_SUFFIX.match(local_name)
    if not match:
        return local_name
    digits = "{:X}".format(SE_IMAGE_BASE + int(target_rva))
    if match.group(1):
        return "sub_" + digits
    if match.group(4) != match.group(4).upper():
        digits = digits.lower()
    return match.group(2) + match.group(3) + digits


CONFIG = shared.PortConfig(
    target_sha256=TARGET_SHA256,
    target_product_version="1.5.97.0",
    default_sources=DEFAULT_SOURCES,
    default_evidence=DEFAULT_EVIDENCE,
    target_display_name="Skyrim SE 1.5.97",
    default_target_path=TARGET_PATH,
    transaction_name="Skyrim AE -> SE reciprocal-unique byte-signature names",
    save_description="Skyrim AE -> SE reciprocal-unique byte-signature names",
    source_help=(
        "repeatable configured identity-pinned source; defaults to the "
        "analyzed AE 1.6.1170 and 1.7.104 programs in Combined"),
    allowed_source_sha256=(
        ("/Skyrim/SkyrimAE_1_6_1170.exe",
         "80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4"),
        ("/Skyrim/SkyrimAE_1_7_104.exe",
         "846efccf0c1374d71f892907f46549560f2fcb0a75cb87a3eed438baa0f1402f"),
        ("/Skyrim/SkyrimAE_1_6_640.exe",
         "d3c4f588b942e73a54240497886e35f094a3641ed2a7173332100eaf1c90ea60"),
    ),
    excluded_name_re=SLOT_PLACEHOLDER_RE,
    local_name_rewrite=se_local_name,
)


def main(argv: Sequence[str] | None = None) -> int:
    return shared.main(argv, config=CONFIG)


if __name__ == "__main__":
    raise SystemExit(main())
