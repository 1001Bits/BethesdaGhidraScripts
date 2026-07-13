"""Shared config defaults for the CommonLibVR ("ng") Ghidra-script pipeline.

Every script in this package reads the same generated-import path, script
directory, and CommonLibVR header root, each overridable per-invocation via
the env vars named below.  Previously each script redefined these identically
(copy-pasted env-var-default boilerplate); this module is the single source of
truth so a future rename/move is one edit instead of N.

Defaults are derived from this repository's own layout, so the pipeline works
from a fresh clone on any machine.  Set the env vars to point elsewhere.

Usage (matches the sys.path pattern already used to import sibling modules
like layout_diff):

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from clvr_config import IMPORT_PATH, SCRIPT_DIR, TYPES_CAT
"""
import os

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(os.path.dirname(_SCRIPT_DIR))

# This package's own directory (scripts/commonlibvr). Override via CLVR_SCRIPT_DIR.
SCRIPT_DIR = os.environ.get('CLVR_SCRIPT_DIR', _SCRIPT_DIR)

# Where generated import scripts and their CSV sidecars land.
RESOLVED_DIR = os.environ.get(
    'CLVR_RESOLVED_DIR', os.path.join(_REPO_DIR, 'ghidrascripts'))

# The generated CommonLibImport_CLVR_<RUNTIME>.py this pipeline applies.
# Override per-invocation (e.g. to target SE/AE instead of VR) via CLVR_IMPORT.
IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT', os.path.join(RESOLVED_DIR, 'CommonLibImport_CLVR_VR.py'))

# CommonLibVR's RE headers.  Clone (or junction) the library to
# extern/CommonLibVR, alongside the sibling CommonLib* checkouts.
RE_DIR = os.environ.get(
    'CLVR_RE_DIR',
    os.path.join(_REPO_DIR, 'extern', 'CommonLibVR', 'include', 'RE'))

TYPED_MEMBERS_CSV = os.environ.get(
    'CLVR_TYPED_MEMBERS_CSV',
    os.path.join(RESOLVED_DIR, 'commonlib_typed_members.csv'))

APPLY_CSV = os.environ.get(
    'CLVR_APPLY_CSV', os.path.join(RESOLVED_DIR, 'vt_apply_candidates.csv'))

# Skyrim VR address-library CSV (id -> rva).  This repository already ships a
# copy, so default to it rather than an external vr_address_tools checkout.
VR_CSV = os.environ.get(
    'BGS_VR_CSV',
    os.path.join(_REPO_DIR, 'addresslibrary', 'sse', 'version-1-4-15-0.csv'))

# Project convention: manual RE / generated CommonLib types live in /types.h
# (see ~/.claude/skyrim-re.md's "Ghidra naming & structs" section).
TYPES_CAT = '/types.h'
