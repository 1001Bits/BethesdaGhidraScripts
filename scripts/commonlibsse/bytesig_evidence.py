"""Skyrim entry point for the shared identity-bound byte-signature schema."""
from __future__ import annotations

import importlib.util
from pathlib import Path


_PATH = Path(__file__).resolve().parent.parent / 'commonlibf4' / 'bytesig_evidence.py'
_SPEC = importlib.util.spec_from_file_location('_shared_bytesig_evidence', _PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError('cannot load shared byte-signature evidence schema')
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

SCHEMA_VERSION = _MODULE.SCHEMA_VERSION
load_validated = _MODULE.load_validated
persist = _MODULE.persist
