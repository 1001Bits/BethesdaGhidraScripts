#!/usr/bin/env python3
r"""Compatibility entry point for the Skyrim-to-Creation-Kit bytesig port.

The implementation now lives in :mod:`reciprocal_bytesig_port` and retains
the original Skyrim configuration by default.  Importers receive that module
object directly so existing monkeypatching and helper imports keep working.
"""
from __future__ import annotations

import sys

import reciprocal_bytesig_port as _implementation


if __name__ == "__main__":
    raise SystemExit(_implementation.main())

# Preserve the historical import surface, including underscored test helpers.
sys.modules[__name__] = _implementation
