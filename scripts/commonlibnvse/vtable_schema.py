#!/usr/bin/env python3
"""Versioned Xbox-vtable interchange schema.

Version 1 used a JSON object keyed by a class string, which made duplicate
physical tables overwrite one another.  Version 2 stores a list and assigns
every table a stable identity including its RVA and base subobject.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import json

SCHEMA = 'fnv-xbox-vtables-v2'


@dataclass
class XboxVTable:
    identity: str
    class_name: str
    subobject: str
    rva: Optional[int]
    mangled: str
    slots: List[dict]


def _legacy_class_and_subobject(key: str):
    # Old producers only used ``Class::Base`` for secondary tables.  Preserve
    # the full key if it is namespaced/template-heavy rather than inventing a
    # subobject identity we cannot prove.
    if key.count('::') == 1 and '<' not in key:
        return tuple(key.split('::', 1))
    return key, ''


def load_xbox_tables(source: Any) -> List[XboxVTable]:
    """Load v2 or legacy v1 data without collapsing duplicate tables."""
    if isinstance(source, (str, Path)):
        data = json.loads(Path(source).read_text(encoding='utf-8'))
    else:
        data = source
    out = []
    if isinstance(data, dict) and data.get('schema') == SCHEMA:
        for i, rec in enumerate(data.get('tables', [])):
            cls = str(rec.get('class', '')).strip()
            slots = rec.get('slots', [])
            if not cls or not isinstance(slots, list):
                continue
            rva = rec.get('rva')
            if rva is not None:
                rva = int(rva)
                if rva < 0:
                    continue
            ident = rec.get('id') or 'xbox:0x%08X:%s:%d' % (
                rva or 0, cls, i)
            out.append(XboxVTable(
                str(ident), cls, str(rec.get('subobject', '')),
                rva, str(rec.get('mangled', '')), slots))
        return out
    if not isinstance(data, dict):
        raise ValueError('unsupported Xbox-vtable JSON root')
    for i, (key, slots) in enumerate(data.items()):
        if not isinstance(slots, list):
            continue
        cls, sub = _legacy_class_and_subobject(key)
        out.append(XboxVTable('legacy:%s:%d' % (key, i), cls, sub,
                              None, '', slots))
    return out


def make_document(tables: Iterable[dict], **metadata) -> Dict[str, Any]:
    return {
        'schema': SCHEMA,
        'metadata': dict(metadata),
        'tables': list(tables),
    }

