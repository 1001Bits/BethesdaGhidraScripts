#!/usr/bin/env python3
"""Build a {qualified_name -> C signature} index from Fallout_Debug_funcs.json
(produced by parse_pdb_pretty.py).

The JSON has shape ``{class_name: [{va, end, size, sig, name}, ...]}``.
Each ``sig`` is a full C++ signature like
``void __cdecl Class::Method(int x, float y)``.

We index by ``name`` (the qualified ``Class::method`` form _extract_qname
produced) and strip MSVC-specific keywords (``__cdecl``, ``virtual``,
``static``) that Ghidra's CParserUtils.parseSignature doesn't tolerate
in arbitrary positions.

For overloaded methods, every distinct signature is retained.  Plain dict
lookup exposes only unambiguous names; ``SignatureIndex.resolve`` can select
an overload from a decorated/demangled identity.

Public API:
    load_sigs(json_path) -> Dict[qualified_name, c_signature_string]
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from paths import artifact


_STRIP_KEYWORDS = re.compile(
    r'\b('
    r'__cdecl|__thiscall|__stdcall|__fastcall|__vectorcall|__clrcall|'
    r'virtual|static|inline|explicit|friend|register'
    r')\s+'
)


def clean_sig(sig: str) -> str:
    """Strip MSVC calling conventions and inheritance qualifiers."""
    s = _STRIP_KEYWORDS.sub('', sig)
    # Collapse multiple spaces
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def _identity_tail(text: str, qname: str) -> str:
    """Canonical ``Class::method(args) qualifiers`` tail for overload joins."""
    pos = text.rfind(qname)
    if pos < 0:
        return ''
    tail = text[pos + len(qname):]
    tail = re.sub(r'\b(?:class|struct|enum|union)\b', '', tail)
    return re.sub(r'\s+', '', tail)


class SignatureIndex(dict):
    """Dict-compatible unambiguous index plus lossless overload candidates."""
    def __init__(self, candidates: Dict[str, List[str]]):
        self.candidates = candidates
        super().__init__((name, sigs[0]) for name, sigs in candidates.items()
                         if len(sigs) == 1)

    def resolve(self, qname: str, decorated_or_demangled: str = '') -> Optional[str]:
        sigs = self.candidates.get(qname, [])
        if len(sigs) == 1:
            return sigs[0]
        if not sigs or not decorated_or_demangled:
            return None
        wanted = _identity_tail(decorated_or_demangled, qname)
        if not wanted:
            return None
        hits = [sig for sig in sigs if _identity_tail(sig, qname) == wanted]
        return hits[0] if len(hits) == 1 else None


def load_sigs(json_path) -> Dict[str, str]:
    """Return ``{qualified_name: cleaned_c_signature}``.

    Accepts a single Path or an iterable of Paths -- when multiple PDBs
    are supplied, sigs are merged with first-win semantics (Debug build
    listed first wins on overlap; other builds fill in functions the
    Debug PDB didn't surface, e.g. due to different inlining).
    """
    paths = [json_path] if isinstance(json_path, Path) else list(json_path)
    candidates: Dict[str, List[str]] = {}
    for p in paths:
        if not p.is_file():
            continue
        data = json.loads(p.read_text(encoding='utf-8'))
        from_path: Dict[str, List[str]] = {}
        for _cls, fns in data.items():
            for fn in fns:
                qname = fn.get('name', '')
                sig   = fn.get('sig', '')
                if not qname or not sig:
                    continue
                cleaned = clean_sig(sig)
                if '(' not in cleaned or ')' not in cleaned:
                    continue
                bucket = from_path.setdefault(qname, [])
                if cleaned not in bucket:
                    bucket.append(cleaned)
        for qname, sigs in from_path.items():
            # PDB priority is path order.  Later builds fill missing names but
            # never manufacture overload ambiguity by mixing build variants.
            candidates.setdefault(qname, sigs)
    return SignatureIndex(candidates)


if __name__ == '__main__':
    import sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        artifact('Fallout_Debug_funcs.json')
    sigs = load_sigs(p)
    print(f'  qualified names with signatures: {len(sigs):,}')
    # Show 3 samples
    for k in list(sigs)[:3]:
        print(f'    {k!r} -> {sigs[k]!r}')
