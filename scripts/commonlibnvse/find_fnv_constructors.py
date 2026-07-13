#!/usr/bin/env python3
"""Find constructors in PC FalloutNV.exe by byte-scanning .text for
references to known vtable VAs.

x86 constructors initialize the vtable pointer with patterns like:
    C7 06 LL HH HH HH        mov dword ptr [esi], offset vtable
    C7 07 LL HH HH HH        mov dword ptr [edi], offset vtable
    C7 45 ?? LL HH HH HH     mov dword ptr [ebp+X], offset vtable
    8B/89 forms with esp     stack-allocated cases

We don't decode instructions fully -- the constructor signature is
simply ``a 4-byte LE encoding of a vtable VA somewhere in .text``.
The function containing that byte sequence is the constructor (or one
of several constructors / inlined sites).  Most classes have at least
one constructor whose ONLY job is to set the vtable + a couple fields.

For each vtable VA:
  1. Find every byte position in .text matching its 4-byte LE encoding
  2. Walk back to function start (INT3-padding heuristic)
  3. Emit ``<Class>::<Class>`` at each unique fn start

Output: ``fnv_constructor_names.csv`` review candidates.  They are quarantined
from automatic imports because a vtable write alone cannot distinguish a
constructor from a destructor or reinitialization helper.

Run:
    python find_fnv_constructors.py
"""
from __future__ import annotations

import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
from paths import PC_EXE

sys.path.insert(0, str(SCRIPT_DIR))
from extract_pc_fnv_string_xrefs import (
    parse_pe_x86, find_function_start_for_offset,
)
from addressing import FNV_IMAGE_BASE, load_vtable_records


def load_vtables() -> Dict[int, str]:
    """{vtable_va: class_name} from fnv_pc_vtables.txt + RTTI extras."""
    records = load_vtable_records(
        [REFS_DIR / 'fnv_pc_vtables.txt',
         REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'])
    return {FNV_IMAGE_BASE + rec.table_rva: rec.class_name for rec in records}


def load_existing_names() -> Dict[int, str]:
    """RVAs already named via fallback symbols.  We skip ctor candidates
    landing on these (they have better names already)."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from pdb_naming import build_fallback_symbols
    return {s['a']: s['n'] for s in build_fallback_symbols() if s.get('a')}


sys.path.insert(0, str(SCRIPT_DIR.parent / 'core'))
from pdb_symbols import undecorate as _undecorate  # noqa: E402


def _demangle_class(cls: str) -> str:
    """Convert RTTI-extracted mangled class names to PDB-pretty form.

    Our vtable extraction stores classes in raw form between ``??_7`` and
    the first ``@@`` (e.g. ``?$SettingT@VGameSettingCollection`` for the
    templated ``SettingT<GameSettingCollection>``).  Templated classes
    need an EXTRA ``@@`` to terminate their args before the vftable
    marker, otherwise dbghelp returns the input unchanged.
    """
    if not cls or ('?$' not in cls and '@' not in cls.replace('::', '')):
        return cls
    # Templated names need an extra @@ before the vftable suffix to
    # terminate their template-arg list.
    suffix = '@@@@6B@' if cls.startswith('?$') else '@@6B@'
    mangled = f'??_7{cls}{suffix}'
    try:
        d = _undecorate(mangled)
    except Exception:
        return cls
    # Demangled form: ``[const ]Class::`vftable'`` -- pull the Class out.
    m = re.match(r"(?:const\s+)?(.+?)::`vftable'", d)
    if m:
        return m.group(1)
    return cls


def _sanitize_class_for_ctor(cls: str) -> str:
    """``BSSimpleArray<X,1024>`` -> ``BSSimpleArray`` (bare class).
    Constructors use the bare class name as the method name in MSVC.
    For nested classes like ``Class::Inner``, use the last segment."""
    last = cls.rsplit('::', 1)[-1]
    return last.split('<', 1)[0]


def main():
    print('Loading vtables (incl. RTTI extras)...')
    vtables = load_vtables()
    print(f'  vtables: {len(vtables):,}')

    print('Loading existing fallback names...')
    existing = load_existing_names()
    print(f'  named RVAs: {len(existing):,}')

    print(f'Parsing PE: {PC_EXE}')
    data, image_base, sects = parse_pe_x86(PC_EXE)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    print(f'  .text: 0x{text_vaddr:08X} ({len(text_bytes):,} bytes)')

    # Reverse map: vtable VA -> class for fast lookup
    vt_va_set = set(vtables.keys())

    print('Scanning .text for vtable VA references...')
    # Constructor pattern: ``mov dword ptr [reg], offset vtable_va``
    # encodes as a 4-byte LE VA preceded by 2-3 bytes of opcode/modrm.
    # Common forms:
    #   C7 06 XX XX XX XX    mov [esi], imm32
    #   C7 07 XX XX XX XX    mov [edi], imm32
    #   C7 45 ?? XX XX XX XX mov [ebp+disp8], imm32
    #   C7 47 ?? XX XX XX XX mov [edi+disp8], imm32
    #   C7 46 ?? XX XX XX XX mov [esi+disp8], imm32
    #   C7 06/07/45/47/46 with C6, A3, 89... variants
    #
    # We require the xref to be BOTH within the first 256 bytes of the
    # heuristic function start AND preceded by one of the C7 forms
    # (constructor-typical "store immediate to memory" pattern).
    _MOV_MEM_IMM = (0xC7,)
    fn_to_vts: Dict[int, List[tuple]] = defaultdict(list)
    n_xrefs = 0
    n_in_fn = 0
    n_ctor_pat = 0
    for i in range(2, len(text_bytes) - 4):
        v = (text_bytes[i] | (text_bytes[i+1] << 8) |
             (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if v not in vt_va_set:
            continue
        n_xrefs += 1
        # Require ``C7 <modrm> [disp] imm32`` -- the modrm byte for
        # [esi]/[edi]/[ebp+d8]/[esi+d8]/[edi+d8] is 0x06/0x07/0x45/0x46/0x47.
        # imm32 starts at position i, so the modrm + opcode is at i-2 (for
        # no-disp forms) or i-3 (with disp8).
        is_ctor_pattern = False
        if i >= 2 and text_bytes[i-2] == 0xC7 \
           and text_bytes[i-1] in (0x06, 0x07):
            is_ctor_pattern = True
        elif i >= 3 and text_bytes[i-3] == 0xC7 \
             and text_bytes[i-2] in (0x45, 0x46, 0x47):
            is_ctor_pattern = True
        if not is_ctor_pattern:
            continue
        n_ctor_pat += 1
        fn_va = find_function_start_for_offset(text_bytes, text_vaddr, i)
        if fn_va == 0:
            continue
        # The byte-scan heuristic is only credible near the function entry.
        # Reject the old far-back matches rather than merely documenting a
        # 256-byte policy that the implementation did not enforce.
        xref_va = text_vaddr + i
        if xref_va < fn_va or xref_va - fn_va > 256:
            continue
        n_in_fn += 1
        fn_to_vts[fn_va].append((i, v))
    print(f'  raw 4-byte VA matches:               {n_xrefs:,}')
    print(f'  preceded by C7 mov-imm pattern:      {n_ctor_pat:,}')
    print(f'  resolved to a function:              {n_in_fn:,}')
    print(f'  unique constructor-candidate fns:    {len(fn_to_vts):,}')

    # Emit: for each fn that's NOT already named, pick the PRIMARY vtable
    # (the one whose class has the most fns associated -- typically the
    # primary base of a multi-inherit ctor) and name as Class::Class.
    matches: List = []
    skipped_named = 0
    multi_picked  = 0
    for fn_va, vts in fn_to_vts.items():
        rva = fn_va - image_base
        if rva in existing:
            skipped_named += 1
            continue
        # Sort xrefs by byte offset (instruction order)
        vts_sorted = sorted(set((off, vt) for off, vt in vts),
                            key=lambda x: x[0])
        unique_vts = list({vt for _, vt in vts_sorted})
        if len(unique_vts) == 1:
            vt = unique_vts[0]
        else:
            # Multi-vtable function (multi-inheritance ctor/dtor).
            # MSVC overwrites base vtable ptrs with derived class's LAST,
            # so the LATEST byte offset's vtable is the primary class.
            vt = vts_sorted[-1][1]
            multi_picked += 1
        raw_cls = vtables.get(vt, '')
        if not raw_cls:
            continue
        # Demangle templated forms (``?$SettingT@VGameSettingCollection``
        # -> ``SettingT<GameSettingCollection>``) to match PDB sigs.
        cls = _demangle_class(raw_cls)
        # MSVC PDB emits constructor methods with the FULL class name
        # (including template args) repeated as the method name:
        #   ``SettingT<GameSettingCollection>::SettingT<GameSettingCollection>``
        # For nested classes (``Class::Inner``) use just the last
        # segment as the method name.
        last_seg = cls.rsplit('::', 1)[-1]
        if last_seg:
            matches.append((rva, f'{cls}::{last_seg}', vt))

    print(f'  named candidates: {len(matches):,}')
    print(f'  skipped (already named): {skipped_named:,}')
    print(f'  multi-vtable resolved via LAST-write heuristic: {multi_picked:,}')

    out_path = REFS_DIR / 'fnv_constructor_names.csv'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# constructor-candidate names: 0x<rva>|<Class::Class>|0x<vtable_va>\n')
        f.write('# ADDRESS_COORDINATE=RVA\n')
        f.write('# EVIDENCE=nearest-start;max-distance=256;opcode=C7\n')
        for rva, name, vt in sorted(matches):
            f.write(f'0x{rva:08X}|{name}|0x{vt:08X}\n')
    print(f'Wrote {out_path}: {len(matches):,} new constructor candidates')


if __name__ == '__main__':
    main()
