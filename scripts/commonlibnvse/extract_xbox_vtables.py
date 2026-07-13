#!/usr/bin/env python3
"""Extract per-class vtable slot order from the FNV Xbox 360 dev-kit PDB+EXE.

For each primary vtable symbol (``??_7Class@@6B@``) in the PDB, read the
function-pointer slots from ``Fallout.exe`` (PowerPC BE PE32), resolve
each pointer to a function name via PDB publics, and emit a JSON map:

    { "ClassName": ["VTable mangled name (slot 0)",
                    "Method0 mangled",
                    "Method1 mangled", ...], ... }

This is the slot-order ground truth we need to positional-match Xbox
vftable contents onto PC FNV's RTTI-walked vtables (same C++ source,
same vtable shape -- just different ISA/addresses).

Run:
    python extract_xbox_vtables.py <pdb> <exe> <publics_dump> <out.json> [pc_vtables.txt]

If pc_vtables.txt is supplied, Xbox reads are capped to the PC FNV vtable's
slot count per class.  Without it, bounds come from the next ``??_7`` symbol,
which over-reads when vtables aren't densely symbolic (TESForm goes from
~30 real slots to 78 read).
"""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

from paths import executable
LLVM_UNDNAME = str(executable('BGS_LLVM_UNDNAME', 'llvm-undname',
                              'tools/llvm/bin/llvm-undname.exe'))


# ---------------------------------------------------------------------------
# PE parsing for PowerPC BE Fallout.exe
# ---------------------------------------------------------------------------

def parse_pe(path: Path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe_off:pe_off + 4] == b'PE\x00\x00'
    coff = pe_off + 4
    machine = struct.unpack_from('<H', data, coff)[0]
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt = coff + 20
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    # PE32+ vs PE32 (Xbox uses PE32, image base @ opt+28)
    magic = struct.unpack_from('<H', data, opt)[0]
    is_pe32_plus = (magic == 0x20B)
    image_base = struct.unpack_from('<Q' if is_pe32_plus else '<I',
                                     data, opt + (24 if is_pe32_plus else 28))[0]
    sect_off = opt + opt_sz
    sects = []
    for i in range(nsec):
        so = sect_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin-1', 'replace')
        vsize = struct.unpack_from('<I', data, so + 8)[0]
        vaddr = struct.unpack_from('<I', data, so + 12)[0]
        rsize = struct.unpack_from('<I', data, so + 16)[0]
        rptr  = struct.unpack_from('<I', data, so + 20)[0]
        chars = struct.unpack_from('<I', data, so + 36)[0]
        sects.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                       'rptr': rptr, 'rsize': rsize, 'chars': chars})
    return data, image_base, sects, machine


def rva_to_off(sects, rva):
    for s in sects:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize']):
            return s['rptr'] + (rva - s['vaddr'])
    return None


def is_text_rva(sects, rva):
    for s in sects:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize']):
            # IMAGE_SCN_MEM_EXECUTE = 0x20000000
            return bool(s['chars'] & 0x20000000)
    return False


# ---------------------------------------------------------------------------
# PDB publics parse + demangling
# ---------------------------------------------------------------------------

_PUB_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S+)\s*$')


def load_publics(path: Path) -> dict:
    out = {}
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _PUB_RE.match(line)
            if m:
                rva = int(m.group(1), 16)
                # Earlier wins on collisions (PDB lists primary symbol first)
                out.setdefault(rva, m.group(2))
    return out


def is_primary_vftable(mangled: str, cls: str) -> bool:
    """MSVC primary vftable mangle: ``??_7<class>@@6B@`` (no base subobject)."""
    return mangled.endswith('6B@') and '@@6B@' in mangled


def is_secondary_vftable(mangled: str) -> bool:
    """MSVC secondary vftable: ``??_7Class@@6B<BaseName>@@@`` (multi-inheritance)."""
    if not mangled.startswith('??_7'):
        return False
    if mangled.endswith('@@6B@'):
        return False
    # Has ``@@6B`` followed by a base subobject identifier
    idx = mangled.find('@@6B')
    return idx > 0 and mangled.endswith('@@@')


def vftable_class_name(mangled: str) -> str:
    """Extract the class name from ``??_7Class@@6B[Base]@@@``.

    Returns the bare class name; caller filters by base-subobject presence.
    """
    if not mangled.startswith('??_7'):
        return ''
    body = mangled[4:]
    end = body.find('@@')
    return body[:end] if end > 0 else ''


def vftable_base_name(mangled: str) -> str:
    """For a secondary vftable ``??_7Class@@6BBase@@@``, extract ``Base``.
    Returns '' for primary vtables.
    """
    if not is_secondary_vftable(mangled):
        return ''
    idx = mangled.find('@@6B')
    if idx < 0:
        return ''
    # Trim the trailing ``@@@`` (or ``@@``)
    base_part = mangled[idx + 4:]
    if base_part.endswith('@@@'):
        return base_part[:-3]
    if base_part.endswith('@@'):
        return base_part[:-2]
    return base_part


def demangle_batch(mangled_list, batch=100):
    """Demangle a list of MSVC names via llvm-undname.exe.  Returns dict."""
    out = {}
    if not os.path.isfile(LLVM_UNDNAME):
        return {m: m for m in mangled_list}
    for i in range(0, len(mangled_list), batch):
        chunk = mangled_list[i:i + batch]
        try:
            r = subprocess.run([LLVM_UNDNAME, '--no-callee-cc', '--no-return-type',
                                '--no-access-specifier', '--no-member-type'],
                               input='\n'.join(chunk), capture_output=True,
                               text=True, check=False)
        except Exception:
            for m in chunk: out[m] = m
            continue
        if r.returncode != 0:
            for m in chunk:
                out[m] = m
            continue
        # llvm-undname echoes "<mangled>\n<demangled>\n"
        lines = r.stdout.splitlines()
        for j in range(0, len(lines) - 1, 2):
            mangled = lines[j].strip()
            demangled = lines[j + 1].strip() if j + 1 < len(lines) else mangled
            out[mangled] = demangled
    return out


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def load_pc_vtable_sizes(path: Path) -> dict:
    """Parse all physical PC table sizes without last-wins class collapse."""
    out = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not line.startswith('VTABLE|'):
            continue
        parts = line.split('|')
        if len(parts) >= 4:
            cls = parts[2].strip()
            n = parts[3].strip().split()[0]
            try:
                out.setdefault(cls, []).append(int(n))
            except ValueError:
                pass
    return out


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    pdb_path, exe_path, publics_path, out_path = map(Path, sys.argv[1:5])
    pc_vtable_path = Path(sys.argv[5]) if len(sys.argv) > 5 else None
    pc_sizes = load_pc_vtable_sizes(pc_vtable_path) if pc_vtable_path else {}
    if pc_sizes:
        print(f'Loaded PC vtable sizes for {len(pc_sizes)} classes (used to cap Xbox reads)')

    print(f'Loading PE: {exe_path.name}')
    data, image_base, sects, machine = parse_pe(exe_path)
    arch = {0x14c: 'x86', 0x1f2: 'PowerPC BE'}.get(machine, hex(machine))
    print(f'  arch={arch}  image_base=0x{image_base:X}  sections={len(sects)}')
    # PowerPC BE = 4-byte big-endian pointers
    ptr_struct = '>I' if machine == 0x1f2 else '<I'
    ptr_size = 4

    print(f'Loading PDB publics: {publics_path.name}')
    publics = load_publics(publics_path)
    print(f'  {len(publics)} symbols (deduped by RVA)')

    # Primary vtable symbols (``??_7Class@@6B@``) — our main extraction targets.
    # ALSO extract secondary vtables (``??_7Class@@6BBase@@@``) for
    # multi-inheritance classes -- those keep ~30% more naming surface.
    primary_vts = []
    secondary_vts = []
    all_vt_rvas = []
    for rva, mangled in publics.items():
        if not mangled.startswith('??_7'):
            continue
        all_vt_rvas.append(rva)
        if mangled.endswith('@@6B@'):
            cls = vftable_class_name(mangled)
            if cls:
                primary_vts.append((rva, cls, mangled))
        elif is_secondary_vftable(mangled):
            cls = vftable_class_name(mangled)
            base = vftable_base_name(mangled)
            if cls and base:
                # V2 keeps class and base-subobject in separate fields; never
                # collapse identity into a class-keyed JSON property.
                secondary_vts.append((rva, cls, mangled))
    primary_vts.sort()
    secondary_vts.sort()
    all_vt_rvas.sort()
    print(f'  primary vtables: {len(primary_vts)}  secondary: {len(secondary_vts)} '
          f'(all vtable symbols: {len(all_vt_rvas)})')

    # For each vtable (primary OR secondary), the bound is the NEXT vtable
    # symbol of ANY kind.  Both primary and secondary are bounded by their
    # neighbor; without that, reads spill across into adjacent vtables.
    next_vt = {}
    import bisect
    for rva, _, _ in (primary_vts + secondary_vts):
        i = bisect.bisect_right(all_vt_rvas, rva)
        next_vt[rva] = all_vt_rvas[i] if i < len(all_vt_rvas) else rva + 0x10000

    # Build vtable layouts: read pointers from EXE, resolve names.
    # We extract BOTH primary and secondary vtables -- they're keyed
    # differently in the JSON so downstream matching can pair both
    # against PC FNV's RTTI-found vtables.
    all_vts = primary_vts + secondary_vts
    layouts = {}
    n_classes_named = n_total_slots = n_unnamed_slots = 0
    for rva, cls, mangled in all_vts:
        off = rva_to_off(sects, rva)
        if off is None:
            continue
        max_slots = min((next_vt[rva] - rva) // ptr_size, 256)
        # Cap to PC FNV vtable count when known -- avoids over-reading past
        # the real vtable into adjacent non-symbolic data.
        # A class can own multiple primary/secondary tables.  The legacy PC
        # text lacks a subobject tag, so only use its size as a cap when the
        # class has exactly one physical table.
        if cls in pc_sizes and len(pc_sizes[cls]) == 1:
            max_slots = min(max_slots, pc_sizes[cls][0])
        slots = []
        for s in range(max_slots):
            entry = data[off + s * ptr_size: off + s * ptr_size + ptr_size]
            if len(entry) < ptr_size:
                break
            va = struct.unpack(ptr_struct, entry)[0]
            if va == 0:
                break
            target_rva = va - image_base
            if not is_text_rva(sects, target_rva):
                break
            # Exact match only — the nearest-preceding fallback assigns wrong
            # names to slots that happen to land between unrelated functions
            # (a vtable slot pointer should be exactly the function entry).
            name = publics.get(target_rva)
            slots.append({'m': name or f'__unnamed_{target_rva:08x}',
                          'rva': target_rva})
            if not name:
                n_unnamed_slots += 1
        if slots:
            # A list, not a class-keyed dict: duplicate physical tables are
            # semantically distinct and must never overwrite one another.
            layouts.setdefault(cls, []).append({
                'rva': rva,
                'mangled': mangled,
                'slots': slots,
            })
            n_classes_named += 1
            n_total_slots += len(slots)

    print(f'Built vtable layouts: {n_classes_named} classes, '
          f'{n_total_slots} total slots, {n_unnamed_slots} unnamed slot entries')

    # Demangle method names for human readability + downstream matching
    print('Demangling method names via llvm-undname...')
    all_mangled = sorted({s['m'] for tables in layouts.values()
                          for table in tables for s in table['slots']
                          if s['m'].startswith('?')})
    demangled = demangle_batch(all_mangled, batch=200)
    print(f'  demangled {len(demangled)} unique names')

    # Final output: per-class, slot-ordered list of {mangled, demangled}
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from vtable_schema import make_document
    output_tables = []
    for cls, tables in layouts.items():
        for table in tables:
            mangled = table['mangled']
            subobject = vftable_base_name(mangled)
            slots = []
            for slot in table['slots']:
                m = slot['m']
                slots.append({'m': m, 'd': demangled.get(m, m),
                              'rva': slot['rva']})
            output_tables.append({
                'id': 'xbox:0x%08X:%s:%s' %
                      (table['rva'], cls, subobject or 'primary'),
                'class': cls,
                'subobject': subobject,
                'rva': table['rva'],
                'mangled': mangled,
                'slots': slots,
            })
    output = make_document(output_tables, address_coordinate='RVA',
                           image_base=image_base, machine=machine,
                           pointer_size=ptr_size)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        json.dump(output, f)
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
