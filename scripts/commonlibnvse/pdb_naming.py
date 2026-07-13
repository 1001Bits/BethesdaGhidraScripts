#!/usr/bin/env python3
"""PDB-derived fallback symbols for FalloutNV.

Sources, in priority order (lower index wins on address collision):

  1. ``refs/fnv_pc_symbols.txt``  -- 7.6k labels from xNVSE / JIP LN NVSE
     headers in ``0xVA|name|src`` form.  Already PC FNV image-base coords.
  2. ``refs/fnv_xbox_vtables.json`` + ``refs/fnv_pc_vtables.txt``
     -- per-class Xbox vtable slot order paired with PC FNV vtable
     addresses.  For each class present in both, emit
     ``Class::method`` for every PC vfunc slot whose Xbox counterpart
     has a name.  This is the rich source: ~1800 classes, ~45k slots.
  3. ``refs/fnv_pdb_matched_classes.txt`` -- legacy pre-matched cross-ref
     (predates the direct vtable extraction).  Only consumes classes
     with exact PDB-method-count == PC-vfunc-count (~112 classes).

Returns a list of symbol entries shaped for the FNV pipeline's
``fallback_symbols_json`` slot:
    {'n': qualified_name, 't': 'func'|'label', 'sig': '', 'a': rva, 'fnv': rva, 'src': label}
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / "refs"
FNV_IMAGE_BASE = 0x00400000

sys.path.insert(0, str(SCRIPT_DIR))
from addressing import (AddressError, load_vtable_records,
                        normalize_address)  # noqa: E402
from vtable_schema import load_xbox_tables  # noqa: E402
from paths import ARTIFACTS, artifact  # noqa: E402

_XBOX_METHOD_IDENTITY_BY_RVA = {}

_VTABLE_HINTS = ('_vtbl', '_vtable', 'vtable_', 'VTABLE_', '::vftable',
                 '_RTTI', 'RTTI_', '_RTTIType', 'kVtbl_', 'g_vftable_',
                 's_vtbl_')

# These sources identify the PC address by decoding a vtable slot.  That is
# direct executable-entry evidence, independent of how the method name was
# recovered.  Heuristic xref/callgraph/immediate/constructor corpora are
# intentionally absent: they may rename an existing Ghidra function but must
# never cause the x86 importer to materialize a new one.
_VERIFIED_ENTRY_SOURCES = frozenset((
    'commonlib_vtable',
    'xbox_vtable',
    'xbox_pdb_matched',
))


def _verified_entry_source(source: str) -> bool:
    return source in _VERIFIED_ENTRY_SOURCES


def _looks_like_label(name: str) -> bool:
    return any(h in name for h in _VTABLE_HINTS)


def _load_nvse_known(path: Path) -> List[Tuple[int, str]]:
    """Parse fnv_pc_symbols.txt (`0xVA|name|source` form), discard noise."""
    out: List[Tuple[int, str]] = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        parts = ln.split('|', 2)
        if len(parts) < 2:
            continue
        addr_s, name = parts[0].strip(), parts[1].strip()
        if not addr_s.startswith('0x'):
            continue
        # Image-base bogus entries the extractor included for flag enums.
        if int(addr_s, 16) == FNV_IMAGE_BASE:
            continue
        if name.startswith(('aka:', 'GAME -', 'GAME-', 'GECK -', 'GECK-',
                            'see 0x', 'see address', 'unknown ', '0x')):
            continue
        if name.startswith(('kFlag', 'kFlags_', 'kEffFlag', 'kFormFlag',
                            'kNiFlag')):
            # Bitmask enum values were scraped as though they were addresses.
            continue
        # Drop parenthetical noise the extractor appended to flag-enum names.
        name = re.sub(r'\s*\([^)]*\)\s*$', '', name).strip()
        if not name:
            continue
        # Skip names that are basically a hex literal or comma-list of them.
        if re.fullmatch(r'(?:0x[0-9A-Fa-f]+[,\s]*)+', name):
            continue
        # Skip names that contain spaces and look like prose ("locale fix" etc.).
        # Real identifiers don't have spaces.
        if ' ' in name and not name.startswith(('kVtbl_', 'k_', 'g_', 's_', 'kFlag', 'kEvent')):
            continue
        try:
            va = int(addr_s, 16)
        except ValueError:
            continue
        try:
            out.append((normalize_address(va, 'VA'), name))
        except AddressError:
            continue
    return out


_CLASS_HDR = re.compile(r'^#\s+(\w+)\s*$', re.M)
_PDB_METHOD = re.compile(
    r'#\s+PDB seg\d+:0x[0-9A-Fa-f]+\s+\w[\w:]*::(?P<m>[~`]?[\w<>\s]+?)\s*$', re.M)
_PC_VFUNC = re.compile(
    r'^\s+PC\s+0x(?P<addr>[0-9A-Fa-f]+)\s*=\s*\w+::vfunc_(?P<slot>\d+)\s*$', re.M)


def _load_matched_vtable_methods(path: Path) -> List[Tuple[int, str]]:
    """For each class block where PDB method count == PC vfunc count,
    positional-map PDB names to PC vtable slot RVAs.  Returns (rva, "Class::method").
    """
    out: List[Tuple[int, str]] = []
    if not path.is_file():
        return out
    text = path.read_text(encoding='utf-8', errors='replace')
    # Class blocks separated by blank-line-then-class-header.
    blocks = re.split(r'\n(?=# \w+\s*\n)', text)
    for blk in blocks:
        m = re.match(r'^#\s+(\w+)\s*\n', blk)
        if not m:
            continue
        cls = m.group(1)
        methods = [m.group('m').strip() for m in _PDB_METHOD.finditer(blk)]
        slots = [(int(m.group('addr'), 16), int(m.group('slot')))
                 for m in _PC_VFUNC.finditer(blk)]
        if not methods or not slots or len(methods) != len(slots):
            continue
        # Slots aren't guaranteed sequential in the file; sort by slot index.
        slots.sort(key=lambda x: x[1])
        for (addr, _slot), method in zip(slots, methods):
            # Strip the trailing parenthesis form some destructors carry.
            clean = method.split('(')[0].strip()
            qname = f'{cls}::{clean}'
            try:
                out.append((normalize_address(addr, 'VA'), qname))
            except AddressError:
                continue
    return out


_PC_VT_HDR = re.compile(r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|(\d+)\s+vfuncs\s*$')
# Class name in slot rows can include templated chars (?$@<>) and digits,
# so match anything up to the literal ``::vf`` / ``::vfunc_`` suffix.
_PC_VT_ROW = re.compile(r'^\s+VFUNC\|0x([0-9A-Fa-f]+)\|.+?::vf(?:unc_)?(\d+)\s*$')


def _strip_args(demangled: str) -> str:
    """``ClassName::method(args)`` -> ``ClassName::method`` (drop signature)."""
    # Cut at the first unparenthesized '(' from the right -- demangled names
    # may have ``operator()`` etc. inside, so simple split('(') is unsafe.
    depth = 0
    last_paren = -1
    for i in range(len(demangled) - 1, -1, -1):
        ch = demangled[i]
        if ch == ')':
            depth += 1
        elif ch == '(':
            depth -= 1
            if depth == 0:
                last_paren = i
                break
    if last_paren > 0:
        return demangled[:last_paren].rstrip()
    return demangled


def _load_xbox_vtable_methods() -> List[Tuple[int, str]]:
    """Pair the Xbox per-class vtable slot order with PC FNV vtable slot RVAs.

    For each class present in both fnv_xbox_vtables.json (Xbox slot ->
    demangled name) and fnv_pc_vtables.txt (PC slot RVA -> generic vfN),
    pair them positionally: PC slot N's RVA gets named after Xbox slot N's
    method.  Returns [(rva, "Class::method"), ...].

    Also consumes fnv_pc_vtables_rtti_extra.txt when present -- those
    are RTTI-discovered vtables that Ghidra missed (templated types,
    etc.).
    """
    xbox_path = REFS_DIR / 'fnv_xbox_vtables.json'
    pc_path   = REFS_DIR / 'fnv_pc_vtables.txt'
    pc_extra  = REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'
    if not xbox_path.is_file() or not pc_path.is_file():
        return []

    raw_xbox = json.loads(xbox_path.read_text(encoding='utf-8'))
    if not isinstance(raw_xbox, dict) or raw_xbox.get('schema') != 'fnv-xbox-vtables-v2':
        # V1 was class-keyed and irreversibly overwrote duplicate physical
        # tables.  It can be read by migration tools, but is not safe input for
        # automatic naming.
        return []

    xbox_tables = load_xbox_tables(raw_xbox)
    pc_records = load_vtable_records([pc_path, pc_extra])

    # Demangle on-the-fly via dbghelp -- when extract_xbox_vtables.py was
    # built llvm-undname.exe wasn't on this box so the JSON's ``d`` field
    # was just the mangled string.  Re-undecorate here so we get real
    # method names (and they'll match the PDB sig index downstream).
    import sys as _sys
    _sys.path.insert(0, str((SCRIPT_DIR.parent / 'core').resolve()))
    from pdb_symbols import undecorate

    def _qname_template_aware(s: str) -> str:
        """Template-aware ``return_type Class::method`` -> ``Class::method``.
        Walks backwards from end counting ``<>`` depth so template commas
        don't fool the split."""
        tdepth = 0
        start = 0
        for i in range(len(s) - 1, -1, -1):
            ch = s[i]
            if ch == '>':
                tdepth += 1
            elif ch == '<':
                tdepth -= 1
            elif ch.isspace() and tdepth == 0:
                start = i + 1
                break
        return s[start:].strip()

    def _qname_from_demangled(d: str, cls_fallback: str, slot_i: int) -> str:
        """Extract ``Class::method`` from a demangled MSVC name, handling
        backticked special methods, ``_purecall``, templated class names
        with commas, etc."""
        if d in ('_purecall', '__purecall', '__abi_winrt_thunk') or '__cdecl' in d and '::' not in d:
            return f'{cls_fallback}::vf{slot_i:03d}_{d.lstrip("_")}'
        m_bt = re.search(r"`([^']+)'", d)
        if m_bt:
            spec = m_bt.group(1).replace(' ', '_')
            head = d[:m_bt.start()].rstrip(':').rstrip()
            head = head.split('(')[0].rstrip()
            head = _qname_template_aware(head)
            if head.endswith('::'):
                head = head[:-2]
            if head:
                return f'{head}::{spec}'
            return f'{cls_fallback}::vf{slot_i:03d}_{spec}'
        s = _strip_args(d)
        qname = _qname_template_aware(s)
        if qname and '::' in qname:
            return qname
        return f'{cls_fallback}::vf{slot_i:03d}'

    xbox_by_class = {}
    pc_by_class = {}
    for table in xbox_tables:
        xbox_by_class.setdefault(table.class_name, []).append(table)
    for table in pc_records:
        pc_by_class.setdefault(table.class_name, []).append(table)

    def _emit_slot(xb_slot, pc_slot_rva, cls, slot_idx, table_ids, out_list):
        method_full = xb_slot.get('d') or xb_slot.get('m', '')
        mangled     = xb_slot.get('m', '')
        if not method_full or method_full.startswith('__unnamed_'):
            return
        if method_full == mangled and mangled.startswith('?'):
            try:
                method_full = undecorate(mangled)
            except Exception:
                pass
        qname = _qname_from_demangled(method_full, cls, slot_idx)
        out_list.append((pc_slot_rva, qname))
        _XBOX_METHOD_IDENTITY_BY_RVA[pc_slot_rva] = {
            'qname': qname,
            'demangled': method_full,
            'mangled': mangled,
            'xbox_table': table_ids[0],
            'pc_table': table_ids[1],
            'slot': slot_idx,
        }

    out: List[Tuple[int, str]] = []
    for cls, xb_tables in xbox_by_class.items():
        pc_tables = pc_by_class.get(cls, [])
        if not pc_tables:
            continue

        # Only accept reciprocal-unique, exact-size table matches.  Positional
        # concatenation was the source of widespread secondary-table method
        # corruption when two tables had similar lengths.
        xb_candidates = {
            xb.identity: [pc for pc in pc_tables
                          if len(pc.slots) == len(xb.slots) and
                          (not xb.subobject or not pc.subobject or
                           xb.subobject == pc.subobject)]
            for xb in xb_tables
        }
        pc_candidates = {
            pc.identity: [xb for xb in xb_tables
                          if len(pc.slots) == len(xb.slots) and
                          (not xb.subobject or not pc.subobject or
                           xb.subobject == pc.subobject)]
            for pc in pc_tables
        }
        pairs = []
        for xb in xb_tables:
            candidates = xb_candidates[xb.identity]
            if len(candidates) != 1:
                continue
            pc = candidates[0]
            reverse = pc_candidates[pc.identity]
            if len(reverse) != 1 or reverse[0].identity != xb.identity:
                continue
            pairs.append((xb, pc))

        for xb, pc in pairs:
            pc_slots = dict(pc.slots)
            for i, entry in enumerate(xb.slots):
                pc_rva = pc_slots.get(i)
                if pc_rva is None:
                    continue
                _emit_slot(entry, pc_rva, cls, i,
                           (xb.identity, pc.identity), out)
    return out


def _load_string_anchored(path: Path) -> List[Tuple[int, str]]:
    """Parse string_anchored.csv (``0xRVA|qualified name|<src>``).

    Sources: self-naming string anchors (string_anchor_lift.py).
    """
    out = []
    if not path.is_file():
        return out
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    for ln in lines:
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 2)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        try:
            out.append((normalize_address(rva, 'RVA'), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_string_xref_names(path: Path) -> List[Tuple[int, str]]:
    """Parse string_xref_names.csv (``0xRVA|qname|tier|votes|mangled``).

    Sources: string-xref greedy bipartite matching (match_string_xrefs.py).
    """
    out = []
    if not path.is_file():
        return out
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    if '# EVIDENCE=reciprocal-unique;min-signal=0.5;min-votes=2' not in lines[:8]:
        return out
    for ln in lines:
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 4)
        if len(p) < 4:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        tier = p[2].strip().upper()
        try:
            votes = int(p[3])
        except ValueError:
            continue
        # Quarantine low-signal and one-vote transfers.  Existing T2-T4
        # corpora were greedy assignments without reciprocal uniqueness.
        if tier != 'T1' or votes < 2:
            continue
        try:
            out.append((normalize_address(rva, 'RVA'), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_source_file_names(path: Path) -> List[Tuple[int, str]]:
    """Parse source_file_names.csv (``0xRVA|qname|cpp_basename|mangled``).

    Sources: per-compiland positional matching (source_file_cluster_lift.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        try:
            out.append((normalize_address(rva, 'RVA'), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_imm_paired_names(path: Path) -> List[Tuple[int, str]]:
    """Parse imm_paired_names.csv (``0xRVA|qname|0xIMM|mangled``).

    Sources: rare-immediate fingerprint pairing
    (extract_xbox_rare_immediates.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        try:
            out.append((normalize_address(rva, 'RVA'), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_constructor_names(path: Path, coordinate: str = 'RVA',
                            required_evidence: str = '') -> List[Tuple[int, str]]:
    """Parse constructor_names.csv (``0xRVA|Class::Class|0xvtable_va``).

    Sources: vtable-VA byte-scan (find_fnv_constructors.py).
    """
    out = []
    if not path.is_file():
        return out
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    if required_evidence and not any(
            ln.strip() == '# EVIDENCE=' + required_evidence for ln in lines[:16]):
        return out
    for ln in lines:
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 2)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        try:
            out.append((normalize_address(rva, coordinate), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_global_labels(path: Path) -> List[Tuple[int, str]]:
    """Parse global_label_names.csv (``0xRVA|qname|votes|mangled``).

    Sources: xref-set-similarity pairing (match_globals_via_xrefs.py).
    These are DATA addresses, named as ``label`` symbols.
    """
    out = []
    if not path.is_file():
        return out
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    if '# EVIDENCE=reciprocal-unique;min-votes=2' not in lines[:8]:
        return out
    for ln in lines:
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        try:
            votes = int(p[2]) if len(p) > 2 else 0
        except ValueError:
            continue
        if votes < 2:
            continue
        try:
            out.append((normalize_address(rva, 'RVA'), p[1].strip()))
        except AddressError:
            continue
    return out


def _load_pc_vtable_labels(path: Path) -> List[Tuple[int, str]]:
    """Parse fnv_pc_vtables.txt and emit (rva, 'VTABLE_<Class>') pairs.

    Format: ``VTABLE|0x<RVA>|<ClassName>|<N> vfuncs`` (header rows only).
    These labels let the generated import script's vtable-walk pass find
    the vtable base for each CommonLib-defined class and name slot
    pointers from it.  Image base is 0x00400000; the RVA is already
    relative.
    """
    out: List[Tuple[int, str]] = []
    if not path.is_file():
        return out
    records = load_vtable_records([path])
    counts = {}
    for rec in records:
        counts[rec.class_name] = counts.get(rec.class_name, 0) + 1
    ordinals = {}
    for rec in records:
        cls = rec.class_name
        rva = rec.table_rva
        # rtti_extra rows carry partially-mangled template names like
        # ``?$SettingT@VGameSettingCollection`` -- sanitize to a Ghidra-
        # legal identifier (mirrors pdb_types_to_pipeline normalization).
        cls = re.sub(r'[^\w]', '_', cls)
        while '__' in cls:
            cls = cls.replace('__', '_')
        cls = cls.strip('_')
        if not cls:
            continue
        ordinal = ordinals.get(rec.class_name, 0)
        ordinals[rec.class_name] = ordinal + 1
        suffix = ('__table_%d_%08X' % (ordinal, rva)
                  if counts[rec.class_name] > 1 else '')
        out.append((rva, 'VTABLE_' + cls + suffix))
    return out


def _load_pdb_compiland_index():
    """Load Xbox VA -> compiland-basename map and build PC RVA -> compiland
    via the xbox_vtable + string_xref pairings (the two sources where we
    know both sides of the PC<->Xbox correspondence)."""
    import json as _j
    out: Dict[int, str] = {}
    cmp_path = artifact('Fallout_Debug_modules.json')
    if not cmp_path.is_file():
        return out
    va_to_cmp = _j.loads(cmp_path.read_text(encoding='utf-8'))
    # Convert string keys (json) to int
    va_to_cmp = {int(k): v for k, v in va_to_cmp.items()}

    # PC RVA -> name -> (Xbox VA via funcs.json) -> compiland
    funcs_path = artifact('Fallout_Debug_funcs.json')
    name_to_xbox_va: Dict[str, int] = {}
    if funcs_path.is_file():
        for _cls, fns in _j.loads(funcs_path.read_text(encoding='utf-8')).items():
            for fn in fns:
                qname = fn.get('name')
                va    = fn.get('va')
                if qname and va and qname not in name_to_xbox_va:
                    name_to_xbox_va[qname] = va

    # 1. xbox_vtable pairs (PC RVA -> qualified name)
    for rva, name in _load_xbox_vtable_methods():
        xb_va = name_to_xbox_va.get(name)
        if xb_va is not None:
            cmp = va_to_cmp.get(xb_va)
            if cmp:
                out.setdefault(rva, cmp)

    # 2. string_xref CSV
    p = REFS_DIR / 'fnv_string_xref_names.csv'
    if p.is_file():
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            parts = ln.split('|', 4)
            if len(parts) < 2:
                continue
            try:
                rva = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[1].strip()
            xb_va = name_to_xbox_va.get(name)
            if xb_va is not None:
                cmp = va_to_cmp.get(xb_va)
                if cmp:
                    out.setdefault(rva, cmp)
    return out


def _load_pdb_sig_index():
    """Lazy import + load the qualified-name -> C signature index.

    Merges sigs from all 4 PDBs (Debug + Retail + Release-Beta +
    Release-MemDebug).  Debug wins on collisions; the other builds fill
    gaps where Debug didn't surface a sig (different inlining/ICF).
    """
    try:
        from pdb_signatures import load_sigs
        base = ARTIFACTS
        paths = [base / f'{n}_funcs.json' for n in (
                 'Fallout_Debug', 'Fallout',
                 'Fallout_Release_Beta', 'Fallout_Release_MemDebug')]
        return load_sigs(paths)
    except Exception:
        return {}


def _build_rva_to_sig_index(sig_by_qname: Dict[str, str]) -> Dict[int, Tuple[str, str]]:
    """Build PC-RVA -> sig index using sources that surface BOTH a name
    AND an address.  Used as a fallback when the symbol's final name
    differs from the PDB qualified form (e.g. xNVSE wrappers like
    ``FormHeap_Allocate`` are PDB's ``Bethesda::FormHeap::Allocate``).
    """
    out: Dict[int, Tuple[str, str]] = {}

    # 1. xbox_vtable pairs (PC RVA -> qualified PDB name)
    for rva, name in _load_xbox_vtable_methods():
        identity = _XBOX_METHOD_IDENTITY_BY_RVA.get(rva, {}).get('demangled', '')
        resolver = getattr(sig_by_qname, 'resolve', None)
        sig = resolver(name, identity) if resolver else sig_by_qname.get(name)
        if sig:
            out.setdefault(rva, (name, sig))

    # 2. string_xref CSV (PC RVA -> qualified name)
    p = REFS_DIR / 'fnv_string_xref_names.csv'
    if p.is_file():
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            parts = ln.split('|', 4)
            if len(parts) < 2:
                continue
            try:
                rva = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[1].strip()
            sig = sig_by_qname.get(name)
            if sig:
                out.setdefault(rva, (name, sig))
    return out


def build_fallback_symbols() -> List[dict]:
    """Return the merged fallback symbol list for the FNV pipeline."""
    include_experimental = os.environ.get('BGS_FNV_INCLUDE_EXPERIMENTAL') == '1'
    nvse_syms     = _load_nvse_known(REFS_DIR / 'fnv_pc_symbols.txt')
    jip_syms      = _load_nvse_known(REFS_DIR / 'fnv_jip_addresses.txt')
    commonlib_path = REFS_DIR / 'fnv_commonlib_vtable_methods.csv'
    commonlib_text = (commonlib_path.read_text(encoding='utf-8', errors='replace')
                      if commonlib_path.is_file() else '')
    if '# ADDRESS_COORDINATE=RVA' in commonlib_text.splitlines()[:8]:
        commonlib = _load_constructor_names(commonlib_path, 'RVA')
    else:
        # Legacy output combined duplicate tables and also wrote VAs in an
        # RVA-labelled CSV.  It must be regenerated by the fixed scanner.
        commonlib = []
    pdb_syms      = _load_matched_vtable_methods(REFS_DIR / 'fnv_pdb_matched_classes.txt')
    xbox_vt       = _load_xbox_vtable_methods()
    string_anch   = _load_string_anchored(REFS_DIR / 'fnv_string_anchored.csv')
    string_xref   = _load_string_xref_names(REFS_DIR / 'fnv_string_xref_names.csv')
    src_file      = (_load_source_file_names(REFS_DIR / 'fnv_source_file_names.csv')
                     if include_experimental else [])
    imm_pairs     = (_load_imm_paired_names(REFS_DIR / 'fnv_imm_paired_names.csv')
                     if include_experimental else [])
    constructors  = (_load_constructor_names(
        REFS_DIR / 'fnv_constructor_names.csv', 'RVA',
        'nearest-start;max-distance=256;opcode=C7')
        if include_experimental else [])
    ghidra_ctors  = (_load_constructor_names(REFS_DIR / 'fnv_ghidra_ctor_names.csv')
                     if include_experimental else [])
    ghidra_dtors  = (_load_constructor_names(REFS_DIR / 'fnv_ghidra_dtor_names.csv')
                     if include_experimental else [])
    cgalign       = (_load_constructor_names(REFS_DIR / 'fnv_callgraph_names.csv')
                     if include_experimental else [])
    thunks        = _load_constructor_names(REFS_DIR / 'fnv_thunk_names.csv')  # same format
    globals_      = _load_global_labels(REFS_DIR / 'fnv_global_label_names.csv')
    ghidra_globs  = (_load_global_labels(REFS_DIR / 'fnv_ghidra_global_names.csv')
                     if include_experimental else [])
    pc_vtables    = (_load_pc_vtable_labels(REFS_DIR / 'fnv_pc_vtables.txt')
                     + _load_pc_vtable_labels(REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'))

    # Address -> (name, source).  Earlier source wins on collision.
    by_addr: Dict[int, Tuple[str, str]] = {}
    label_addrs: Dict[int, Tuple[str, str]] = {}  # data symbols (forced label)
    # These scraped files contain a mixture of function entries, globals,
    # vtables, hook sites, return sites and call instructions, but do not carry
    # a machine-readable symbol kind.  Import them as labels only; creating a
    # function requires a typed declaration or executable-section evidence.
    for rva, name in nvse_syms:
        label_addrs.setdefault(rva, (name, 'nvse_known'))
    for rva, name in jip_syms:
        label_addrs.setdefault(rva, (name, 'jip_known'))
    for rva, name in commonlib:
        by_addr.setdefault(rva, (name, 'commonlib_vtable'))
    for rva, name in xbox_vt:
        by_addr.setdefault(rva, (name, 'xbox_vtable'))
    for rva, name in string_anch:
        by_addr.setdefault(rva, (name, 'string_anchor'))
    for rva, name in string_xref:
        by_addr.setdefault(rva, (name, 'string_xref'))
    for rva, name in src_file:
        by_addr.setdefault(rva, (name, 'source_file'))
    for rva, name in imm_pairs:
        by_addr.setdefault(rva, (name, 'imm_paired'))
    for rva, name in constructors:
        by_addr.setdefault(rva, (name, 'ctor_byte_scan'))
    for rva, name in ghidra_ctors:
        by_addr.setdefault(rva, (name, 'ctor_ghidra_xref'))
    for rva, name in ghidra_dtors:
        by_addr.setdefault(rva, (name, 'dtor_ghidra_inferred'))
    for rva, name in cgalign:
        by_addr.setdefault(rva, (name, 'callgraph_align'))
    for rva, name in thunks:
        by_addr.setdefault(rva, (name, 'thunk_jmp'))
    for rva, name in pdb_syms:
        by_addr.setdefault(rva, (name, 'xbox_pdb_matched'))
    # Globals are DATA addresses -- never collide with function RVAs from
    # the sources above.  Tracked separately so they're always emitted as
    # labels, regardless of the looks-like-label heuristic.
    for rva, name in globals_:
        label_addrs.setdefault(rva, (name, 'global_label'))
    for rva, name in ghidra_globs:
        label_addrs.setdefault(rva, (name, 'global_ghidra_pair'))
    for rva, name in pc_vtables:
        label_addrs.setdefault(rva, (name, 'pc_vtable'))
    sig_index = _load_pdb_sig_index()
    rva_sig_index = _build_rva_to_sig_index(sig_index)
    compiland_index = _load_pdb_compiland_index()

    # Build a known-types index from the PDB types + enums + typedefs JSONs
    # so we can parse sigs into structured form.
    _types_known: set = set()
    _enums_known: set = set()
    _typedefs: dict = {}
    try:
        import json as _j
        types_p = artifact('Fallout_Debug_types.json')
        enums_p = artifact('Fallout_Debug_enums.json')
        tdefs_p = artifact('Fallout_Debug_typedefs.json')
        if types_p.is_file():
            _types_known = set(_j.loads(types_p.read_text(encoding='utf-8')))
        if enums_p.is_file():
            _enums_known = set(_j.loads(enums_p.read_text(encoding='utf-8')))
        if tdefs_p.is_file():
            _typedefs = _j.loads(tdefs_p.read_text(encoding='utf-8'))
    except Exception:
        pass

    try:
        from pdb_sig_to_structured import parse_sig
    except Exception:
        parse_sig = None

    # DIA-derived per-function locals (authoritative param names + types)
    try:
        from pdb_locals_apply import sd_from_dia, annotate_comment, load_locals
        _ = load_locals()  # warm cache
    except Exception:
        sd_from_dia = None
        annotate_comment = None

    def _alias_lookups(name: str) -> List[str]:
        """Yield alternate qualified-name forms to try for sig lookup.

        Bridges the gap between vtable-slot names (compiler-generated
        wrappers) and the user-defined methods the PDB sig index actually
        catalogs:
          - ``Class::scalar_deleting_destructor`` -> ``Class::~Class``
          - ``Class::vector_deleting_destructor`` -> ``Class::~Class``
          - ``Class<T>::scalar_deleting_destructor`` -> ``Class<T>::~Class``
            (handles templated class names too)
        """
        alts = []
        for suffix in ('::scalar_deleting_destructor',
                       '::vector_deleting_destructor'):
            if name.endswith(suffix):
                cls_full = name[:-len(suffix)]
                # MSVC PDB pretty emits destructors in two flavors:
                #   - ``Class::~Class`` (non-templated)
                #   - ``Class<T>::~Class<T>`` (templated, repeats template args)
                # Try both.
                last_seg = cls_full.rsplit('::', 1)[-1]
                bare = last_seg.split('<', 1)[0]
                if bare:
                    alts.append(f'{cls_full}::~{bare}')
                # Templated: append the FULL last segment (incl. template args)
                if '<' in last_seg:
                    alts.append(f'{cls_full}::~{last_seg}')
                break
        return alts

    out = []
    n_sigs_by_name = 0
    n_sigs_by_rva  = 0
    n_sigs_by_alias = 0
    n_sd_attached  = 0
    n_sd_from_dia  = 0
    n_locals_anno  = 0
    for rva, (name, src) in by_addr.items():
        source_kind = src
        is_label = _looks_like_label(name)
        sig = ''
        sd  = None
        if not is_label:
            identity = _XBOX_METHOD_IDENTITY_BY_RVA.get(rva, {})
            resolver = getattr(sig_index, 'resolve', None)
            sig = (resolver(name, identity.get('demangled', ''))
                   if resolver else sig_index.get(name, ''))
            if sig:
                n_sigs_by_name += 1
            else:
                # Try alias forms (destructor wrappers -> user dtor)
                for alt in _alias_lookups(name):
                    alt_sig = (resolver(alt, identity.get('demangled', ''))
                               if resolver else sig_index.get(alt, ''))
                    if alt_sig:
                        sig = alt_sig
                        n_sigs_by_alias += 1
                        break
                if not sig:
                    # An RVA-only signature from a lower-priority competing
                    # name is not proof that it belongs to the selected name.
                    # Attach it only when both sources preserve the same full
                    # qualified identity (normally already handled above).
                    rva_entry = rva_sig_index.get(rva)
                    if rva_entry and rva_entry[0] == name:
                        sig = rva_entry[1]
                        n_sigs_by_rva += 1
        # Attach compiland (source .obj basename) into the src field so
        # ghidra_import_gen surfaces it via the existing ``Source: ...``
        # plate-comment path -- no shared-code changes needed.
        cmp = compiland_index.get(rva, '')
        if cmp:
            src = f'{src} / {cmp}'
        # Structured-sig form: ghidra_import_gen applies via
        # FunctionDefinitionDataType (more reliable than the raw-sig path
        # which goes through CParserUtils.parseSignature).
        # 1) Prefer DIA-derived sig (authoritative param names + types).
        if sd is None and sd_from_dia is not None:
            try:
                d_sd = sd_from_dia(name, sig, _types_known, _enums_known, _typedefs)
                if d_sd is not None:
                    sd = d_sd
                    n_sd_from_dia += 1
                    n_sd_attached += 1
            except Exception:
                pass
        # 2) Fall back to parsing the raw sig text.
        if sd is None and sig and parse_sig is not None:
            try:
                parsed = parse_sig(sig, _types_known, _enums_known, _typedefs)
                if parsed is not None:
                    sd = parsed
                    n_sd_attached += 1
            except Exception:
                pass
        # 3) Annotate src with locals if DIA has them
        if annotate_comment is not None:
            try:
                anno = annotate_comment(name, sig_hint=sig)
                if anno:
                    src = f'{src} | {anno}'
                    n_locals_anno += 1
            except Exception:
                pass
        entry = {
            'n': name,
            't': 'label' if is_label else 'func',
            'sig': sig,
            'a': rva,
            'fnv': rva,
            'src': src,
        }
        if sd is not None:
            entry['sd'] = sd
        if not is_label and _verified_entry_source(source_kind):
            entry['verified_entry'] = True
        out.append(entry)
    for rva, (name, src) in label_addrs.items():
        if rva in by_addr:
            continue
        cmp = compiland_index.get(rva, '')
        if cmp:
            src = f'{src} / {cmp}'
        out.append({
            'n': name,
            't': 'label',
            'sig': '',
            'a': rva,
            'fnv': rva,
            'src': src,
        })
    if sig_index:
        print(f'  Attached PDB signatures: {n_sigs_by_name:,} by name + '
              f'{n_sigs_by_alias:,} by alias + '
              f'{n_sigs_by_rva:,} by RVA fallback '
              f'(of {len(by_addr):,} candidates)')
    if compiland_index:
        n_with_cmp = sum(1 for r in by_addr if r in compiland_index)
        print(f'  Attached compiland (.obj) tags to {n_with_cmp:,} symbols')
    if n_sd_attached:
        print(f'  Attached structured sigs: {n_sd_from_dia:,} via DIA + '
              f'{n_sd_attached - n_sd_from_dia:,} via raw-sig parse '
              f'(total {n_sd_attached:,})')
    if n_locals_anno:
        print(f'  Annotated {n_locals_anno:,} symbols with DIA param/local names')
    return out


if __name__ == '__main__':
    syms = build_fallback_symbols()
    n_func  = sum(1 for s in syms if s['t'] == 'func')
    n_label = sum(1 for s in syms if s['t'] == 'label')
    by_src: Dict[str, int] = {}
    for s in syms:
        by_src[s['src']] = by_src.get(s['src'], 0) + 1
    print(f'Total fallback symbols: {len(syms)}  (funcs {n_func}, labels {n_label})')
    for src, n in sorted(by_src.items(), key=lambda kv: -kv[1]):
        print(f'  {src:14s} {n:6d}')
