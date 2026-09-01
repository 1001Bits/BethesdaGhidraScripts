#!/usr/bin/env python3
"""Dump per-class vtable layouts from a CommonLib-imported Starfield project.

Walks ``VTABLE_<Class>`` symbols in the named Ghidra project, reads each
vtable's function-pointer entries inline, looks the slot targets up
against Ghidra's function manager, and emits a ``vtable_layout`` CSV that
``scripts/core/build_shift_map.py`` can diff against another version's
layout.

Vtable bounds are determined by sorting all ``VTABLE_*`` symbol addresses
within the same memory block and reading slots from each vtable's start
until the next vtable's start (or the end of the block).  This avoids
having to know slot counts ahead of time and stays robust against
multi-inheritance secondary vtables (``VTABLE_<Class>_<N>``) which are
treated as their own entries.

Fingerprint: first ``FP_BYTES`` bytes of each slot function, as
space-separated hex (no masking yet -- raw bytes are good enough for
SF intra-version-line matching since CommonLib applies the same names
across patches; masking can be added later if the matcher needs it).

Usage::

    python -m dump_vtable_layouts \\
        --project-dir C:/GhidraProjects/Starfield \\
        --project-name StarfieldProject \\
        --program Starfield.exe \\
        --label sf_1_16_236 \\
        --out scripts/commonlibsf/refs/sf_1-16-236-0_vtables.csv

When invoked with no args it auto-fills from the BGS pipeline
defaults (``ghidraprojects/BethesdaGhidraScripts/`` project, current
SF PE version detected from ``exes/starfield/sf/Starfield.exe``).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
SCRIPT_DIR  = Path(__file__).resolve().parent
CORE_DIR    = REPO_DIR / "scripts" / "core"

sys.path.insert(0, str(CORE_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

FP_BYTES = 32
_VERSIONLIB_RE = re.compile(
    r'^versionlib-(\d+)-(\d+)-(\d+)-(\d+)\.bin$', re.IGNORECASE)


def _parse_args():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  required=True, help='Ghidra project directory (e.g. C:/GhidraProjects/Starfield)')
    ap.add_argument('--project-name', required=True, help='Ghidra project name (e.g. StarfieldProject)')
    ap.add_argument('--program',      default='Starfield.exe', help='program filename inside the project')
    ap.add_argument('--label',        required=True, help='binary label embedded in CSV rows (e.g. sf_1_16_236)')
    ap.add_argument('--out',          required=True, help='output CSV path')
    ap.add_argument('--no-fingerprints', action='store_true',
                    help='skip per-slot function fingerprint extraction (faster, weaker cross-version matching)')
    ap.add_argument('--no-function-names', action='store_true',
                    help='omit analysis names (required for untrusted/non-anchor targets)')
    ap.add_argument('--expected-sha256', required=True,
                    help='refuse to dump unless Ghidra program SHA-256 matches')
    ap.add_argument('--versionlib', required=True,
                    help='exact SF versionlib used to enumerate VTABLE RVAs without prior names')
    return ap.parse_args()


def _find_program(project, program_name):
    """Walk the project tree for a program file matching ``program_name``.

    Falls back to a Steamless-unpacked variant when the exact name isn't
    found.  ``Starfield.exe`` may live in the BGS pipeline project as
    ``Starfield.unpacked.exe`` (or similar) when Steamless stripped DRM
    before import.  Without this fallback the caller silently fails to
    locate the binary and the vtable dump produces no output.
    """
    root = project.getProjectData().getRootFolder()
    stem = program_name.rsplit('.', 1)[0]
    candidates = (
        program_name,
        stem + '.unpacked.exe',
        stem + '_unpacked.exe',
        stem + '.unpacked',
        stem,
    )

    def walk(folder, predicate):
        for f in folder.getFiles():
            if predicate(f.getName()):
                return f
        for sub in folder.getFolders():
            r = walk(sub, predicate)
            if r is not None:
                return r
        return None

    # Exact match first
    for cand in candidates:
        f = walk(root, lambda n, c=cand: n == c)
        if f is not None:
            return f

    # Last-ditch prefix match -- any file under the project starting with
    # the stem and ending with ``.exe``.  Catches Steamless variants the
    # explicit list above missed.
    f = walk(root, lambda n: n.startswith(stem) and n.lower().endswith('.exe'))
    return f


def _find_program_by_sha256(project, expected_sha256, consumer, monitor):
    """Find exactly one program by persisted executable SHA-256."""
    matches = []
    root = project.getProjectData().getRootFolder()

    def walk(folder):
        for domain_file in folder.getFiles():
            obj = None
            try:
                obj = domain_file.getDomainObject(consumer, False, False, monitor)
                actual = (obj.getExecutableSHA256() or '').lower()
                if actual == expected_sha256.lower():
                    matches.append(domain_file)
            except Exception:
                pass
            finally:
                if obj is not None:
                    obj.release(consumer)
        for sub in folder.getFolders():
            walk(sub)

    walk(root)
    if len(matches) > 1:
        raise RuntimeError('multiple Ghidra programs share expected SHA-256: {}'.format(
            ', '.join(f.getPathname() for f in matches)))
    return matches[0] if matches else None


def _enumerate_vtables_via_rtti(program):
    """RTTI-walk fallback when no VTABLE_*/::vftable symbols exist.

    Reuses ``scan_rtti_vtables`` from ``run_vtable_pipeline``: parses MSVC
    RTTI structures directly from program memory and yields
    {vtable_va: class_name}.  Returns the same tuple shape as
    ``_enumerate_vtables`` so the caller is drop-in compatible.

    Used when neither CommonLib's ``VTABLE_<Class>`` flat labels nor
    Ghidra-RTTI's ``<Class>::vftable`` namespace symbols are present in
    the project -- e.g. the binary was imported but ``CommonLibImport_*.py``
    was never successfully applied, and the user only ran auto-analysis
    or our generic RTTI vtable pipeline (option 9, which renames vfunc
    targets but doesn't create vtable-address labels).
    """
    from run_vtable_pipeline import scan_msvc_rtti
    out = []
    records = scan_msvc_rtti(program).get('vtable_records', [])
    for record in sorted(records, key=lambda item: int(item['vtable_va'])):
        class_name = str(record.get('class_name') or '').strip()
        if not class_name:
            continue
        # CommonLib/Ghidra import names encode namespace separators as '__'
        # in flat vtable identifiers.  Preserve the complete qualified class
        # identity; taking only the leaf merges unrelated namespace peers.
        layout_key = class_name.replace('::', '__')
        vaddr = int(record['vtable_va'])
        subobject_offset = int(record.get('subobject_offset', 0))
        # Preserve the physical table identity emitted by the RTTI scanner.
        # Do not encode a secondary-table identity into ``class_name``: doing
        # that turns (Actor, offset 0x10) into a fictitious Actor__sub_10 class
        # and makes every row look primary when serialized.
        vtable_id = str(record.get('vtable_id') or
                        '{}@rva_{:X}:subobject_{:X}'.format(
                            class_name, int(record.get('vtable_rva', 0)),
                            subobject_offset))
        out.append((layout_key, vaddr, vtable_id, subobject_offset,
                    bool(record.get('is_primary', subobject_offset == 0)),
                    class_name + '::vftable'))
    return out


def _enumerate_vtables_from_versionlib(program, versionlib_path,
                                       expected_sha256):
    """Enumerate CommonLib's exact VTABLE identifiers without mutating Ghidra."""
    from address_library import AddressLibrary
    from ids_parser import parse_vtable_h

    match = _VERSIONLIB_RE.match(Path(versionlib_path).name)
    if not match:
        raise ValueError(
            'versionlib path must use versionlib-X-Y-Z-W.bin naming: {}'.format(
                versionlib_path))
    expected_version = tuple(int(component) for component in match.groups())
    db = AddressLibrary().load_bin(
        versionlib_path, expected_version=expected_version,
        expected_sha256=expected_sha256)
    if not db:
        return []
    holder = type('AddressLibraryView', (), {'sf_db': db})()
    labels = parse_vtable_h(str(REPO_DIR / 'extern' / 'CommonLibSF' /
                                'include' / 'RE'), holder)
    base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    raw = []
    seen = set()
    for item in labels:
        symbol = item['name']
        cls = item.get('vtable_class')
        if not cls:
            # Old/custom parsers lacking neutral class metadata cannot safely
            # distinguish generated array ordinals from genuine ``_<N>``
            # class names.
            continue
        va = base + int(item['sf_off'])
        if va in seen or not mem.contains(af.getAddress(va)):
            continue
        seen.add(va)
        # MSVC x64 stores a pointer to CompleteObjectLocator at vtable[-1].
        # COL.offset (+4) is the subobject displacement; offset 0 identifies
        # the primary table regardless of CommonLib array ordering.
        try:
            col_va = mem.getLong(af.getAddress(va - 8)) & 0xFFFFFFFFFFFFFFFF
            subobject_offset = mem.getInt(af.getAddress(col_va + 4)) & 0xFFFFFFFF
        except Exception:
            continue
        raw.append((cls, va, subobject_offset, symbol))

    out = []
    for cls, va, subobject_offset, symbol in raw:
        # RVA is part of the ID solely to distinguish duplicate COLs with the
        # same class/offset.  Cross-build matching uses class + physical
        # subobject offset, not this build-specific address component.
        vtable_id = '{}@rva_{:X}:subobject_{:X}'.format(
            cls, va - base, subobject_offset)
        out.append((cls, va, vtable_id, subobject_offset,
                    subobject_offset == 0, symbol))
    return out


def _version_from_versionlib(versionlib_path):
    match = _VERSIONLIB_RE.match(Path(versionlib_path).name)
    if not match:
        raise ValueError(
            'versionlib path must use versionlib-X-Y-Z-W.bin naming: {}'.format(
                versionlib_path))
    return tuple(int(component) for component in match.groups())


def _enumerate_vtables(program):
    """Return [(class_name, vtable_addr_int, primary_or_secondary_index, sym_name)].

    Recognizes two conventions:
      ``VTABLE_<Class>``        flat (CommonLib import script convention)
      ``VTABLE_<Class>_N``      flat secondary vtable (N=1,2,...)
      ``<Class>::vftable``      namespace-scoped (Ghidra RTTI analyzer)
      ``<Class>::vftable_N``    namespace-scoped secondary

    Classes named under both conventions are deduped by address, keeping
    the first encountered.  This matters: CommonLib import doesn't always
    create flat labels for classes Ghidra's RTTI already found.
    """
    sm = program.getSymbolTable()
    seen_addrs = {}
    out = []

    def _record(cls, idx, sym):
        addr_int = sym.getAddress().getOffset()
        if addr_int in seen_addrs:
            return
        seen_addrs[addr_int] = True
        out.append((cls, addr_int, idx, sym.getName(True)))

    for s in sm.getAllSymbols(True):
        n = s.getName()
        if n.startswith('VTABLE_'):
            rest = n[len('VTABLE_'):]
            idx = 0
            cls = rest
            if '_' in rest:
                head, _, tail = rest.rpartition('_')
                if tail.isdigit():
                    idx = int(tail)
                    cls = head
            _record(cls, idx, s)
            continue
        # Ghidra RTTI namespace-scoped: <Class>::vftable[_N]
        if n == 'vftable' or n.startswith('vftable_'):
            ns = s.getParentNamespace()
            if ns is None or ns.isGlobal():
                continue
            cls = ns.getName(True).replace('::', '__')
            idx = 0
            if n.startswith('vftable_'):
                tail = n[len('vftable_'):]
                if tail.isdigit():
                    idx = int(tail)
            _record(cls, idx, s)
            continue
    return out


def _vtable_terminator_map(program, vtable_entries):
    """Per-vtable upper bound for slot reads -- the containing memory
    block's end.  Slot validity, rather than a guessed fixed slot count,
    terminates each walk.

    Both prior heuristics were wrong on real Starfield projects:

      - Ghidra-applied struct length (``<Class>::vftable``) is often
        2 slots wide (Ghidra only records vfuncs it cross-referenced) ->
        truncates Actor/TESForm/PlayerCharacter to 2-3 slots.
      - Next ``VTABLE_*`` symbol address is also often only 16-24 bytes
        away because CommonLib/Ghidra place intra-vtable labels (multi-
        inheritance subobject markers) inside the same vtable -> same
        truncation.

    Rely on _read_slot_pointers' .text check instead: vfunc slots all
    point into .text, the next vtable's COL pointer sits in .rdata, so
    the slot check terminates cleanly at the real vtable boundary.
    """
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    end_by_addr = {}
    for entry in vtable_entries:
        vaddr = entry[1]
        block = mem.getBlock(af.getAddress(vaddr))
        if block is None:
            # A vtable must itself be mapped.  Returning its start makes the
            # reader emit no rows instead of wandering through an arbitrary
            # hard-coded address window.
            end_by_addr[vaddr] = vaddr
        else:
            end_by_addr[vaddr] = block.getEnd().getOffset() + 1
    return end_by_addr


def _read_slot_pointers(program, vaddr_int, end_addr_int):
    """Read 8-byte function pointers from vaddr until the block/slot terminator.

    Terminates on the first slot whose pointer:
      - is null
      - is outside the image (x64, image base 0x140000000)
      - points into NON-executable memory (not in .text)

    Earlier versions required Ghidra to already have a function defined
    at the slot target.  That under-reads catastrophically on projects
    where auto-analysis didn't create functions for every vfunc target
    yet (e.g. the RTTI-pipeline path with ~11k "create fail" targets):
    one missing function at slot 0 would discard the entire vtable, and
    major Bethesda classes ended up with 0 slots in the dump.  Checking
    only "lands in executable memory" lets over-read tails reach the
    next vtable's COL (which lives in .rdata, not .text) and stop
    cleanly, while preserving slots that are valid function pointers
    even if Ghidra hasn't analyzed them yet.

    No fixed slot cap is used.  Such a cap silently truncated real Actor,
    MenuActor, and PlayerCharacter tables at exactly 384 entries.  A mapped
    block end is finite, and the first non-executable pointer terminates at
    the next COL/vtable boundary.
    """
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    out = []
    cur = vaddr_int
    while cur + 8 <= end_addr_int:
        try:
            ptr = mem.getLong(af.getAddress(cur))
        except Exception:
            break
        if ptr == 0:
            break
        if ptr < 0x140000000 or ptr > 0x200000000:
            break
        ptr_addr = af.getAddress(ptr & 0xFFFFFFFFFFFFFFFF)
        block = mem.getBlock(ptr_addr)
        if block is None or not block.isExecute():
            break
        out.append(ptr & 0xFFFFFFFFFFFFFFFF)
        cur += 8
    return out


def _read_fingerprint(program, func_addr_int, n=FP_BYTES):
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    try:
        buf = bytearray(n)
        for i in range(n):
            buf[i] = mem.getByte(af.getAddress(func_addr_int + i)) & 0xFF
    except Exception:
        return ''
    return ' '.join('{:02X}'.format(b) for b in buf)


def _func_name_at(program, addr_int):
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    f = fm.getFunctionAt(af.getAddress(addr_int))
    if f is None:
        return ''
    # getName(True) includes namespace path (Class::method)
    return f.getName(True)


def main():
    args = _parse_args()
    target_version = _version_from_versionlib(args.versionlib)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    from vtable_layout import BinaryLayout, ClassVtable, SlotEntry, save_csv

    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        consumer = java.lang.Object()
        domain_file = _find_program_by_sha256(
            project, args.expected_sha256, consumer, monitor)
        if domain_file is None:
            print('ERROR: target program not found in project (name={}, sha256={})'.format(
                args.program, args.expected_sha256 or '<not supplied>'))
            sys.exit(2)
        print('Found program: {}'.format(domain_file.getPathname()))

        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            actual = ''
            try:
                actual = (program.getExecutableSHA256() or '').lower()
            except Exception:
                pass
            if not actual:
                # Older Ghidra releases may only persist the original
                # executable MD5.  Do not pretend that is enough to
                # validate a SHA-256-bound layout.
                print('ERROR: Ghidra program has no executable SHA-256 metadata;')
                print('       re-import it before producing a target-bound layout.')
                sys.exit(2)
            if actual != args.expected_sha256.lower():
                print('ERROR: stale/wrong Ghidra program: executable SHA-256')
                print('       program={} expected={}'.format(actual, args.expected_sha256.lower()))
                sys.exit(2)
            print('Enumerating vtables...')
            t0 = time.time()
            entries = _enumerate_vtables_from_versionlib(
                program, args.versionlib, actual)
            enumeration_method = 'versionlib/CommonLib VTABLE IDs'
            primary_classes = {cls for cls, _va, _identity, _offset,
                               is_primary, _sym in entries if is_primary}
            critical = {'Actor', 'TESForm', 'PlayerCharacter'}
            if len(entries) < 1000 or not critical.issubset(primary_classes):
                print('  exact versionlib has insufficient data/vtable IDs '
                      '({} entries); scanning MSVC RTTI.'.format(len(entries)))
                entries = _enumerate_vtables_via_rtti(program)
                enumeration_method = 'exact MSVC RTTI/COL scan'
                primary_classes = {
                    cls for cls, _va, _identity, _offset,
                    is_primary, _sym in entries if is_primary}
            print('  {}: {} vtables'.format(enumeration_method, len(entries)))
            print('  found {} labeled vtables ({:.1f}s)'.format(len(entries), time.time() - t0))
            if len(entries) < 1000 or not critical.issubset(primary_classes):
                print('ERROR: exact binary vtable enumeration failed coverage validation;')
                print('       entries={} missing critical={}'.format(
                    len(entries), sorted(critical - primary_classes)))
                sys.exit(1)

            print('Computing vtable bounds...')
            end_by_addr = _vtable_terminator_map(program, entries)

            print('Walking slots + naming functions...')
            layout = BinaryLayout(binary_label=args.label, binary_path=args.program)
            t0 = time.time()
            n_slots = 0
            for i, (cls, vaddr, vtable_id, subobject_offset,
                    is_primary, sym_name) in enumerate(entries):
                if i % 200 == 0 and i:
                    elapsed = time.time() - t0
                    pace = i / elapsed
                    remaining = (len(entries) - i) / pace
                    print('  {} / {} vtables ({:.0f}/s, ~{:.0f}s remaining)'.format(
                        i, len(entries), pace, remaining))
                end_addr = end_by_addr.get(vaddr, vaddr)
                slot_ptrs = _read_slot_pointers(program, vaddr, end_addr)
                if not slot_ptrs:
                    continue
                cv = layout.upsert(
                    cls, vaddr, vtable_id=vtable_id,
                    subobject_offset=subobject_offset,
                    is_primary=is_primary)
                for slot, fptr in enumerate(slot_ptrs):
                    name = ('' if args.no_function_names else
                            _func_name_at(program, fptr))
                    fp = '' if args.no_fingerprints else _read_fingerprint(program, fptr)
                    cv.add(SlotEntry(slot=slot, func_addr=fptr,
                                     func_name=name, fingerprint=fp))
                    n_slots += 1
            print('  done: {} vtables, {} slots ({:.1f}s)'.format(
                len(layout.vtables), n_slots, time.time() - t0))

            if n_slots < 10000 or len(layout.classes) < 1000:
                print('ERROR: vtable slot coverage is implausibly low '
                      '(classes={}, slots={}).'.format(
                          len(layout.classes), n_slots))
                sys.exit(1)
            rows = save_csv(layout, args.out)
            print('Wrote {} rows to {}'.format(rows, args.out))
            from sf_shift_manifest import write_layout_identity
            identity = write_layout_identity(
                args.out, target_version, actual,
                program_path=domain_file.getPathname(),
                versionlib_path=args.versionlib,
                enumeration_method=enumeration_method,
                function_names_included=not args.no_function_names,
                fingerprint_mode=('none' if args.no_fingerprints
                                  else 'raw-bytes-32'))
            print('Bound layout identity: {} (target {})'.format(
                str(args.out) + '.identity.json', identity['target_sha256']))
        finally:
            program.release(consumer)


if __name__ == '__main__':
    main()
