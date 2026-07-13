#!/usr/bin/env python3
"""Reconcile stale CommonLib-style vtable slot function names against the
current AST-derived slot layout.

Problem this solves
-------------------
``ghidra_import_gen.py``'s ``_import_vtable_names`` only renames functions
whose current name starts with ``FUN_`` / ``sub_`` / ``thunk_FUN_``.  Once
any other name is set, regenerating + re-applying the import script is a
no-op for that address.  That means if an *older* (buggy) emission applied
``X::method_A`` to a function but today's AST says that slot is actually
``X::method_B``, the stale label persists forever.

This reconciler is the opt-in cleanup: it walks every ``VTABLE_<Class>``
symbol in the target project, reads the function pointer at each slot,
and overwrites stale CommonLib-style labels (i.e. names of the form
``<SomeClass>::<method>`` where the leaf method doesn't match today's AST
expectation for that slot) with the correct name.  Plain ``FUN_``/``sub_``
placeholders are still handled by the main import pass -- the reconciler
ignores them.  Non-CommonLib-style names (e.g. ``Actor_FUN_140abc123``,
or any hand-typed name without ``::``) are left alone so the reconciler
doesn't clobber user labels.

Inputs
------
``--import-script`` points at a generated ``CommonLibImport_*.py``.  The
reconciler parses the ``VTABLES = [...]`` literal out of it -- no Ghidra
or clang needed for that pass.  Slot data is then applied via pyghidra
against the user's project.

Output
------
Prints a per-class reconciliation report:
  - ``reconciled``: name overwritten (was a stale CommonLib-style label)
  - ``ok``        : already matches AST expectation (no action)
  - ``unnamed``   : ``FUN_``/``sub_`` placeholder, deferred to main import
  - ``manual``    : non-CommonLib name (no ``::``), left alone
  - ``no_vtable`` : ``VTABLE_<Class>`` symbol not present in the binary
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

# Slot names the RTTI pass invents when it has no method name for a slot.
# They are machine output, never analyst work, so they stay reconcilable no
# matter which SourceType an older pipeline stamped on them.
_PLACEHOLDER_SLOT = re.compile(r'(?:Func|vfunc_?)\d+(?:_v\d+)?')


def _rename_slot(func, func_addr, program, target, expected_name, curr,
                 dry_run, class_short, SourceType):
    """Apply the bound CommonLib slot name, preserving the naming convention.

    A function already inside a class namespace keeps it (leaf rename); a flat
    function gets the flat ``Class::method`` form the CommonLib importer uses.
    """
    if dry_run:
        print('  DRY {} @ 0x{:X} : {!r} -> {!r}'.format(
            class_short, func_addr.getOffset(), curr, target))
        return
    try:
        namespace = func.getParentNamespace()
        in_class_ns = (namespace is not None and
                       not namespace.isGlobal())
        func.setName(expected_name if in_class_ns else target,
                     SourceType.IMPORTED)
        cu = program.getListing().getCodeUnitAt(func_addr)
        if cu:
            existing = cu.getComment(0) or ''
            note = 'Reconciled from stale name: ' + curr
            if note not in existing:
                cu.setComment(0, note + ('\n' + existing if existing else ''))
    except Exception as e:  # noqa: BLE001
        print('  WARN setName failed on 0x{:X}: {}'.format(
            func_addr.getOffset(), e))


def _extract_vtables_from_import_script(script_path: Path
                                         ) -> List[Tuple[str, str, int, str, List[Tuple[int, str]]]]:
    """Parse the ``VTABLES = [...]`` literal out of a generated import script.

    Returns list of (vname, class_full_name, vtbl_size, category, slots) tuples,
    where slots is [(slot_off, slot_name), ...].  The ret/params tuple entries
    in the original VTABLES emission are dropped -- the reconciler only cares
    about offset + name.
    """
    src = script_path.read_text(encoding='utf-8')
    # The emission is one line per tuple inside VTABLES = [...]; find the literal.
    # A robust parse: tokenize until we find "VTABLES = [", then balance brackets.
    needle = 'VTABLES = ['
    idx = src.find(needle)
    if idx < 0:
        raise ValueError('VTABLES literal not found in {}'.format(script_path))
    bracket_start = idx + len(needle) - 1
    depth = 0
    i = bracket_start
    in_str = None
    while i < len(src):
        ch = src[i]
        if in_str:
            if ch == '\\':
                i += 2; continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"'):
                in_str = ch
            elif ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    bracket_end = i
                    break
        i += 1
    else:
        raise ValueError('Unterminated VTABLES literal')
    literal = src[bracket_start:bracket_end + 1]
    parsed = ast.literal_eval(literal)
    out = []
    for vt in parsed:
        if len(vt) < 5:
            continue
        # Entries grew from 5 fields to 7 (..., vtable_kind, subobject_offset);
        # slice so both generations parse.
        vname, class_full_name, vtbl_size, category, slots = vt[:5]
        if len(vt) >= 6 and vt[5] != 'primary':
            continue
        compact_slots = [(s[0], s[1]) for s in slots if len(s) >= 2]
        out.append((vname, class_full_name, vtbl_size, category, compact_slots))
    return out


def _extract_target_manifests(script_path: Path) -> list:
    """Extract the JSON payload passed to TARGET_MANIFESTS in new importers."""
    src = script_path.read_text(encoding='utf-8')
    marker = 'TARGET_MANIFESTS = _json_target.loads('
    start = src.find(marker)
    if start < 0:
        return []
    start += len(marker)
    expr = src[start:]
    depth = 1
    quote = None
    escaped = False
    for i, ch in enumerate(expr):
        if quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in ('\'', '"'):
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                payload = ast.literal_eval(expr[:i].strip())
                value = json.loads(payload)
                return value if isinstance(value, list) else []
    return []


def _find_program(project, program_name):
    """Locate ``program_name`` in the project, with Steamless-variant fallbacks.

    Programs imported by ``run_headless.py`` may carry a Steamless-stripped
    name (``Starfield.unpacked.exe``) rather than the original
    (``Starfield.exe``); we try a few common variants and finally fall
    back to a prefix match against the stem.
    """
    project_data = project.getProjectData()
    requested_path = str(program_name).replace('\\', '/')
    if requested_path.startswith('/'):
        exact = project_data.getFile(requested_path)
        if exact is not None:
            return exact

    root = project_data.getRootFolder()
    program_name = requested_path.rsplit('/', 1)[-1]
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
            if predicate(f.getName()) or predicate(f.getPathname()):
                return f
        for sub in folder.getFolders():
            r = walk(sub, predicate)
            if r is not None:
                return r
        return None

    for cand in candidates:
        f = walk(root, lambda n, c=cand: n == c)
        if f is not None:
            return f

    return walk(root, lambda n: n.startswith(stem) and n.lower().endswith('.exe'))


_NOISE_PREFIXES = ('FUN_', 'sub_', 'thunk_FUN_', 'thunk_sub_')


def _is_noise(name: str) -> bool:
    return any(name.startswith(p) for p in _NOISE_PREFIXES)


def _vtbl_symbol(sym_table, class_short: str):
    """Find the VTABLE_<class_short> symbol.  Prefer flat name; fall back to
    a ``<class>::vftable`` namespace-scoped symbol if needed.
    """
    flat = list(sym_table.getSymbols('VTABLE_' + class_short))
    if len(flat) == 1:
        return flat[0]
    if len(flat) > 1:
        return None
    # Walk all symbols named 'vftable' and match parent namespace
    nameq = 'vftable'
    for s in sym_table.getSymbols(nameq):
        ns = s.getParentNamespace()
        if ns is None or ns.isGlobal():
            continue
        if ns.getName(True).replace('::', '__') == class_short:
            return s
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program', required=True, help='Program filename in the project')
    ap.add_argument('--import-script', required=True, help='Generated CommonLibImport_*.py to read VTABLES from')
    ap.add_argument('--dry-run', action='store_true',
                    help='Report what would change without writing')
    args = ap.parse_args()

    import_script = Path(args.import_script).resolve()
    if not import_script.is_file():
        print('ERROR: import script not found: {}'.format(import_script))
        sys.exit(1)

    print('Parsing VTABLES from {} ...'.format(import_script))
    vtables = _extract_vtables_from_import_script(import_script)
    print('  parsed {} vtable entries'.format(len(vtables)))
    if not vtables:
        print('Reconciliation not applicable: importer has no VTABLES entries.')
        return
    target_manifests = _extract_target_manifests(import_script)
    if not target_manifests:
        print('ERROR: importer has no exact TARGET_MANIFESTS binding')
        sys.exit(1)

    # Build per-class expectation: slot_off -> expected_name, plus the set
    # of all method names in this class's slots (used to detect stale CommonLib
    # labels: a name like "<class>::DoFailedToLoadGraph" at the wrong slot
    # belongs to this class but at a different slot).
    expectations: Dict[str, Dict[int, str]] = {}
    class_method_set: Dict[str, set] = {}
    for vname, class_full_name, vtbl_size, category, slots in vtables:
        class_short = class_full_name.split('::')[-1]
        slot_map = dict(slots)
        expectations[class_short] = slot_map
        class_method_set[class_short] = {n for n in slot_map.values()}

    os.environ.setdefault('GHIDRA_INSTALL_DIR', str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        domain_file = _find_program(project, args.program)
        if domain_file is None:
            print('ERROR: program {} not found in project'.format(args.program))
            sys.exit(1)
        print('Found program: {}'.format(domain_file.getPathname()))

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, not args.dry_run, False, monitor)
        try:
            try:
                from binary_identity import verify_ghidra_program
                verify_ghidra_program(program, target_manifests)
            except Exception as e:
                print('ERROR: unable to verify program identity: {}'.format(e))
                sys.exit(1)

            sym_table = program.getSymbolTable()
            fm = program.getFunctionManager()
            mem = program.getMemory()
            af = program.getAddressFactory().getDefaultAddressSpace()
            ptr_size = program.getDefaultPointerSize()

            def read_func_addr(vaddr, slot_off):
                slot_addr = af.getAddress(vaddr + (slot_off // 8) * ptr_size)
                raw = (mem.getLong(slot_addr) & 0xFFFFFFFFFFFFFFFF
                       if ptr_size == 8 else mem.getInt(slot_addr) & 0xFFFFFFFF)
                addr = af.getAddress(raw)
                block = mem.getBlock(addr)
                if block is None or not block.isInitialized() or not block.isExecute():
                    return None
                return addr

            # Determine all proposed owners up front so a shared base/ICF body
            # is never renamed repeatedly according to traversal order.
            claims = {}
            for class_short, slot_map in expectations.items():
                vsym = _vtbl_symbol(sym_table, class_short)
                if vsym is None:
                    continue
                vaddr = vsym.getAddress().getOffset()
                for slot_off, expected_name in slot_map.items():
                    if expected_name.startswith('fn_'):
                        continue
                    try:
                        faddr = read_func_addr(vaddr, slot_off)
                    except Exception:
                        continue
                    if faddr is not None:
                        claims.setdefault(faddr.getOffset(), set()).add(
                            class_short + '::' + expected_name)

            totals = {'reconciled': 0, 'ok': 0, 'unnamed': 0, 'manual': 0,
                      'no_vtable': 0, 'no_func': 0, 'read_fail': 0}

            tx = program.startTransaction('Vtable name reconciler') if not args.dry_run else None
            commit = False
            try:
                for class_short, slot_map in expectations.items():
                    vsym = _vtbl_symbol(sym_table, class_short)
                    if vsym is None:
                        totals['no_vtable'] += 1
                        continue
                    vaddr = vsym.getAddress().getOffset()
                    class_methods = class_method_set[class_short]
                    for slot_off, expected_name in slot_map.items():
                        if expected_name.startswith('fn_'):
                            continue  # placeholder; nothing to reconcile against
                        try:
                            func_addr = read_func_addr(vaddr, slot_off)
                        except Exception:
                            totals['read_fail'] += 1
                            continue
                        if func_addr is None:
                            totals['read_fail'] += 1
                            continue
                        func = fm.getFunctionAt(func_addr)
                        if func is None:
                            totals['no_func'] += 1
                            continue
                        leaf_curr = func.getName()
                        # The RTTI pass names slots as namespace Class + leaf
                        # FuncN, so the flat name alone hides the class.  Use
                        # the namespaced name for the staleness analysis.
                        curr = func.getName(True)
                        target = class_short + '::' + expected_name
                        if len(claims.get(func_addr.getOffset(), ())) != 1:
                            totals['manual'] += 1
                            continue
                        if curr == target or leaf_curr == expected_name:
                            totals['ok'] += 1
                            continue
                        if _is_noise(curr) or _is_noise(leaf_curr):
                            totals['unnamed'] += 1
                            continue
                        # Machine-generated slot placeholders (FuncN, FuncN_vM,
                        # vfunc_N) are never hand-authored, whatever source
                        # type an older pipeline stamped on them -- upgrade
                        # them to the bound CommonLib method name.
                        if _PLACEHOLDER_SLOT.fullmatch(leaf_curr):
                            _rename_slot(func, func_addr, program, target,
                                         expected_name, curr, args.dry_run,
                                         class_short, SourceType)
                            totals['reconciled'] += 1
                            continue
                        # Only reconcile names of the form '<x>::<leaf>' where
                        # the leaf is one of THIS class's expected method names
                        # but at a different slot, OR the prefix matches THIS
                        # class.  Both are signs of a stale CommonLib emission;
                        # other ``<x>::<y>`` names are likely from a base class
                        # legitimately and we leave them alone.
                        if '::' not in curr:
                            totals['manual'] += 1
                            continue
                        prefix, _, leaf = curr.rpartition('::')
                        leaf_root = leaf.split('(')[0].split('[')[0]
                        is_this_class_prefix = (prefix.split('::')[-1] == class_short)
                        leaf_is_this_classes_method = leaf_root in class_methods
                        if not (is_this_class_prefix or leaf_is_this_classes_method):
                            totals['manual'] += 1
                            continue
                        # Stale CommonLib name: overwrite.
                        _rename_slot(func, func_addr, program, target,
                                     expected_name, curr, args.dry_run,
                                     class_short, SourceType)
                        totals['reconciled'] += 1
                commit = True
            finally:
                if tx is not None:
                    program.endTransaction(tx, commit)
                if not args.dry_run and commit:
                    program.save('Vtable name reconciler', monitor)

            print()
            print('=== Reconciler summary ===')
            for k in ('reconciled', 'ok', 'unnamed', 'manual', 'no_vtable', 'no_func', 'read_fail'):
                print('  {:<12} {}'.format(k, totals[k]))
            if args.dry_run:
                print('(dry-run: no changes written)')
            else:
                print('(changes saved)')
        finally:
            program.release(consumer)


if __name__ == '__main__':
    main()
