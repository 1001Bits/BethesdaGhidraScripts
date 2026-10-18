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
  - ``failed``    : rename threw and the name could not be put in effect; the
                    slot still carries its stale name.  Never folded into
                    ``reconciled`` -- a miscount here would claim the binary was
                    corrected when it was not.
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
from ghidra_project import open_program, open_user_project

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

# Slot names the RTTI pass invents when it has no method name for a slot.
# They are machine output, never analyst work, so they stay reconcilable no
# matter which SourceType an older pipeline stamped on them.
_PLACEHOLDER_SLOT = re.compile(r'(?:Func|vfunc_?)\d+(?:_v\d+)?')


def _promote_existing_symbol(program, func_addr, wanted):
    """Make an already-present symbol of *wanted* name the primary one.

    Ghidra refuses ``setName`` when a symbol of that name already sits at the
    address -- typically a label the CommonLib import pass put there.  The name
    is then *present but not in effect*: the function's primary name is still
    the stale one, so the slot reads wrong everywhere it matters (decompiler,
    call graph, exports).  Promoting the existing symbol is the rename.

    Returns True when the address ends up primarily named *wanted*.
    ``Symbol.setPrimary()`` only applies to NON-function symbols: at a function
    entry the function symbol stays primary and the call returns False, so the
    result is read back instead of assumed.
    """
    for symbol in program.getSymbolTable().getSymbols(func_addr):
        if str(symbol.getName()) == wanted or str(symbol.getName(True)) == wanted:
            if symbol.isPrimary():
                return True
            symbol.setPrimary()
            return bool(symbol.isPrimary())
    return False


def _carries_name(func, wanted):
    """Is *wanted* the name actually in effect on the function?"""
    try:
        return (str(func.getName()) == wanted or
                str(func.getName(True)) == wanted)
    except Exception:  # noqa: BLE001
        return False


def _is_user_defined(symbol, SourceType):
    try:
        return symbol is not None and symbol.getSource() == SourceType.USER_DEFINED
    except Exception:  # noqa: BLE001
        return False


def is_analyst_name(func, leaf_name, SourceType):
    """A USER_DEFINED function name that is not a machine placeholder is an
    analyst's work: the reconciler must never overwrite it."""
    if _PLACEHOLDER_SLOT.fullmatch(str(leaf_name)):
        return False
    return _is_user_defined(func.getSymbol(), SourceType)


def _replace_duplicate_label(program, func, func_addr, wanted, SourceType):
    """The wanted name sits at the entry as a secondary LABEL, which blocks
    ``setName`` and cannot be promoted over a function symbol.  Drop that
    label (never an analyst's USER_DEFINED one) and rename the function."""
    for symbol in list(program.getSymbolTable().getSymbols(func_addr)):
        if symbol.isPrimary():
            continue
        if not (str(symbol.getName()) == wanted or
                str(symbol.getName(True)) == wanted):
            continue
        if _is_user_defined(symbol, SourceType):
            return False
        if not symbol.delete():
            return False
        func.setName(wanted, SourceType.IMPORTED)
        return True
    return False


def _rename_slot(func, func_addr, program, target, expected_name, curr,
                 dry_run, class_short, SourceType):
    """Apply the bound CommonLib slot name, preserving the naming convention.

    A function already inside a class namespace keeps it (leaf rename); a flat
    function gets the flat ``Class::method`` form the CommonLib importer uses.

    Returns True when the slot now carries the bound name.  A rename that threw
    must never be counted as reconciled -- the whole point of this pass is that
    the name in the binary is the one the bound importer says it should be.
    """
    if dry_run:
        print('  DRY {} @ 0x{:X} : {!r} -> {!r}'.format(
            class_short, func_addr.getOffset(), curr, target))
        return True

    namespace = func.getParentNamespace()
    in_class_ns = (namespace is not None and not namespace.isGlobal())
    wanted = expected_name if in_class_ns else target

    try:
        func.setName(wanted, SourceType.IMPORTED)
    except Exception as exc:  # noqa: BLE001
        # Almost always DuplicateNameException: the wanted name is already at
        # this address as a non-primary symbol.  Promote it instead of leaving
        # the function under its stale name.
        try:
            promoted = _promote_existing_symbol(program, func_addr, wanted)
            if not (promoted and _carries_name(func, wanted)):
                _replace_duplicate_label(
                    program, func, func_addr, wanted, SourceType)
            if not _carries_name(func, wanted):
                print('  WARN setName failed on 0x{:X}: {}'.format(
                    func_addr.getOffset(), exc))
                return False
        except Exception as promote_exc:  # noqa: BLE001
            print('  WARN setName failed on 0x{:X}: {} '
                  '(and promoting the existing symbol failed: {})'.format(
                      func_addr.getOffset(), exc, promote_exc))
            return False

    if not _carries_name(func, wanted):
        # Whatever happened above, the function does not carry the bound name.
        print('  WARN 0x{:X} is still named {!r}, not {!r}'.format(
            func_addr.getOffset(), str(func.getName(True)), wanted))
        return False

    cu = program.getListing().getCodeUnitAt(func_addr)
    if cu:
        existing = cu.getComment(0) or ''
        note = 'Reconciled from stale name: ' + curr
        if note not in existing:
            cu.setComment(0, note + ('\n' + existing if existing else ''))
    return True


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


def split_qualified(name: str) -> List[str]:
    """Split a C++ qualified name at TOP-LEVEL ``::`` only.

    ``RE::BSTHashMap<RE::BSFixedString, RE::Foo::Bar>`` is one class, not
    ``...Bar>``: separators inside ``<>``/``()``/``[]`` belong to the
    template/parameter list and are never a scope boundary.
    """
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(name):
        ch = name[i]
        if ch in '<([':
            depth += 1
        elif ch in '>)]':
            depth = max(0, depth - 1)
        elif depth == 0 and name.startswith('::', i):
            parts.append(name[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(name[start:])
    return parts


def short_class_name(class_full_name: str) -> str:
    """The leaf class name (template-aware), e.g. ``RE::A::Entry`` -> ``Entry``."""
    return split_qualified(class_full_name)[-1]


def build_expectations(vtables):
    """Slot expectations keyed by FULL qualified class name.

    Returns ``(expectations, ambiguous)``: ``expectations`` maps a full class
    name to ``(class_short, {slot_off: method})``; ``ambiguous`` maps a short
    name to the full names that share it.  The binary only carries
    ``VTABLE_<short>`` labels, so a short name claimed by two classes (two
    ``Entry`` classes in different namespaces) -- or one class listed twice
    with different slots -- gets NO expectation: last-writer-wins used to put
    one class's IMPORTED slot names on the other class's table.
    """
    by_full: Dict[str, Dict[int, str]] = {}
    conflicting = set()
    for _vname, class_full_name, _size, _category, slots in vtables:
        slot_map = dict(slots)
        previous = by_full.get(class_full_name)
        if previous is not None and previous != slot_map:
            conflicting.add(class_full_name)
        by_full[class_full_name] = slot_map
    by_short: Dict[str, set] = {}
    for full in by_full:
        by_short.setdefault(short_class_name(full), set()).add(full)
    expectations = {}
    ambiguous = {}
    for short, fulls in by_short.items():
        if len(fulls) != 1 or fulls & conflicting:
            ambiguous[short] = sorted(fulls)
            continue
        full = next(iter(fulls))
        expectations[full] = (short, by_full[full])
    return expectations, ambiguous


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

    # Build per-class expectation (keyed by FULL class name): slot_off ->
    # expected_name, plus the set of all method names in this class's slots
    # (used to detect stale CommonLib labels: a name like
    # "<class>::DoFailedToLoadGraph" at the wrong slot belongs to this class
    # but at a different slot).  Short names shared by several classes are
    # dropped: the binary's VTABLE_<short> label cannot say which one it is.
    expectations, ambiguous = build_expectations(vtables)
    class_method_set: Dict[str, set] = {
        full: set(slot_map.values())
        for full, (_short, slot_map) in expectations.items()}
    if ambiguous:
        print('  {} short class name(s) shared by several classes; no '
              'expectation for them (e.g. {})'.format(
                  len(ambiguous), ', '.join(sorted(ambiguous)[:5])))

    os.environ.setdefault('GHIDRA_INSTALL_DIR', str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    with open_user_project(args.project_dir, args.project_name) as project:
        domain_file = _find_program(project, args.program)
        if domain_file is None:
            print('ERROR: program {} not found in project'.format(args.program))
            sys.exit(1)
        print('Found program: {}'.format(domain_file.getPathname()))

        consumer = java.lang.Object()
        program = open_program(domain_file, consumer, monitor, write=not args.dry_run)
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
            for class_short, slot_map in expectations.values():
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

            totals = {'reconciled': 0, 'failed': 0, 'ok': 0, 'unnamed': 0,
                      'manual': 0, 'no_vtable': 0, 'no_func': 0, 'read_fail': 0}

            tx = program.startTransaction('Vtable name reconciler') if not args.dry_run else None
            commit = False
            try:
                for class_full, (class_short, slot_map) in expectations.items():
                    vsym = _vtbl_symbol(sym_table, class_short)
                    if vsym is None:
                        totals['no_vtable'] += 1
                        continue
                    vaddr = vsym.getAddress().getOffset()
                    class_methods = class_method_set[class_full]
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
                            renamed = _rename_slot(
                                func, func_addr, program, target,
                                expected_name, curr, args.dry_run,
                                class_short, SourceType)
                            totals['reconciled' if renamed else 'failed'] += 1
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
                        curr_parts = split_qualified(curr)
                        prefix = '::'.join(curr_parts[:-1])
                        leaf = curr_parts[-1]
                        leaf_root = leaf.split('(')[0].split('[')[0]
                        is_this_class_prefix = bool(prefix) and (
                            split_qualified(prefix)[-1] == class_short)
                        leaf_is_this_classes_method = leaf_root in class_methods
                        if not (is_this_class_prefix or leaf_is_this_classes_method):
                            totals['manual'] += 1
                            continue
                        if is_analyst_name(func, leaf_curr, SourceType):
                            # Looks stale, but a person typed it: keep it.
                            totals['manual'] += 1
                            continue
                        # Stale CommonLib name: overwrite.
                        renamed = _rename_slot(
                            func, func_addr, program, target,
                            expected_name, curr, args.dry_run,
                            class_short, SourceType)
                        totals['reconciled' if renamed else 'failed'] += 1
                commit = True
            finally:
                committed = False
                if tx is not None:
                    committed = bool(program.endTransaction(tx, commit))
                if not args.dry_run and commit:
                    if not committed:
                        # A rolled-back transaction must not be saved and
                        # reported as "changes saved".
                        raise RuntimeError(
                            'reconciler transaction did not commit; '
                            'nothing was saved')
                    program.save('Vtable name reconciler', monitor)

            print()
            print('=== Reconciler summary ===')
            for k in ('reconciled', 'failed', 'ok', 'unnamed', 'manual',
                      'no_vtable', 'no_func', 'read_fail'):
                print('  {:<12} {}'.format(k, totals[k]))
            if totals['failed']:
                print('  ({} slot(s) still carry a stale name -- see the WARNs '
                      'above)'.format(totals['failed']))
            if args.dry_run:
                print('(dry-run: no changes written)')
            else:
                print('(changes saved)')
        finally:
            program.release(consumer)


if __name__ == '__main__':
    main()
