"""Ghidra driver: type + name high-confidence global singletons from a
globals_harvest review queue.  Technique adapted from alandtse's
CommonLibVR fork (the apply half of the globals review pattern).

Reads a ``globals_queue_<prog>.csv`` produced by globals_harvest and,
for each row meeting the confidence bar, sets the global's data type to
the inferred class (or a pointer to it) and renames the ``DAT_*`` slot
to a readable singleton name.  A typed global lets the decompiler
propagate field accesses through it -- the downstream payoff that makes
the next discovery pass resolve one level deeper.

DEFAULT IS DRY-RUN.  Set BGS_ENRICH_APPLY=go to write.  Only rows whose
``decision_type`` column is blank are auto-decided by confidence; a
reviewer can hard-override a row by filling ``decision_type`` (that
value wins, or ``skip`` excludes the row).

Knobs (env):
  BGS_ENRICH_APPLY=go        actually type/name (default dry-run)
  BGS_GLOBALS_APPLY_CSV      input queue CSV (default: refs/globals_queue_<prog>.csv)
  BGS_GLOBALS_MIN_CONF       min confidence to auto-apply: high|medium (default high)
"""
import csv
import os
import sys

from evidence_identity import EvidenceIdentityError, validate_evidence

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
MIN_CONF = os.environ.get('BGS_GLOBALS_MIN_CONF', 'high').lower()
_CONF_RANK = {'high': 2, 'medium': 1, 'low': 0}


def _resolve_struct(dtm, name):
    """Resolve an exact/unique StructureDB; never pick a colliding leaf."""
    matches = []
    for dt in dtm.getAllDataTypes():
        if (dt.getClass().getSimpleName() == 'StructureDB'
                and (dt.getName() == name or str(dt.getPathName()) == name)):
            matches.append(dt)
    unique = {str(dt.getPathName()): dt for dt in matches}
    return next(iter(unique.values())) if len(unique) == 1 else None


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    from binary_identity import inspect_pe, verify_ghidra_program
    backing_manifest = inspect_pe(str(cp.getExecutablePath()))
    verify_ghidra_program(cp, [backing_manifest])
    dtm = cp.getDataTypeManager()
    listing = cp.getListing()
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    image_base = int(backing_manifest['image_base'])

    def is_manifest_data_va(value, size):
        rva = int(value) - image_base
        if rva < 0 or rva + size > int(backing_manifest['image_size']):
            return False
        for section in backing_manifest.get('sections', []):
            start = int(section.get('rva', 0))
            span = max(int(section.get('virtual_size', 0)),
                       int(section.get('raw_size', 0)))
            if (start <= rva and rva + size <= start + span and
                    not section.get('executable')):
                return True
        return False

    in_csv = os.environ.get('BGS_GLOBALS_APPLY_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'globals_queue_%s.csv' % cp.getName().replace('.', '_'))
    if not os.path.isfile(in_csv):
        print('globals-apply: no queue CSV at ' + in_csv)
        return
    try:
        binding = validate_evidence(
            in_csv, cp, 'globals_decisions', require_content=True)
        if binding.get('address_coordinate') != 'VA':
            raise EvidenceIdentityError(
                'global_addr evidence must use VA coordinates')
    except EvidenceIdentityError as exc:
        print('globals-apply: refusing stale/unbound queue: %s' % exc)
        return

    rows = list(csv.DictReader(open(in_csv, newline='')))
    typed = renamed = skipped = missing = 0
    had_parent_transaction = (
        APPLY and cp.getCurrentTransactionInfo() is not None)
    tx = cp.startTransaction('globals-apply') if APPLY else None
    commit = False
    try:
        for r in rows:
            decision = (r.get('decision_type') or '').strip()
            conf = (r.get('confidence') or '').strip().lower()
            cls = r.get('inferred_type', '').strip()
            if decision.lower() == 'skip':
                skipped += 1
                continue
            # decision_type hard-override wins; else gate on confidence.
            if decision:
                cls = decision
            elif _CONF_RANK.get(conf, 0) < _CONF_RANK.get(MIN_CONF, 2):
                skipped += 1
                continue
            try:
                raw_va = int(r['global_addr'], 16)
                addr = af.getAddress(raw_va)
            except (ValueError, KeyError):
                continue
            pointer_size = cp.getDefaultPointerSize()
            if not is_manifest_data_va(raw_va, pointer_size):
                skipped += 1
                continue
            block = cp.getMemory().getBlock(addr)
            if block is None or not block.isInitialized() or block.isExecute():
                skipped += 1
                continue
            struct = _resolve_struct(dtm, cls)
            if struct is None:
                missing += 1
                continue
            # ALWAYS type as a pointer (Class*) at the program's ABI width. Typing
            # the slot as the full inline struct is unreliable: large
            # structs fail to create (clear rejected) or truncate to a few
            # bytes, and a wrong inline/pointer guess would over-clear
            # adjacent globals.  Class* is one pointer wide (no over-clear, no
            # truncation), correct for the common pointer-slot singleton,
            # and still lets the decompiler propagate one deref deeper.
            dt = dtm.getPointer(struct, pointer_size)

            # Decide whether to (re)type this slot:
            #  - undefined / no data        -> type as Class*
            #  - already a pointer (Class*) -> done, skip
            #  - any concrete type/instruction -> preserve it.  Even a bare
            #    same-class struct may be analyst work; migrations must not
            #    infer permission to clear it.
            conflict = False
            for delta in range(pointer_size):
                location = addr.add(delta)
                if listing.getInstructionContaining(location) is not None:
                    conflict = True
                    break
                existing = listing.getDefinedDataContaining(location)
                if (existing is not None and not
                        existing.getDataType().getName().startswith(
                            'undefined')):
                    conflict = True
                    break
            if conflict:
                skipped += 1
                continue

            if not APPLY:
                typed += 1
                renamed += 1
                continue
            listing.clearCodeUnits(addr, addr.add(pointer_size - 1), False)
            if listing.createData(addr, dt) is None:
                raise RuntimeError(
                    'globals-apply failed to create pointer data')
            typed += 1
            # Name the slot g_<Class> when it's a DAT_/g_ placeholder.
            sym = st.getPrimarySymbol(addr)
            if sym is None:
                st.createLabel(addr, 'g_' + cls, SourceType.ANALYSIS)
                renamed += 1
            elif (sym.getSource() == SourceType.DEFAULT and
                  sym.getName().startswith(('DAT_', 'g_'))):
                sym.setName('g_' + cls, SourceType.ANALYSIS)
                renamed += 1
        commit = True
    finally:
        if tx is not None:
            committed = bool(cp.endTransaction(tx, commit))
            if commit and not had_parent_transaction and not committed:
                raise RuntimeError('globals-apply transaction did not commit')

    print('globals-apply (%s): %s  min-conf=%s'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', MIN_CONF))
    print('  %s=%d  %s=%d  skipped(low-conf)=%d  struct-not-found=%d'
          % ('typed' if APPLY else 'would-type', typed,
             'named' if APPLY else 'would-name', renamed, skipped, missing))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


if 'currentProgram' in globals():
    run()
