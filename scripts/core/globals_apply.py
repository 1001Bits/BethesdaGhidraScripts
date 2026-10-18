"""Ghidra driver: type + name high-confidence global singletons from a
globals_harvest review queue.  Technique adapted from alandtse's
CommonLibVR fork (the apply half of the globals review pattern).

Reads a ``globals_evidence_<folder>_<prog>.csv`` produced by globals_harvest and,
for each row meeting the confidence bar, sets the global's data type to
the inferred class (or a pointer to it) and renames the ``DAT_*`` slot
to a readable singleton name.  A typed global lets the decompiler
propagate field accesses through it -- the downstream payoff that makes
the next discovery pass resolve one level deeper.

DEFAULT IS DRY-RUN.  Set BGS_ENRICH_APPLY=go to write.  Only rows whose
``decision_type`` column is blank are auto-decided by confidence; a
reviewer can hard-override a row by filling ``decision_type`` in the
DECISIONS csv (that value wins, or ``skip`` excludes the row).  The mined
EVIDENCE csv is content-bound and must not be edited.

When applying, missing/stale/unbound evidence or a missing decisions file
RAISES (the launcher reports FAIL and rolls back); a dry-run prints a
``REFUSED:`` line instead.

Knobs (env):
  BGS_ENRICH_APPLY=go        actually type/name (default dry-run)
  BGS_GLOBALS_CSV            mined evidence (default: refs/globals_evidence_<folder>_<prog>.csv)
  BGS_GLOBALS_APPLY_CSV      reviewer decisions (default: refs/globals_decisions_<folder>_<prog>.csv;
                             written by the launchers after globals_harvest)
  BGS_GLOBALS_MIN_CONF       min confidence to auto-apply: high|medium (default high)
  BGS_TARGET_PE              launcher-verified backing executable
"""
import os

from review_queue import (GLOBALS, ReviewQueueError, load_reviewed_rows,
                          queue_paths)

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


def inline_struct_width(struct):
    """Bytes an inline ``struct`` occupies; 0 when it cannot be laid down
    (a not-yet-defined / zero-length placeholder struct)."""
    for flag in ('isNotYetDefined', 'isZeroLength'):
        test = getattr(struct, flag, None)
        if test is not None and test():
            return 0
    return max(int(struct.getLength()), 0)


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    from target_pe import driver_target_manifest
    # BGS_TARGET_PE (launcher-verified) or the recorded import path; either
    # way the file is identity-verified against the Program here.
    backing_manifest = driver_target_manifest(cp)
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

    def span_fits(raw_va, addr, width, block):
        """[addr, addr+width) is backing-PE data inside ONE loaded block."""
        if not is_manifest_data_va(raw_va, width):
            return False
        try:
            return bool(block.contains(addr.add(width - 1)))
        except Exception:  # noqa: BLE001  (AddressOutOfBoundsException)
            return False

    def span_conflict(addr, width):
        """Any instruction or concrete (non-undefined) data in the span?"""
        for delta in range(width):
            location = addr.add(delta)
            if listing.getInstructionContaining(location) is not None:
                return True
            existing = listing.getDefinedDataContaining(location)
            if (existing is not None and not
                    existing.getDataType().getName().startswith('undefined')):
                return True
        return False

    def named_inside(addr, width):
        """A non-default symbol strictly inside the span -- another named
        global an inline struct would swallow?"""
        if width <= 1:
            return False
        end = addr.add(width - 1)
        symbols = st.getSymbolIterator(addr.add(1), True)
        while symbols.hasNext():
            symbol = symbols.next()
            if symbol.getAddress().compareTo(end) > 0:
                return False
            if symbol.getSource() != SourceType.DEFAULT:
                return True
        return False

    # Rows come from the content-bound EVIDENCE globals_harvest wrote; only the
    # ``decision_type`` column is taken from the reviewer-editable DECISIONS
    # file (identity-bound, not content-bound).  See review_queue.py.
    evidence_csv, decisions_csv = queue_paths(GLOBALS, cp)
    try:
        rows, n_decisions = load_reviewed_rows(
            evidence_csv, decisions_csv, cp, GLOBALS)
    except ReviewQueueError as exc:
        if APPLY:
            # A refusal while applying is a FAILURE: raising reaches the
            # launcher as stderr, so it rolls back and reports FAIL.
            raise
        print('globals-apply: REFUSED: %s' % exc)
        return
    print('globals-apply: %d evidence rows from %s, %d reviewer decision(s) '
          'from %s' % (len(rows), evidence_csv, n_decisions, decisions_csv))
    typed = renamed = skipped = missing = inline = 0
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
            is_inline = (r.get('is_pointer') or '1').strip() == '0'
            if is_inline and not decision:
                # An INLINE singleton (the address is the object itself) must
                # not get ``Class *`` laid over its vtable pointer.  A reviewer
                # decision is required to type it.
                inline += 1
                continue
            if is_inline:
                # Reviewer-approved INLINE singleton: the address IS the
                # object, so it gets the struct itself -- never ``Class *``
                # over its vtable.  It must fit entirely in data the backing
                # PE and the program agree on, or the row is skipped.
                dt = struct
                width = inline_struct_width(struct)
            else:
                # A pointer slot: ``Class *`` at the program's ABI width (one
                # pointer wide: no over-clear, no truncation), which still
                # lets the decompiler propagate one deref deeper.
                dt = dtm.getPointer(struct, pointer_size)
                width = pointer_size
            if width <= 0 or not span_fits(raw_va, addr, width, block):
                skipped += 1
                continue

            # Decide whether to (re)type this slot:
            #  - undefined / no data        -> type as Class* / Class
            #  - already a pointer (Class*) -> done, skip
            #  - any concrete type/instruction -> preserve it.  Even a bare
            #    same-class struct may be analyst work; migrations must not
            #    infer permission to clear it.
            if span_conflict(addr, width) or (
                    is_inline and named_inside(addr, width)):
                skipped += 1
                continue

            # Decide naming BEFORE typing: once the slot is a pointer its
            # default symbol reads ``PTR_...`` and no name test would match.
            sym = st.getPrimarySymbol(addr)
            placeholder = sym is None or sym.getSource() == SourceType.DEFAULT
            if not APPLY:
                typed += 1
                renamed += 1 if placeholder else 0
                continue
            listing.clearCodeUnits(addr, addr.add(width - 1), False)
            if listing.createData(addr, dt) is None:
                raise RuntimeError(
                    'globals-apply failed to create %s data at %s'
                    % ('inline struct' if is_inline else 'pointer', addr))
            typed += 1
            # Name the slot g_<Class> only when it carried no real name.
            if placeholder:
                st.createLabel(addr, 'g_' + cls, SourceType.ANALYSIS)
                renamed += 1
        commit = True
    finally:
        if tx is not None:
            committed = bool(cp.endTransaction(tx, commit))
            if commit and not had_parent_transaction and not committed:
                raise RuntimeError('globals-apply transaction did not commit')

    print('globals-apply (%s): %s  min-conf=%s'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', MIN_CONF))
    print('  %s=%d  %s=%d  skipped=%d  inline-needs-review=%d  '
          'struct-not-found=%d'
          % ('typed' if APPLY else 'would-type', typed,
             'named' if APPLY else 'would-name', renamed, skipped, inline,
             missing))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('globals_apply'))
