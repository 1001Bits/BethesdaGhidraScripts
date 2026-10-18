"""Ghidra driver: APPLY ctor_mine field proposals to the program's structs.

ctor_mine.py writes proposals (class, offset, type, name, slot_state) to a
CSV but nothing applied them -- so every recovered field type/name sat
unused.  This applies them CONSERVATIVELY:

  * only touches slots whose CURRENT component has an undefined TYPE
    (re-checked live, not trusted from the CSV).  A member that is merely
    NAMED unk*/pad* but carries a real type is somebody's work and is kept;
  * embedded-object proposals (name == 'embedded') set field@off to the
    proposed struct type, but only if that type exists in the DTM and fits
    without overrunning the next defined component;
  * 'base' proposals (off==0 inheritance) are skipped -- CommonLib already
    inlines base classes, and retyping offset 0 is risky;
  * param-derived proposals (name is a field label) rename the slot and, if
    the proposed type resolves, retype it.

Dry-run default; BGS_ENRICH_APPLY=go to write.  Reads the mined evidence
from BGS_CTOR_CSV (same default path ctor_mine writes; content-bound, do not
edit) and the reviewer's ``decision`` column from BGS_CTOR_DECISIONS_CSV
(default refs/ctor_decisions_<folder>_<prog>.csv, written by the launchers
after ctor_mine; identity-bound only, so filling it in does not break
anything).

When applying, missing/stale/unbound evidence or a missing decisions file
RAISES (the launcher reports FAIL and rolls back); a dry-run prints a
``REFUSED:`` line instead.
"""
import os
import re

from review_queue import (CTORS, ReviewQueueError, load_reviewed_rows,
                          queue_paths)

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
# A field label must be a C identifier.  Older ctor_mine output stripped
# ``param_`` and proposed names such as ``2``; such a row keeps its type only.
_FIELD_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def field_label_or_none(name):
    """``name`` when it is a usable field identifier, else None."""
    name = (name or '').strip()
    return name if _FIELD_NAME.match(name) else None


def is_placeholder_component(component, offset):
    """True when the member starting at ``offset`` may be filled in.

    ``component`` is what ``Structure.getComponentContaining(offset)`` returned.
    Only the TYPE decides: ``undefined``/``undefined4``/``undefined1[8]`` are
    placeholders.  A typed member named ``unk10``/``pad1C`` is real work (a
    reviewer typed it and kept the provisional name) and is never replaced.

    No component (packed padding, past the end) is NOT free, and neither is an
    offset inside a larger member: ``replaceAtOffset`` there would turn the
    whole covering field -- e.g. a typed 16-byte ``Inner member`` -- into
    undefined bytes.
    """
    if component is None:
        return False
    if int(component.getOffset()) != int(offset):
        return False
    type_name = str(component.getDataType().getName() or '').lower()
    return type_name.startswith('undefined')


def index_types(data_types):
    """One pass over the DTM: name and path -> unique data types."""
    by_key = {}
    for dt in data_types:
        path = str(dt.getPathName())
        by_key.setdefault(str(dt.getName()), {})[path] = dt
        by_key.setdefault(path, {})[path] = dt
    return by_key


def resolve_indexed(index, name, only=None):
    """The one data type called ``name``; a colliding leaf name is None."""
    found = index.get((name or '').strip(), {})
    if only is not None:
        found = {path: dt for path, dt in found.items() if only(dt)}
    return next(iter(found.values())) if len(found) == 1 else None


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    csv_path, decisions_path = queue_paths(CTORS, cp)
    try:
        rows, n_decisions = load_reviewed_rows(
            csv_path, decisions_path, cp, CTORS)
    except ReviewQueueError as exc:
        if APPLY:
            # A refusal while applying is a FAILURE: raising reaches the
            # launcher as stderr, so it rolls back and reports FAIL.
            raise
        print('ctor-apply (%s): REFUSED: %s' % (cp.getName(), exc))
        return
    print('ctor-apply: %d proposals from %s, %d reviewer decision(s) from %s'
          % (len(rows), csv_path, n_decisions, decisions_path))

    # One pass over the DTM (it used to be walked once per CSV row).
    type_index = index_types(dtm.getAllDataTypes())

    def _is_struct(dt):
        return dt.getClass().getSimpleName() == 'StructureDB'

    def resolve_struct(name):
        return resolve_indexed(type_index, name, only=_is_struct)

    def _resolve_type(_dtm, name):
        return resolve_indexed(type_index, name)

    def is_unk_at(sdt, off):
        """The member COVERING off starts there with an undefined TYPE?

        ``getComponentAt`` returns None for an offset inside an earlier field,
        which used to read as "free"; ``getComponentContaining`` returns that
        covering field (or a generated undefined filler in a gap), so the
        start-offset and type checks below see what would be overwritten.
        """
        dtc = sdt.getComponentContaining(off)
        return is_placeholder_component(dtc, off)

    def next_defined_off(sdt, off):
        best = sdt.getLength()
        for c in sdt.getDefinedComponents():
            o = c.getOffset()
            if o > off and o < best:
                best = o
        return best

    errors = []

    def replace(sdt, off, dt, sz, label, r):
        """One bad row must not void the pass: count it and move on."""
        evidence = r.get('constructors') or 'constructor consensus'
        try:
            sdt.replaceAtOffset(off, dt, sz, label, 'ctor-mine: ' + evidence)
            return True
        except Exception as exc:  # noqa: BLE001  (Java IllegalArgumentException etc.)
            errors.append('%s+0x%X %s: %s' % (r.get('class'), off,
                                              r.get('type'), exc))
            return False

    typed = renamed = skipped_known = skipped_fit = skipped_notype = skipped_conf = 0
    had_parent_transaction = (
        APPLY and cp.getCurrentTransactionInfo() is not None)
    tx = cp.startTransaction('ctor-apply') if APPLY else None
    commit = False
    try:
        for r in rows:
            cls = (r.get('class') or '').strip()
            sdt = resolve_struct(cls)
            if sdt is None:
                continue
            decision = (r.get('decision') or '').strip().lower()
            confidence = (r.get('confidence') or '').strip().lower()
            if decision == 'skip':
                skipped_conf += 1
                continue
            if decision not in ('apply', 'approved') and confidence != 'high':
                skipped_conf += 1
                continue
            try:
                off = int(r['offset'], 16)
            except (KeyError, TypeError, ValueError):
                continue
            if off < 0 or off >= sdt.getLength():
                skipped_fit += 1
                continue
            kind = (r.get('name') or '').strip()
            tname = (r.get('type') or '').strip()
            if kind == 'base':                       # off==0 inheritance: skip
                continue
            if not is_unk_at(sdt, off):              # don't overwrite real field
                skipped_known += 1
                continue
            if kind == 'embedded':
                dt = resolve_struct(tname) or _resolve_type(dtm, tname)
                if dt is None:
                    skipped_notype += 1
                    continue
                sz = dt.getLength()
                if (sz <= 0 or off + sz > next_defined_off(sdt, off) or
                        off + sz > sdt.getLength()):
                    skipped_fit += 1
                    continue
                if not APPLY or replace(sdt, off, dt, sz, None, r):
                    typed += 1
            else:                                    # param-derived field label
                dt = _resolve_type(dtm, tname)
                label = field_label_or_none(kind)
                if dt is None:
                    # name-only: just rename the undefined slot if possible
                    skipped_notype += 1
                    continue
                sz = dt.getLength()
                if (sz <= 0 or off + sz > next_defined_off(sdt, off) or
                        off + sz > sdt.getLength()):
                    skipped_fit += 1
                    continue
                if not APPLY or replace(sdt, off, dt, sz, label, r):
                    typed += 1
                    if label:
                        renamed += 1
        commit = True
    finally:
        if tx is not None:
            committed = bool(cp.endTransaction(tx, commit))
            if commit and not had_parent_transaction and not committed:
                raise RuntimeError('ctor-apply transaction did not commit')

    print('ctor-apply (%s): %s  %d fields typed (%d named), '
          'skipped %d already-defined, %d no-fit, %d type-missing, %d unreviewed/low-confidence'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', typed, renamed,
             skipped_known, skipped_fit, skipped_notype, skipped_conf))
    if errors:
        print('  %d row(s) FAILED to apply (left untouched):' % len(errors))
        for line in errors[:20]:
            print('    ' + line)


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('ctor_apply'))
