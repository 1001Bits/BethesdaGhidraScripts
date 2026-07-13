"""Ghidra driver: APPLY ctor_mine field proposals to the program's structs.

ctor_mine.py writes proposals (class, offset, type, name, slot_state) to a
CSV but nothing applied them -- so every recovered field type/name sat
unused.  This applies them CONSERVATIVELY:

  * only touches slots whose CURRENT component is undefined / unk* / pad*
    (re-checked live, not trusted from the CSV) -- never overwrites a real
    field;
  * embedded-object proposals (name == 'embedded') set field@off to the
    proposed struct type, but only if that type exists in the DTM and fits
    without overrunning the next defined component;
  * 'base' proposals (off==0 inheritance) are skipped -- CommonLib already
    inlines base classes, and retyping offset 0 is risky;
  * param-derived proposals (name is a field label) rename the slot and, if
    the proposed type resolves, retype it.

Dry-run default; BGS_ENRICH_APPLY=go to write.  Reads the CSV from
BGS_CTOR_CSV (same default path ctor_mine writes).
"""
import csv
import os

from evidence_identity import EvidenceIdentityError, validate_evidence

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'


def _resolve_type(dtm, name):
    name = name.strip()
    matches = []
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name or str(dt.getPathName()) == name:
            matches.append(dt)
    return matches[0] if len(matches) == 1 else None


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    csv_path = os.environ.get('BGS_CTOR_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'ctor_fields_%s.csv' % cp.getName().replace('.', '_'))
    if not os.path.isfile(csv_path):
        print('ctor-apply (%s): no proposals CSV at %s' % (cp.getName(), csv_path))
        return
    try:
        binding = validate_evidence(
            csv_path, cp, 'ctor_fields', require_content=True)
        if binding.get('address_coordinate') != 'NONE':
            raise EvidenceIdentityError(
                'constructor field evidence must use class-relative offsets')
    except EvidenceIdentityError as exc:
        print('ctor-apply: refusing stale/unbound proposals: %s' % exc)
        return

    # index structs by name
    struct_candidates = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() == 'StructureDB':
            struct_candidates.setdefault(dt.getName(), []).append(dt)
            struct_candidates.setdefault(str(dt.getPathName()), []).append(dt)

    def resolve_struct(name):
        candidates = struct_candidates.get(name, [])
        unique = {str(dt.getPathName()): dt for dt in candidates}
        return next(iter(unique.values())) if len(unique) == 1 else None

    def is_unk_at(sdt, off):
        """Current component at off is undefined/unk/pad (safe to fill)?"""
        dtc = sdt.getComponentAt(off) if hasattr(sdt, 'getComponentAt') else None
        if dtc is None:
            return True
        fn = dtc.getFieldName() or ''
        tn = dtc.getDataType().getName().lower()
        return (dtc.getOffset() == off and
                (fn.startswith(('unk', 'pad')) or 'undefined' in tn))

    def next_defined_off(sdt, off):
        best = sdt.getLength()
        for c in sdt.getDefinedComponents():
            o = c.getOffset()
            if o > off and o < best:
                best = o
        return best

    rows = list(csv.DictReader(open(csv_path)))
    typed = renamed = skipped_known = skipped_fit = skipped_notype = skipped_conf = 0
    had_parent_transaction = (
        APPLY and cp.getCurrentTransactionInfo() is not None)
    tx = cp.startTransaction('ctor-apply') if APPLY else None
    commit = False
    try:
        for r in rows:
            cls = r['class']
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
            except ValueError:
                continue
            if off < 0 or off >= sdt.getLength():
                skipped_fit += 1
                continue
            kind = r['name']
            tname = r['type']
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
                if APPLY:
                    evidence = r.get('constructors') or 'constructor consensus'
                    sdt.replaceAtOffset(
                        off, dt, sz, None, 'ctor-mine: ' + evidence)
                    typed += 1
                else:
                    typed += 1
            else:                                    # param-derived field label
                dt = _resolve_type(dtm, tname)
                label = kind or None
                if dt is None:
                    # name-only: just rename the undefined slot if possible
                    skipped_notype += 1
                    continue
                sz = dt.getLength()
                if (sz <= 0 or off + sz > next_defined_off(sdt, off) or
                        off + sz > sdt.getLength()):
                    skipped_fit += 1
                    continue
                if APPLY:
                    evidence = r.get('constructors') or 'constructor consensus'
                    sdt.replaceAtOffset(
                        off, dt, sz, label, 'ctor-mine: ' + evidence)
                    typed += 1
                    if label:
                        renamed += 1
                else:
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


if 'currentProgram' in globals():
    run()
