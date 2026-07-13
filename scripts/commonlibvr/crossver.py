"""Cross-version field propagation: carry a field resolved in one runtime to the
others (SE <-> AE <-> VR), keyed on the CommonLib offset in the field name.

Two modes (set CLVR_XVER):
  export  -- write currentProgram's resolved /types.h fields to
             <import>.resolved_fields.csv  (class, cl_offset, typename). Run on each
             of SE/AE/VR.
  apply   -- read EVERY *.resolved_fields.csv in the import dir, reconcile per
             (class, cl_offset) across runtimes (crossver_plan.pick_best_type), and
             fill currentProgram's still-unknown field at that CommonLib offset with
             the type -- so one runtime's discovery (or LLM review decision) populates
             the others. Run on each of SE/AE/VR after exporting all three.

The CommonLib offset (encoded in unk*/pad*/fld* names) is the cross-version key, so
VR's larger/shifted layout is handled by NAME, not raw offset. Apply reuses the
improve-or-nop guarantee: each field is validated on a detached struct.copy() and the
live struct is touched only if length-unchanged and no RE is lost
(populate_plan.is_struct_change_safe) -- it can only improve a struct or skip.

Dry-run by default; CLVR_XVER_APPLY=go to write. Run programs SEQUENTIALLY (os.environ
/ CLVR_IMPORT is shared across concurrent Ghidra evals).
"""
import csv
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
MODE = os.environ.get('CLVR_XVER', 'export').lower()
APPLY = os.environ.get('CLVR_XVER_APPLY', 'dry').lower() == 'go'
RESOLVED_CSV = IMPORT_PATH + '.resolved_fields.csv'

import importlib.util as _ilu  # noqa: E402
_cspec = _ilu.spec_from_file_location('clvr_crossver_plan', os.path.join(SCRIPT_DIR, 'crossver_plan.py'))
cv = _ilu.module_from_spec(_cspec)
_cspec.loader.exec_module(cv)
_pspec = _ilu.spec_from_file_location('clvr_populate_plan', os.path.join(SCRIPT_DIR, 'populate_plan.py'))
pl = _ilu.module_from_spec(_pspec)
_pspec.loader.exec_module(pl)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)


def _provenance_map():
    """(class, raw_offset) -> witness functions, from the sibling discovered_fields.csv
    (its `observed_in` column). Lets the resolved export carry use-site provenance so a
    later semantic-naming pass has a function to read, not just a type. Best-effort: an
    older discovered_fields.csv without the column, or no file, just yields blanks."""
    prov = {}
    disc = IMPORT_PATH + '.discovered_fields.csv'
    if not os.path.exists(disc):
        return prov
    try:
        with open(disc, newline='') as fh:
            for row in csv.DictReader(fh):
                obs = (row.get('observed_in') or '').strip()
                if obs:
                    prov[(row['class'], int(row['offset'], 16))] = obs
    except Exception:
        pass
    return prov


def export():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    prov = _provenance_map()
    rows = []
    for st in gu.types_structs(dtm):
        for i in range(st.getNumComponents()):
            c = st.getComponent(i)
            fn = c.getFieldName() or ''
            tn = c.getDataType().getName()
            if cv.is_resolved(fn, tn):
                rows.append((st.getName(), '0x%X' % cv.field_key(fn), tn,
                             prov.get((st.getName(), c.getOffset()), '')))
    with open(RESOLVED_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'cl_offset', 'typename', 'observed_in'])
        for r in rows:
            w.writerow(r)
    print('xver export (%s): %d resolved /types.h fields -> %s'
          % (cp.getName(), len(rows), RESOLVED_CSV))


def apply():
    import collections
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    # merge every runtime's resolved fields: (class, cl_offset) -> [typenames]
    merged = collections.defaultdict(list)
    files = sorted(glob.glob(os.path.join(os.path.dirname(IMPORT_PATH), '*.resolved_fields.csv')))
    for path in files:
        with open(path, newline='') as fh:
            for row in csv.DictReader(fh):
                merged[(row['class'], int(row['cl_offset'], 16))].append(row['typename'])
    print('xver apply (%s): %d sibling export(s), %d (class,offset) keys'
          % (cp.getName(), len(files), len(merged)))

    by_name = gu.build_by_name(dtm)

    # index this program's /types.h structs and their receivable / already-known slots
    struct_by_class = {st.getName(): st for st in gu.types_structs(dtm)}

    applied = skipped = conflicts = 0
    samples = []
    tx = cp.startTransaction('cross-version propagate') if APPLY else None
    try:
        for (cls, off), typenames in merged.items():
            struct = struct_by_class.get(cls)
            if struct is None:
                skipped += 1
                continue
            # find this program's field at the same CommonLib offset
            target = None
            already = False
            for i in range(struct.getNumComponents()):
                c = struct.getComponent(i)
                k = cv.field_key(c.getFieldName() or '')
                if k != off:
                    continue
                if cv.is_resolved(c.getFieldName() or '', c.getDataType().getName()):
                    already = True
                elif cv.is_unknown_target(c.getFieldName() or '', c.getDataType().getName()):
                    target = c
                break
            if already or target is None:
                skipped += 1
                continue
            best, conflict = cv.pick_best_type(typenames)
            if conflict:
                conflicts += 1
            dt = gu.resolve_type(dtm, by_name, best) if best else None
            if dt is None or dt.getLength() != target.getLength():
                skipped += 1
                continue
            toff = target.getOffset()
            cur = target.getFieldName() or ''
            digits = ''.join(ch for ch in cur if ch.isalnum())
            for pre in ('unk', 'pad', 'off_'):
                if digits.lower().startswith(pre):
                    digits = digits[len(pre):]
                    break
            new_name = 'fld%s' % (digits or ('%X' % off))
            # improve-or-nop: validate on a detached copy first
            base = gu.struct_metrics(struct)
            try:
                tcopy = struct.copy(dtm)
                tc = tcopy.getComponentAt(toff)
                if tc is None or tc.getOffset() != toff:
                    skipped += 1
                    continue
                tcopy.replaceAtOffset(toff, dt, dt.getLength(), new_name, '')
                tm = gu.struct_metrics(tcopy)
            except Exception:
                skipped += 1
                continue
            if not pl.is_struct_change_safe(base, tm):
                skipped += 1
                continue
            if APPLY:
                try:
                    struct.replaceAtOffset(toff, dt, dt.getLength(), new_name,
                                           'clvr-xver ' + best)
                except Exception:
                    skipped += 1
                    continue
            applied += 1
            if len(samples) < 20:
                samples.append('%s +0x%X(cl 0x%X) %s -> %s%s'
                               % (cls, toff, off, cur, best, ' [CONFLICT]' if conflict else ''))
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    print('xver apply (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  %s=%d  skipped=%d  type-conflicts=%d'
          % ('applied' if APPLY else 'would-apply', applied, skipped, conflicts))
    for s in samples:
        print('   ' + s)
    if not APPLY:
        print('  set CLVR_XVER_APPLY=go to write.')


if MODE == 'apply':
    apply()
else:
    export()
