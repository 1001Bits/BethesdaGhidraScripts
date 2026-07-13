"""Duplicate-type deduper -- merge duplicates into the canonical type so references
(signatures, struct fields) point at the populated CommonLib type.

A program with its MS PDB loaded carries duplicate STRUCT types per name: Ghidra's
auto-conflict copies (`X.conflict`) and the `/SkyrimSE.pdb/X` vs `/types.h/X` twins.
References to a duplicate miss the RE on the canonical type (132 of ~2.5k AE typed
signatures pointed at `/SkyrimSE.pdb/*` twins; PDB struct fields point at `*.conflict`).
`dtm.replaceDataType(dup, keeper)` merges a duplicate away AND rewires every reference
to the keeper -- so they finally resolve to the canonical populated type.

Two SAFE passes (only unambiguous same-size merges; size-conflicts are flagged, never
auto-merged -- the in-memory `Memory::Allocate` size is ground truth, not CommonLib or
the PDB blindly):
  A. `X.conflict*` -> `X` in the SAME category (Ghidra's conflict copy IS a dup of the
     same-category, same-name type). Same size only.
  B. `/SkyrimSE.pdb/X` -> the UNIQUE same-size `/types.h/X` (skip if 0 or >1 /types.h
     candidates -- ambiguous leaf like nested RUNTIME_DATA/Data/Entry).

NON-DESTRUCTIVE intent: only merges types proven duplicate (same size); never changes a
layout. Dry-run by default (counts + a <import>.dedup_conflicts.csv of size-disagreeing
groups for binary review); CLVR_DEDUP=go to apply. replaceDataType is SLOW (~2-3s each,
rescans all functions) -- applied in batched transactions. Run programs SEQUENTIALLY.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
APPLY = os.environ.get('CLVR_DEDUP', 'dry').lower() == 'go'
BATCH = int(os.environ.get('CLVR_DEDUP_BATCH', '40') or 40)
CONFLICT_CSV = IMPORT_PATH + '.dedup_conflicts.csv'

import importlib.util as _ilu  # noqa: E402
_dspec = _ilu.spec_from_file_location('clvr_dedup_plan', os.path.join(SCRIPT_DIR, 'dedup_plan.py'))
dp = _ilu.module_from_spec(_dspec)
_dspec.loader.exec_module(dp)


def _canon_of(dtm, dt, depth=0):
    """Resolve the canonical (non-.conflict) twin of any datatype kind, rebuilding
    pointer / array wrappers around the canonical element. Returns None if no twin."""
    import ghidra.program.model.data as D
    if dt is None or depth > 12:
        return None
    if isinstance(dt, D.Pointer):
        b = _canon_of(dtm, dt.getDataType(), depth + 1)
        return dtm.getPointer(b) if b is not None else None
    if isinstance(dt, D.Array):
        b = _canon_of(dtm, dt.getDataType(), depth + 1)
        return D.ArrayDataType(b, dt.getNumElements(), b.getLength()) if b is not None else None
    p = dt.getPathName()
    i = p.find('.conflict')
    if i < 0:
        return dt
    return dtm.getDataType(p[:i] + p[i + len('.conflict'):].lstrip('0123456789'))


def _all_conflicts(dtm):
    out = []
    it = dtm.getAllDataTypes()
    while it.hasNext():
        d = it.next()
        if '.conflict' in d.getName():
            out.append(d)
    return out


def purge_conflicts(cp, dtm, apply, mon):
    """Collapse every ``X.conflict`` onto its canonical twin ``X`` so exactly one
    canonical type survives.

    Ghidra's default conflict handler mints ``X.conflict`` copies whenever a type /
    vtable struct / function-definition is re-added with a differing definition (PDB
    import, repeated signature application, re-runs of the importer). These form a
    self-contained, often cyclic cluster (class struct -> __vftable.conflict * ->
    *_VFTable.conflict -> _func_*.conflict) that the struct-only Pass A never fully
    clears. Strategy: rewire any .conflict referenced by a REAL (non-.conflict) type
    or a function signature onto its canonical via replaceDataType; then delete the
    rest (the cluster has no external references, so cycles don't matter and the
    cheap remove() -- no function rescan -- suffices). A .conflict that still has a
    non-.conflict referrer after the rewire pass (rewire failed) is never deleted."""
    import ghidra.program.model.data as D
    confs = _all_conflicts(dtm)
    if not confs:
        print('purge_conflicts (%s): no .conflict types' % cp.getName())
        return (0, 0, 0)

    # function signatures reference datatypes outside the datatype-parent graph, so
    # collect the .conflict types used by any function prototype up front.
    sig_refs = set()
    fi = cp.getFunctionManager().getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        try:
            used = [f.getReturnType()] + [p.getDataType() for p in f.getParameters()]
        except Exception:
            continue
        for t in used:
            bt = t
            while isinstance(bt, (D.Pointer, D.Array)):
                bt = bt.getDataType()
            if bt is not None and '.conflict' in bt.getName():
                sig_refs.add(t.getPathName())

    def _ext(d):
        return any('.conflict' not in p.getName() for p in d.getParents()) or \
            d.getPathName() in sig_refs

    print('purge_conflicts (%s): %d .conflict types (%d externally / signature referenced)'
          % (cp.getName(), len(confs), sum(1 for d in confs if _ext(d))))
    if not apply:
        print('  DRY-RUN: set CLVR_DEDUP=go to apply.')
        return (len(confs), 0, 0)

    rewired = removed = skipped = 0
    tx = cp.startTransaction('dedup: purge .conflict')
    try:
        for d in _all_conflicts(dtm):
            if not _ext(d):
                continue
            c = _canon_of(dtm, d)
            if c is not None and c is not d:
                try:
                    dtm.replaceDataType(d, c, True)
                    rewired += 1
                except Exception:
                    skipped += 1
        for d in _all_conflicts(dtm):
            # never delete one that still has a real referrer (its rewire failed)
            if any('.conflict' not in p.getName() for p in d.getParents()):
                skipped += 1
                continue
            try:
                dtm.remove(d, mon)
                removed += 1
            except Exception:
                skipped += 1
    finally:
        cp.endTransaction(tx, True)
    print('purge_conflicts APPLIED (%s): rewired=%d removed=%d skipped=%d remaining=%d'
          % (cp.getName(), rewired, removed, skipped, len(_all_conflicts(dtm))))
    return (rewired, removed, skipped)


def run():
    from ghidra.program.model.data import Structure
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    # Pass 0: collapse every .conflict copy onto its canonical twin (all datatype
    # kinds, incl. the cyclic vtable/funcdef plumbing the struct passes miss).
    purge_conflicts(cp, dtm, APPLY, monitor)  # noqa: F821

    structs = [d for d in dtm.getAllDataTypes() if isinstance(d, Structure)]

    # Pass A: .conflict copies -> same-category base, grouped by (category, base leaf)
    by_qual = {}
    for d in structs:
        key = (str(d.getCategoryPath()), dp.base_name(d.getName()))
        by_qual.setdefault(key, []).append(d)

    merges = []        # (dup_dt, keeper_dt)
    conflicts = []     # (name, [(size, category), ...])
    for (_cat, _bn), dts in by_qual.items():
        if len(dts) < 2:
            continue
        variants = [{'key': i, 'name': d.getName(), 'category': str(d.getCategoryPath()),
                     'size': d.getLength(), 'ndefined': d.getNumDefinedComponents()}
                    for i, d in enumerate(dts)]
        keeper_key, merge_keys, conflict, _reason = dp.plan_merge(variants)
        if conflict:
            conflicts.append((dts[0].getName(), [(d.getLength(), str(d.getCategoryPath())) for d in dts]))
            continue
        for mk in merge_keys:
            merges.append((dts[mk], dts[keeper_key]))

    # Pass B: /SkyrimSE.pdb/X -> the UNIQUE same-size /types.h/X (by leaf name)
    typesh_by_leaf = {}
    for d in structs:
        if 'types.h' in str(d.getCategoryPath()):
            typesh_by_leaf.setdefault(d.getName(), []).append(d)
    pdb_twin = pdb_ambig = 0
    for d in structs:
        if 'SkyrimSE.pdb' not in str(d.getCategoryPath()):
            continue
        cand = typesh_by_leaf.get(d.getName(), [])
        if len(cand) == 1 and cand[0].getLength() == d.getLength() and cand[0] is not d:
            merges.append((d, cand[0]))
            pdb_twin += 1
        elif cand:
            pdb_ambig += 1

    # de-dup the merge list (a dt could be both a .conflict AND a pdb twin target)
    seen = set()
    uniq = []
    for m, k in merges:
        mp = m.getPathName()
        if mp in seen or m is k:
            continue
        seen.add(mp)
        uniq.append((m, k))

    print('dedup (%s): %d duplicate merges queued (pass A .conflict + pass B pdb-twin=%d, '
          'pdb-ambiguous-skipped=%d), %d size-conflict groups flagged'
          % (cp.getName(), len(uniq), pdb_twin, pdb_ambig, len(conflicts)))
    for m, k in uniq[:15]:
        print('   merge %s -> %s' % (m.getPathName(), k.getPathName()))

    try:
        with open(CONFLICT_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['name', 'variant_sizes_and_categories'])
            for nm, info in conflicts:
                w.writerow([nm, ' | '.join('0x%X@%s' % (s, c) for s, c in info)])
    except Exception as e:
        print('  (conflict CSV write failed: %s)' % e)

    if not APPLY:
        print('  DRY-RUN: no merges applied. Set CLVR_DEDUP=go to apply.')
        print('  size-conflicts (binary-verify) -> %s' % CONFLICT_CSV)
        return

    done = err = 0
    for i in range(0, len(uniq), BATCH):
        batch = uniq[i:i + BATCH]
        tx = cp.startTransaction('dedup batch %d' % (i // BATCH))
        try:
            for m, k in batch:
                try:
                    dtm.replaceDataType(m, k, False)
                    done += 1
                except Exception:
                    err += 1
        finally:
            cp.endTransaction(tx, True)
        if (i // BATCH) % 5 == 0:
            monitor.setMessage('dedup %d/%d merged' % (done, len(uniq)))  # noqa: F821
            print('  ... %d/%d merged' % (done, len(uniq)))
    print('dedup APPLIED: %d merged, %d errors. size-conflicts -> %s' % (done, err, CONFLICT_CSV))


# Auto-run when exec'd directly in Ghidra. Importers (e.g. apply_enrich) pre-seed
# AUTORUN=False to reuse purge_conflicts() without running the full dedup.
if globals().get('AUTORUN', True):
    run()
