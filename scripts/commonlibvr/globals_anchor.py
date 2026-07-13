"""Global-as-anchor field mining (phase 4 of the globals workflow).

commonlib_discover mines a class's fields from its OWN methods (this = param-0). But a
singleton is reached everywhere through its global (`g_X->field`), in functions that
are NOT X's methods -- so those accesses are invisible to the method-scoped discoverer.
Once globals_harvest/apply_globals have TYPED the global `g_X : X *`, the decompiler
types every `g_X` load as an `X *`, and we can mine X's layout from those accesses:
for each function referencing g_X, find the loaded `X *` varnode and run the same
FillOutStructureHelper inference on it. PlayerCharacter alone is referenced by ~1246
functions -- a large field-observation surface the method scope never sees.

This is the real "typed global -> more class RE" lever (store-site inference, phase 3,
does not fire for singletons because they are read, not cached in fields). It reuses
the discovery pipeline wholesale: clvr_ghidra_util for the surface/helpers, discover_plan
for consensus, populate_plan for the improve-or-nop apply, review_plan for the queue.

NON-DESTRUCTIVE: processStructure with createNewStructure=TRUE (throwaway, read-only),
copy-validated apply (length unchanged, no RE lost), one always-committed transaction.
Dry-run by default; CLVR_ANCHOR_APPLY=go. Knobs: CLVR_ANCHOR_SAMPLES (referrers
decompiled per global, default 16), CLVR_ANCHOR_MAX_GLOBALS (0 = all). Run programs
SEQUENTIALLY (shared os.environ).
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
APPLY = os.environ.get('CLVR_ANCHOR_APPLY', 'dry').lower() == 'go'
SAMPLES = int(os.environ.get('CLVR_ANCHOR_SAMPLES', '16') or 16)
MAX_GLOBALS = int(os.environ.get('CLVR_ANCHOR_MAX_GLOBALS', '0') or 0)
OUT_CSV = os.environ.get('CLVR_ANCHOR_CSV', IMPORT_PATH + '.anchor_fields.csv')
# own review queue -- must NOT clobber commonlib_discover's <import>.review_queue.csv
REVIEW_CSV = os.environ.get('CLVR_ANCHOR_REVIEW_CSV', IMPORT_PATH + '.anchor_review_queue.csv')

import importlib.util as _ilu  # noqa: E402


def _load(mod, fn):
    spec = _ilu.spec_from_file_location(mod, os.path.join(SCRIPT_DIR, fn))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


dp = _load('clvr_discover_plan', 'discover_plan.py')
fa = _load('clvr_field_apply', 'field_apply.py')
pl = _load('clvr_populate_plan', 'populate_plan.py')
rp = _load('clvr_review_plan', 'review_plan.py')
gu = _load('clvr_ghidra_util', 'clvr_ghidra_util.py')
ip = _load('clvr_discover_incremental_plan', 'discover_incremental_plan.py')


def _global_value_high(hf, gaddr_off, PcodeOp):
    """The HighVariable for the typed global at gaddr_off -- the `X *` the decompiler
    holds for it. The decompiler does NOT emit a LOAD with a constant address: it
    represents the global as a VARNODE whose address IS the global address (ram space),
    already typed `X *`. So we find any pcode operand at that address and return its
    high (preferring a pointer-typed one, which processStructure can mine for X's
    layout). None if the global is not referenced as a value here."""
    fallback = None
    ops = hf.getPcodeOps()
    while ops.hasNext():
        op = ops.next()
        cands = [op.getInput(i) for i in range(op.getNumInputs())]
        cands.append(op.getOutput())
        for vn in cands:
            if vn is None:
                continue
            a = vn.getAddress()
            if a is None or not a.isMemoryAddress() or a.getOffset() != gaddr_off:
                continue
            h = vn.getHigh()
            if h is None:
                continue
            dt = h.getDataType()
            if dt is not None and dt.getName().endswith('*'):
                return h                     # the X* value -> mine X
            fallback = fallback or h
    return fallback


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.decompiler.util import FillOutStructureHelper
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.data import Pointer, Structure
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()
    listing = cp.getListing()
    rm = cp.getReferenceManager()

    # unknown-field surface per /types.h class
    unk_by_class = {}
    struct_by_class = {}
    for dt in gu.types_structs(dtm):
        offs = gu.unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs
            struct_by_class[dt.getName()] = dt

    # typed globals that point to a class WITH unknowns -> our anchors
    anchors = []                             # (Address, class_name)
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        t = d.getDataType()
        if isinstance(t, Pointer):
            base = t.getDataType()
            if isinstance(base, Structure) and base.getName() in unk_by_class:
                anchors.append((d.getAddress(), base.getName()))
    if MAX_GLOBALS:
        anchors = anchors[:MAX_GLOBALS]
    print('Anchor mining (%s): %d typed globals point to %d unknown-bearing classes; '
          'sampling <=%d referrers each.'
          % (cp.getName(), len(anchors), len(set(c for _, c in anchors)), SAMPLES))

    decomp = DecompInterface()
    decomp.openProgram(cp)
    helper = FillOutStructureHelper(cp, monitor)  # noqa: F821

    observations = []
    dt_by_typename = {}
    evidence = {}
    mined_globals = funcs = 0
    for gaddr, cls in anchors:
        offs = unk_by_class[cls]
        seen = set()
        for ref in rm.getReferencesTo(gaddr):
            if len(seen) >= SAMPLES:
                break
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is None or f.getEntryPoint() in seen:
                continue
            seen.add(f.getEntryPoint())
            try:
                r = decomp.decompileFunction(f, 30, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                hv = _global_value_high(r.getHighFunction(), gaddr.getOffset(), PcodeOp)
                if hv is None:
                    continue
                st = helper.processStructure(hv, f, True, False, decomp)
                if st is None:
                    continue
                funcs += 1
                for c in st.getComponents():
                    tn = c.getDataType().getName()
                    if c.getOffset() in offs and gu.useful_typename(tn):
                        observations.append((cls, c.getOffset(), tn))
                        dt_by_typename.setdefault(tn, c.getDataType())
                        ev = evidence.setdefault((cls, c.getOffset()), [])
                        if f.getName() not in ev and len(ev) < 6:
                            ev.append(f.getName())
            except Exception:
                continue
        mined_globals += 1

    decomp.dispose()

    aggregated = dp.aggregate_inferences(observations)
    rows = dp.to_rows(aggregated, lambda c, o: unk_by_class.get(c, {}).get(o, ''))
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'current_name', 'inferred_type', 'confidence',
                    'votes', 'total_observations'])
        for cls, off, cur, typ, conf, votes, total in rows:
            w.writerow([cls, '0x%X' % off, cur, typ, conf, votes, total])

    # review queue: size-only-consensus fields (same as discovery)
    review = [(cls, off, info) for (cls, off), info in aggregated.items()
              if rp.is_review_worthy(info['named'], info['total'], info['votes'])[0]]
    review.sort(key=lambda r: rp.review_rank(r[2]['total'], r[2]['votes']), reverse=True)
    try:
        with open(REVIEW_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['class', 'offset', 'current_name', 'size_only_guess', 'votes',
                        'total_observations', 'observed_in', 'decision_type'])
            for cls, off, info in review:
                w.writerow([cls, '0x%X' % off, unk_by_class.get(cls, {}).get(off, ''),
                            info['type'], info['votes'], info['total'],
                            ' '.join(evidence.get((cls, off), [])[:6]), ''])
    except Exception as e:
        print('  (review queue write failed: %s)' % e)

    # apply high-confidence named fields (shared improve-or-nop apply)
    applied, skips, changed_classes, samples = fa.apply_fields(
        cp, dtm, struct_by_class, dt_by_typename, aggregated, 'clvr-anchor', APPLY)

    named = sum(1 for r in rows if r[3] not in dp.GENERIC_TYPES)
    print('\n=== Anchor mining summary (%s) ===' % cp.getName())
    print('  globals mined=%d  functions analyzed=%d  observations=%d'
          % (mined_globals, funcs, len(observations)))
    print('  candidate fields=%d  (named-type=%d, size-only=%d)'
          % (len(rows), named, len(rows) - named))
    if APPLY:
        print('  APPLIED %d fields   skips=%s' % (applied, dict(skips)))
        for s in samples:
            print('     ' + s)
    else:
        print('  READ-ONLY (CLVR_ANCHOR_APPLY=go to write)')
    for cls, off, cur, typ, conf, votes, total in rows[:15]:
        if typ not in dp.GENERIC_TYPES:
            print('   %s +0x%X %s -> %s [%s] %d/%d' % (cls, off, cur, typ, conf, votes, total))
    print('  -> ' + OUT_CSV)
    if changed_classes and APPLY:
        print('  changed classes (re-mine next discovery): %s'
              % ', '.join(sorted(changed_classes)[:12]))


run()
