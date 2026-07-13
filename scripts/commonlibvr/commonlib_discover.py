"""CommonLib<->Ghidra discovery harvester (READ-ONLY).

Closes the virtuous cycle: the bootstrap imports CommonLib's types/sigs into
Ghidra; this leverages Ghidra's own decompiler dataflow (FillOutStructureHelper,
the engine behind "Auto Fill Out Structure") to INFER field types at the offsets
CommonLib still marks `unkNN` -- net-new RE that exists only because the typed
scaffold gave the decompiler anchors to propagate from. Feed the results back to
CommonLib, re-import, and the next cycle propagates one level deeper.

NON-DESTRUCTIVE: mining calls processStructure with createNewStructure=TRUE so it
builds a THROWAWAY structure to read -- it never fills out (and grows) the live
typed struct (createNewStructure=False does, silently, with no new type created).
The apply step additionally validates every field on a detached copy first and only
touches the live struct when the change is provably improve-or-nop (length
unchanged, no RE lost). Read-only mode (default) writes only a CSV.

Generalized: runtime is taken from the program name (offset key s/a/v), CommonLib
structs/symbols from the generated import. Run it on SE/AE/VR, any CommonLib
version. Output: <import>.discovered_fields.csv -- candidate CommonLib fields
(class, offset, current unk name, inferred type, confidence), high-confidence
first, ready for review and write-back.

Knobs (env): CLVR_DISCOVER_PER_CLASS (methods sampled per class, default 4),
CLVR_DISCOVER_MAX_CLASSES (0 = all), CLVR_DISCOVER_FOLLOW (1 = follow into called
functions for deeper inference, slower; default 0).
"""
import collections
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402

OUT_CSV = os.environ.get('CLVR_DISCOVER_CSV', IMPORT_PATH + '.discovered_fields.csv')
# Per class, how many `this`-methods/vfuncs to mine. 0 = ALL (default): a class
# reveals its field layout through its own methods, so walk them all. Set a positive
# N only to cap runtime (mines the first N in address order).
PER_CLASS = int(os.environ.get('CLVR_DISCOVER_PER_CLASS', '0') or 0)
MAX_CLASSES = int(os.environ.get('CLVR_DISCOVER_MAX_CLASSES', '0') or 0)
# Follow the class pointer into the functions it is passed to (callee review):
# FillOutStructureHelper observes field accesses one call-edge deeper. Default OFF
# (it roughly 20x's runtime for mostly size-only gains); set 1 to enable.
FOLLOW = os.environ.get('CLVR_DISCOVER_FOLLOW', '0') == '1'
# Default is read-only (write a CSV only). CLVR_DISCOVER_APPLY=go also WRITES the
# high-confidence named fields into the /types.h structs -- the edge that lets the
# in-Ghidra population cycle compound (a newly-typed field is an anchor next pass).
APPLY = os.environ.get('CLVR_DISCOVER_APPLY', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_discover_plan', os.path.join(SCRIPT_DIR, 'discover_plan.py'))
dp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(dp)
_rspec = _ilu.spec_from_file_location('clvr_review_plan', os.path.join(SCRIPT_DIR, 'review_plan.py'))
rp = _ilu.module_from_spec(_rspec)
_rspec.loader.exec_module(rp)
_ispec = _ilu.spec_from_file_location('clvr_discover_incremental_plan',
                                      os.path.join(SCRIPT_DIR, 'discover_incremental_plan.py'))
ip = _ilu.module_from_spec(_ispec)
_ispec.loader.exec_module(ip)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)
_faspec = _ilu.spec_from_file_location('clvr_field_apply', os.path.join(SCRIPT_DIR, 'field_apply.py'))
fa = _ilu.module_from_spec(_faspec)
_faspec.loader.exec_module(fa)

# INCREMENTAL discovery (skip re-mining classes whose dependency closure was untouched
# since last pass -- see discover_incremental_plan). DIRTY: a file of class names (one
# per line) the orchestrator wants re-mined this pass; empty/absent = full pass. STATE:
# persisted per-class refs (what each class dereferences) so the orchestrator can
# compute the next dirty set. CHANGED: the classes whose struct this pass modified,
# the seed for the next pass's dirty computation.
DIRTY_FILE = os.environ.get('CLVR_DISCOVER_DIRTY', '')
STATE_JSON = os.environ.get('CLVR_DISCOVER_STATE', IMPORT_PATH + '.discover_state.json')
CHANGED_JSON = os.environ.get('CLVR_DISCOVER_CHANGED', IMPORT_PATH + '.discover_changed.json')

# The optional LLM-review queue: fields the decompiler is sure EXIST (consensus) but
# could only size, not name -- a ranked worklist for a human/LLM to assign a type
# (applied authoritatively by apply_review.py). Always written; cheap, and the apply
# step is opt-in. <import>.review_queue.csv unless overridden.
REVIEW_CSV = os.environ.get('CLVR_DISCOVER_REVIEW_CSV', IMPORT_PATH + '.review_queue.csv')


def _unk_offsets(dt):
    """Pointer-sized offsets a /types.h struct still leaves unknown (unk/pad name
    or undefined type) -- the harvest surface."""
    offs = {}
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if c.getLength() >= 8 and (fn.startswith(('unk', 'pad')) or 'undefined' in tn):
            offs[c.getOffset()] = fn or ('off_%X' % c.getOffset())
    return offs


def _useful(tn):
    if not tn or 'undefined' in tn or '[' in tn:
        return False
    return tn not in ('char', 'byte', 'bool', 'void')


def _harvest_surface(dtm):
    """Live /types.h structs that still have unknown pointer-sized fields, with their
    unknown-offset maps. Returns (unk_by_class, struct_by_class)."""
    unk_by_class, struct_by_class = {}, {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if 'types.h' not in str(dt.getCategoryPath()):
            continue
        offs = _unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs
            struct_by_class[dt.getName()] = dt
    return unk_by_class, struct_by_class


def _function_pool(fm, unk_by_class):
    """Functions whose param-0 (`this`) is a class-with-unknowns -> the class's own
    methods, where it reveals its layout. Mining a NON-this param was tried and REVERTED
    (it inferred past the struct end and grew it ~2x); `this`-only is the safe surface."""
    by_class = {}
    for f in fm.getFunctions(True):
        base_t = gu.param0_class_name(f)
        if base_t and base_t in unk_by_class:
            by_class.setdefault(base_t, []).append((f, 0))
    # Incremental scope: an orchestrator-supplied dirty list restricts the pool; an
    # empty/absent list is a full cold pass.
    if DIRTY_FILE and os.path.exists(DIRTY_FILE):
        try:
            with open(DIRTY_FILE) as fh:
                want = set(line.strip() for line in fh if line.strip())
        except Exception:
            want = set()
        if want:
            full = len(by_class)
            by_class = {c: v for c, v in by_class.items() if c in want}
            print('Incremental discovery: mining %d/%d dirty classes (from %s).'
                  % (len(by_class), full, DIRTY_FILE))
    return by_class


def _global_edge_map(fm, listing, rm):
    """function entry offset -> set of classes it reaches through a typed global. A class
    doing `g_T->field` dereferences T, a dependency the `this`-field refs miss; this is
    the edge that makes singleton keystones rank in the unlock triage and invalidate in
    the dirty-tracking. Precomputed once over typed /types.h-pointer globals."""
    from ghidra.program.model.data import Pointer, Structure
    func_globals = {}
    gcount = 0
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        t = d.getDataType()
        if not isinstance(t, Pointer):
            continue
        base = t.getDataType()
        if not (isinstance(base, Structure) and 'types.h' in str(base.getCategoryPath())):
            continue
        gcls = base.getName()
        gcount += 1
        for ref in rm.getReferencesTo(d.getAddress()):
            fn = fm.getFunctionContaining(ref.getFromAddress())
            if fn is not None:
                func_globals.setdefault(fn.getEntryPoint().getOffset(), set()).add(gcls)
    print('Global-edge refs: %d typed globals -> %d functions carry a global dependency.'
          % (gcount, len(func_globals)))
    return func_globals


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.decompiler.util import FillOutStructureHelper
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()

    unk_by_class, struct_by_class = _harvest_surface(dtm)
    by_class = _function_pool(fm, unk_by_class)
    func_globals = _global_edge_map(fm, cp.getListing(), cp.getReferenceManager())

    dt_before = dtm.getDataTypeCount(True)
    decomp = DecompInterface()
    decomp.openProgram(cp)
    helper = FillOutStructureHelper(cp, monitor)  # noqa: F821

    observations = []
    dt_by_typename = {}                  # inferred typename -> its live DataType
    evidence = {}                        # (cls, offset) -> [observing function names]
    mined_state = {}                     # cls -> {'refs': [base type names it derefs]}
    classes_done = funcs_done = 0
    total_classes = min(len(by_class), MAX_CLASSES) if MAX_CLASSES else len(by_class)
    per = 'ALL' if PER_CLASS <= 0 else str(PER_CLASS)
    print('Discovery: %d structs have unknown fields; %d have functions to mine '
          '(per-class=%s, callee-follow=%s).'
          % (len(unk_by_class), len(by_class), per, FOLLOW))
    for cl, fns in by_class.items():
        if MAX_CLASSES and classes_done >= MAX_CLASSES:
            break
        classes_done += 1
        if classes_done % 25 == 0 or classes_done == total_classes:
            monitor.setMessage('discover %d/%d classes, %d fields' % (  # noqa: F821
                classes_done, total_classes, len(observations)))
            print('  [%d/%d classes] functions=%d observations=%d'
                  % (classes_done, total_classes, funcs_done, len(observations)))
        offs = unk_by_class[cl]
        cls_observed = set()                 # offsets seen this class -> early-exit
        cls_refs = mined_state.setdefault(cl, {'refs': []})['refs']
        # global-edge: every typed-global class any of this class's methods reaches is a
        # dependency (ungated by early-exit -- this is graph data, not field mining).
        for f0, _pi in fns:
            for gcls in func_globals.get(f0.getEntryPoint().getOffset(), ()):
                if gcls != cl and gcls not in cls_refs:
                    cls_refs.append(gcls)
        for f, pidx in (fns if PER_CLASS <= 0 else fns[:PER_CLASS]):
            # Per-class early-exit: once every unknown offset has been observed, more
            # methods of this class can only re-observe the same fields -- stop mining
            # it. Full recall (we have all offsets), strictly less decompilation.
            if cls_observed.issuperset(offs):
                break
            try:
                r = decomp.decompileFunction(f, 45, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                lsm = r.getHighFunction().getLocalSymbolMap()
                if lsm.getNumParams() <= pidx:
                    continue
                hv = lsm.getParamSymbol(pidx).getHighVariable()
                if hv is None:
                    continue
                # createNewStructure=TRUE: build a THROWAWAY structure from the
                # dataflow and return it to read. With False the helper fills out the
                # variable's EXISTING type IN PLACE -- which silently GREW live
                # /types.h structs during mining (it doubled MapMenu 0x30560->0x60880,
                # undetected because no new *type* is created). True keeps mining
                # truly read-only.
                st = helper.processStructure(hv, f, True, FOLLOW, decomp)
                if st is None:
                    continue
                funcs_done += 1
                for c in st.getComponents():
                    tn = c.getDataType().getName()
                    if not _useful(tn):
                        continue
                    # refs: EVERY class type this method dereferences through `this`,
                    # at ANY offset (not only the unknown ones). This is the dependency
                    # edge the incremental cycle invalidates on and the unlock-surface
                    # triage scores -- capturing all of them (a) fixes an
                    # under-invalidation soundness gap (a class that derefs T at a
                    # KNOWN offset still must re-mine when T's layout improves) and
                    # (b) densifies the graph so transitive unlock is meaningful.
                    bt = ip.base_type(tn)
                    if bt and bt not in cls_refs:
                        cls_refs.append(bt)
                    if c.getOffset() in offs:
                        observations.append((cl, c.getOffset(), tn))
                        cls_observed.add(c.getOffset())
                        dt_by_typename.setdefault(tn, c.getDataType())
                        ev = evidence.setdefault((cl, c.getOffset()), [])
                        if f.getName() not in ev and len(ev) < 6:
                            ev.append(f.getName())   # who saw it -> reviewer's leads
            except Exception:
                continue
    decomp.dispose()

    aggregated = dp.aggregate_inferences(observations)
    rows = dp.to_rows(aggregated, lambda c, o: unk_by_class.get(c, {}).get(o, ''))
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'current_name', 'inferred_type',
                    'confidence', 'votes', 'total_observations', 'observed_in'])
        for cls, off, cur, typ, conf, votes, total in rows:
            # observed_in: the functions whose dataflow revealed this field -- the
            # use-site provenance. Kept for EVERY field (not just the review queue), so
            # a later semantic-naming pass can jump straight to a witness function
            # instead of re-hunting construction sites.
            w.writerow([cls, '0x%X' % off, cur, typ, conf, votes, total,
                        ' '.join(evidence.get((cls, off), [])[:6])])

    # Optional LLM-review queue: fields the decompiler is sure EXIST (consensus
    # across functions) but could only size, not name. These are exactly the
    # auto-skipped `generic-size-only` cases -- a ranked worklist for a human/LLM to
    # assign a type, applied authoritatively by apply_review.py. Strongest evidence
    # first; `decision_type` is blank for the reviewer to fill. (Named fields are
    # auto-applied; single weak observations are left for more discovery first.)
    review = []
    for (cls, off), info in aggregated.items():
        worthy, _why = rp.is_review_worthy(info['named'], info['total'], info['votes'])
        if worthy:
            review.append((cls, off, info))
    review.sort(key=lambda r: rp.review_rank(r[2]['total'], r[2]['votes']), reverse=True)
    review_n = 0
    try:
        with open(REVIEW_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['class', 'offset', 'current_name', 'size_only_guess',
                        'votes', 'total_observations', 'observed_in', 'decision_type'])
            for cls, off, info in review:
                w.writerow([cls, '0x%X' % off,
                            unk_by_class.get(cls, {}).get(off, ''), info['type'],
                            info['votes'], info['total'],
                            ' '.join(evidence.get((cls, off), [])[:6]), ''])
                review_n += 1
    except Exception as e:
        print('  (review queue write failed: %s)' % e)

    # APPLY: write high-confidence named fields into the /types.h structs so the next
    # cycle propagates from them (shared improve-or-nop apply; never grows or clobbers).
    applied, apply_skips, changed_classes, apply_samples = fa.apply_fields(
        cp, dtm, struct_by_class, dt_by_typename, aggregated, 'clvr-discovered', APPLY)

    high = sum(1 for r in rows if r[4] == 'high')
    named = sum(1 for r in rows if r[3] not in dp.GENERIC_TYPES)
    classes_with_hits = len({r[0] for r in rows})
    per_class = collections.Counter(r[0] for r in rows)
    dt_after = dtm.getDataTypeCount(True)
    print('\n=== Discovery summary (%s) ===' % cp.getName())
    print('  classes mined=%d  functions analyzed=%d' % (classes_done, funcs_done))
    print('  candidate fields=%d  (high-confidence=%d, named-type=%d, size-only=%d)'
          % (len(rows), high, named, len(rows) - named))
    print('  classes with >=1 discovery=%d / %d unknown-bearing'
          % (classes_with_hits, len(unk_by_class)))
    print('  top classes by yield: %s'
          % ', '.join('%s(%d)' % (c, n) for c, n in per_class.most_common(6)))
    if APPLY:
        print('  APPLIED %d fields into /types.h structs   skips=%s'
              % (applied, dict(apply_skips)))
        for s in apply_samples:
            print('     ' + s)
    else:
        print('  READ-ONLY (CLVR_DISCOVER_APPLY=go to write fields into structs)')
    print('  data-type count %d -> %d (%s; apply only retypes fields, never creates)'
          % (dt_before, dt_after, 'unchanged' if dt_before == dt_after else 'CHANGED'))
    print('  -> ' + OUT_CSV)
    print('  LLM-review queue: %d size-only-consensus fields need a type'
          ' (fill decision_type, then apply_review.py) -> %s' % (review_n, REVIEW_CSV))

    # Persist incremental state for the orchestrator: merge this pass's per-class refs
    # into the prior state (carrying forward classes a warm pass skipped), and record
    # the structs we changed so the next pass can compute its dirty set. Best-effort --
    # a write failure just forces the next pass to run cold.
    try:
        prior = {}
        if os.path.exists(STATE_JSON):
            with open(STATE_JSON) as fh:
                prior = (json.load(fh) or {}).get('classes', {})
        merged = ip.merge_state(prior, mined_state)
        with open(STATE_JSON, 'w') as fh:
            json.dump({'version': 1, 'classes': merged}, fh)
        with open(CHANGED_JSON, 'w') as fh:
            json.dump({'changed': sorted(changed_classes)}, fh)
        print('  incremental state: %d classes tracked, %d changed this pass -> %s'
              % (len(merged), len(changed_classes), STATE_JSON))
    except Exception as e:
        print('  (incremental state write failed: %s -- next pass runs cold)' % e)


run()
