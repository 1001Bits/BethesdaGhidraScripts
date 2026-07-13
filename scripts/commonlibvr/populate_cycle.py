"""In-Ghidra population cycle orchestrator (the convergence driver).

Closes the loop WITHOUT leaving Ghidra. Each cycle runs three enrich stages in
order and the output of each is an anchor for the next:

  1. thiscall  (seed_this.py)        -- widen the typed-`this` surface
  2. propagate (propagate.py)        -- commit concrete param/return types the
                                        decompiler infers from those anchors
  3. discover+apply (commonlib_discover.py, CLVR_DISCOVER_APPLY=go)
                                     -- infer struct-field types via dataflow and
                                        WRITE the high-confidence ones into the
                                        /types.h structs

A field typed in cycle N is a new anchor the decompiler propagates from in cycle
N+1, so coverage compounds. Between cycles we snapshot four coverage metrics and
stop when a pass yields fewer than MIN_GAIN net improvements -- the practical
fixpoint. Export back to CommonLib is deliberately OUT OF SCOPE here: this drives
the live Ghidra program to a stable, maximally-populated state first.

Coverage metrics (populate_plan): thiscall members, concrete-named /types.h fields
(up), still-unknown /types.h fields (down), concrete-typed function params (up).

Modes:
  dry (default)  -- measure current coverage once and print the snapshot; no work.
  CLVR_CYCLE=go  -- run the apply loop to convergence.

Each sub-stage stays non-destructive (ANALYSIS source, protect IMPORTED/
USER_DEFINED, one always-committed transaction -- never commit=False). Knobs:
CLVR_CYCLE_MAX (cycles, default 5), CLVR_CYCLE_MIN_GAIN (default 5), plus every
sub-stage's own env (CLVR_PROP_SEED, CLVR_DISCOVER_PER_CLASS, ...) passes through.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
APPLY = os.environ.get('CLVR_CYCLE', 'dry').lower() == 'go'
MAX_CYCLES = int(os.environ.get('CLVR_CYCLE_MAX', '5') or 5)
MIN_GAIN = int(os.environ.get('CLVR_CYCLE_MIN_GAIN', '5') or 5)
COVERAGE_CSV = os.environ.get('CLVR_CYCLE_CSV', IMPORT_PATH + '.coverage.csv')

import json  # noqa: E402
import importlib.util as _ilu  # noqa: E402
_pspec = _ilu.spec_from_file_location('clvr_populate_plan', os.path.join(SCRIPT_DIR, 'populate_plan.py'))
pl = _ilu.module_from_spec(_pspec)
_pspec.loader.exec_module(pl)
_ispec = _ilu.spec_from_file_location('clvr_discover_incremental_plan',
                                      os.path.join(SCRIPT_DIR, 'discover_incremental_plan.py'))
ip = _ilu.module_from_spec(_ispec)
_ispec.loader.exec_module(ip)

# Incremental-discovery sidecars (written by commonlib_discover.py, read here to
# decide the next cycle's dirty set). The dirty file is what we HAND BACK to the next
# discover pass.
DISCOVER_STATE = IMPORT_PATH + '.discover_state.json'
DISCOVER_CHANGED = IMPORT_PATH + '.discover_changed.json'
DISCOVER_DIRTY = IMPORT_PATH + '.discover_dirty.txt'


def _plan_next_discover_dirty(sig_changed):
    """After a cycle's discover stage, decide what the NEXT cycle's discover should
    re-mine. Returns the dirty-file path to set as CLVR_DISCOVER_DIRTY, or '' for a
    full (cold) pass. Cold whenever a signature-changing stage (thiscall/propagate) ran
    this cycle -- that path isn't captured by the struct-deref dependency model -- or
    when compute_dirty says cold/many-changed."""
    if sig_changed:
        return ''                              # callee-sig path live -> mine everything
    try:
        with open(DISCOVER_STATE) as fh:
            classes = (json.load(fh) or {}).get('classes', {})
        with open(DISCOVER_CHANGED) as fh:
            changed = set((json.load(fh) or {}).get('changed', []))
    except Exception:
        return ''                              # missing sidecar -> safe cold pass
    dirty, reason = ip.compute_dirty(classes, changed)
    if dirty is None:
        print('  next discover: COLD (%s)' % reason)
        return ''
    if not dirty:
        print('  next discover: nothing dirty (%s) -- discover will no-op' % reason)
    with open(DISCOVER_DIRTY, 'w') as fh:
        fh.write('\n'.join(sorted(dirty)))
    print('  next discover: %d dirty classes (%s) -> %s'
          % (len(dirty), reason, DISCOVER_DIRTY))
    return DISCOVER_DIRTY


def _concrete(typename):
    """True if a type names real RE (struct/class/enum), not a size-only generic."""
    t = (typename or '').replace(' ', '')
    while t.endswith('*') or t.endswith('64'):
        t = t[:-2] if t.endswith('64') else t[:-1]
    if not t:
        return False
    low = t.lower()
    if low.startswith('undefined'):
        return False
    return not pl.is_generic_type(low)


def measure_coverage(cp):
    """Snapshot the four coverage metrics from the live program (no decompile --
    cheap; safe to call any time, including dry-run).

    Struct coverage is in BYTES, not component count: carving a typed field out of a
    larger `undefined` run fragments the remainder into more components, so a count
    rises even when RE was added. Bytes are conserved -- the only robust signal."""
    from ghidra.program.model.symbol import SymbolType
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()
    dtm = cp.getDataTypeManager()
    thiscall = typed_params = 0
    for f in fm.getFunctions(True):
        p = f.getParentNamespace()
        is_cls = (p is not gns and p.getSymbol() is not None
                  and p.getSymbol().getSymbolType() == SymbolType.CLASS)
        if is_cls and f.getCallingConventionName() == '__thiscall':
            thiscall += 1
        for prm in f.getParameters():
            if _concrete(prm.getDataType().getName()):
                typed_params += 1
    named_field_bytes = unk_field_bytes = 0
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if 'types.h' not in str(dt.getCategoryPath()):
            continue
        for i in range(dt.getNumComponents()):
            c = dt.getComponent(i)
            fn = c.getFieldName() or ''
            tn = c.getDataType().getName()
            if fn.startswith(('unk', 'pad')) or 'undefined' in tn:
                unk_field_bytes += c.getLength()
            elif _concrete(tn):
                named_field_bytes += c.getLength()
    return {'thiscall': thiscall, 'named_field_bytes': named_field_bytes,
            'unk_field_bytes': unk_field_bytes, 'typed_params': typed_params}


def _run_stage(name, env, cp, monitor):
    """exec a sub-stage script with its apply env set, sharing this program."""
    for k, v in env.items():
        os.environ[k] = v
    path = os.path.join(SCRIPT_DIR, name)
    g = dict(globals())
    g['__name__'] = '__main__'
    g['currentProgram'] = cp
    g['monitor'] = monitor
    with open(path) as fh:
        code = fh.read()
    print('\n----- stage: %s -----' % name)
    exec(compile(code, path, 'exec'), g)


def run():
    cp = currentProgram  # noqa: F821
    mon = monitor        # noqa: F821

    snapshots = []
    base = measure_coverage(cp)
    snapshots.append((0, base, None))
    print('=== population cycle (%s) ===' % cp.getName())
    print('  cycle 0 (baseline): %s' % base)

    if not APPLY:
        print('\nDRY: coverage snapshot only. Set CLVR_CYCLE=go to run the apply '
              'loop (thiscall -> propagate -> discover+apply) to convergence.')
    else:
        # Stages in order. thiscall and propagate converge in cycle 1 (nothing left
        # to convert / no new concrete params); only discover keeps compounding. So
        # measure coverage after EACH stage and, once a stage moves no metric, mark
        # it done and skip it in later cycles -- this avoids re-decompiling propagate's
        # whole seed every cycle (on AE that is ~7800 functions / ~11 min for 0 gain).
        STAGES = [('seed_this.py', {'CLVR_SEED': 'go'}),
                  ('propagate.py', {'CLVR_PROP': 'go'}),
                  ('commonlib_discover.py', {'CLVR_DISCOVER_APPLY': 'go'})]
        active = {name: True for name, _ in STAGES}
        prev = base
        # Incremental discovery: cycle 1 is cold (no dirty file). After each cycle we
        # compute the next cycle's dirty class set from discover's sidecars. Clear any
        # stale dirty file so cycle 1 mines everything.
        next_dirty = ''
        try:
            if os.path.exists(DISCOVER_DIRTY):
                os.remove(DISCOVER_DIRTY)
        except Exception:
            pass
        for cyc in range(1, MAX_CYCLES + 1):
            print('\n########## CYCLE %d/%d ##########' % (cyc, MAX_CYCLES))
            cov = prev
            sig_changed = False              # did a thiscall/propagate stage move metrics?
            for name, env in STAGES:
                if not active[name]:
                    print('  (skip %s -- converged in an earlier cycle)' % name)
                    continue
                if name == 'commonlib_discover.py':
                    # hand the precomputed dirty set to discover (cold when '')
                    env = dict(env, CLVR_DISCOVER_DIRTY=next_dirty)
                _run_stage(name, env, cp, mon)
                after = measure_coverage(cp)
                stage_delta = pl.coverage_delta(cov, after)
                cov = after
                moved = any(v != 0 for v in stage_delta.values())
                if name != 'commonlib_discover.py' and moved:
                    sig_changed = True       # signatures changed -> next discover cold
                if all(v == 0 for v in stage_delta.values()):
                    active[name] = False
                    print('  --> %s changed nothing; marking converged (skip henceforth)'
                          % name)
            # decide what the next cycle's discover re-mines
            next_dirty = (_plan_next_discover_dirty(sig_changed)
                          if active['commonlib_discover.py'] else '')
            cur = cov
            delta = pl.coverage_delta(prev, cur)
            prog = pl.progress(delta)
            snapshots.append((cyc, cur, delta))
            print('\n  cycle %d coverage: %s' % (cyc, cur))
            print('  cycle %d delta:    %s  (progress=%d)' % (cyc, delta, prog))
            prev = cur
            if pl.is_regression(delta):
                print('  >>> REGRESSION (progress %d < 0): a stage made the program '
                      'WORSE by the metrics. Stopping for inspection -- NOT a fixpoint.'
                      % prog)
                break
            if not any(active.values()):
                print('  >>> CONVERGED: every stage is a no-op after %d cycles' % cyc)
                break
            if pl.is_converged(delta, MIN_GAIN):
                print('  >>> CONVERGED (0 <= progress %d < min_gain %d) after %d cycles'
                      % (prog, MIN_GAIN, cyc))
                break
        else:
            print('  >>> reached MAX_CYCLES=%d without full convergence' % MAX_CYCLES)

    try:
        with open(COVERAGE_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['cycle', 'thiscall', 'named_field_bytes', 'unk_field_bytes',
                        'typed_params', 'd_thiscall', 'd_named_field_bytes',
                        'd_unk_field_bytes', 'd_typed_params', 'progress'])
            for cyc, snap, delta in snapshots:
                d = delta or {}
                w.writerow([cyc, snap['thiscall'], snap['named_field_bytes'],
                            snap['unk_field_bytes'], snap['typed_params'],
                            d.get('thiscall', ''), d.get('named_field_bytes', ''),
                            d.get('unk_field_bytes', ''), d.get('typed_params', ''),
                            pl.progress(d) if delta else ''])
        print('\n  coverage trace -> %s' % COVERAGE_CSV)
    except Exception as e:
        print('  (coverage CSV write failed: %s)' % e)


run()
