"""Call-graph type-propagation fixpoint (the "heart" the seeders feed).

The thiscall seeder gave ~10k functions a typed `this`; CommonLib gave thousands
more an authoritative signature. This driver lets those anchors radiate: it
decompiles a function, reads the types the decompiler's dataflow inferred for its
parameters/return, and -- where the decompiler found a CONCRETE NAMED type
(struct/class pointer) for a slot the DB still has as generic -- commits just that
slot. A committed function's neighbours (callers and callees) are re-enqueued
because the new type can now flow one edge further. Iterate to an empty worklist
(fixpoint) or MAX_ROUNDS.

WHY FILTERED + SURGICAL, not HighFunctionDBUtil.commitParamsToDatabase (measured):
the decompiler's whole-prototype commit is net-negative on this codebase -- it
proposes `void` returns (clobbering honest `undefined`) and `longlong` params
(false precision) far more than real struct pointers, and it is all-or-nothing per
function. So we apply ONLY safe_refinement() slots (generic -> concrete named) via
Parameter.setDataType / Function.setReturnType, leaving honest unknowns and existing
RE untouched. Decision logic + the empirical rationale live in propagate_plan.py
(unit-tested).

NON-DESTRUCTIVE / TRANSACTIONS: the Ghidra MCP wraps each eval in its own outer
transaction, and Ghidra rolls back the whole group if any nested transaction ends
with commit=False. So this NEVER ends a transaction with commit=False: dry-run
mutates nothing (it only decompiles, classifies, and writes a CSV), and apply opens
ONE transaction that is always committed. Protected signatures (IMPORTED PDB,
USER_DEFINED human/CommonLib) are never written. Seeds use SourceType.ANALYSIS so a
human edit / CommonLib re-import outranks them. Dry-run by default; CLVR_PROP=go to
apply.

Knobs (env): CLVR_PROP (go to apply), CLVR_PROP_MAX_ROUNDS (default 6),
CLVR_PROP_TIMEOUT (decompile seconds/func, default 30), CLVR_PROP_APPLY_CAP
(max commits per function across the run, default 2, prevents oscillation),
CLVR_PROP_SEED ('class' = only class-namespace functions seed the worklist
[default, highest yield]; 'all' = every non-protected function), CLVR_PROP_CSV.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
APPLY = os.environ.get('CLVR_PROP', 'dry').lower() == 'go'
MAX_ROUNDS = int(os.environ.get('CLVR_PROP_MAX_ROUNDS', '6') or 6)
TIMEOUT = int(os.environ.get('CLVR_PROP_TIMEOUT', '30') or 30)
APPLY_CAP = int(os.environ.get('CLVR_PROP_APPLY_CAP', '2') or 2)
SEED = os.environ.get('CLVR_PROP_SEED', 'class').lower()
OUT_CSV = os.environ.get('CLVR_PROP_CSV', IMPORT_PATH + '.propagated.csv')

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_propagate_plan', os.path.join(SCRIPT_DIR, 'propagate_plan.py'))
pp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(pp)


def _srcname(f):
    s = f.getSignatureSource()
    return s.name() if hasattr(s, 'name') else str(s)


def run():
    from ghidra.program.model.symbol import SymbolType, SourceType
    from ghidra.app.decompiler import DecompInterface
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()

    def is_class(f):
        p = f.getParentNamespace()
        return (p is not gns and p.getSymbol() is not None
                and p.getSymbol().getSymbolType() == SymbolType.CLASS)

    def eligible(f):
        return not (f.isThunk() or f.isExternal() or pp.is_protected(_srcname(f)))

    # Seed worklist. 'class' seeds only class-namespace methods (where the typed
    # `this` makes a concrete-pointer gain plausible -- measured ~30x the global
    # FUN_* hit rate); 'all' seeds every eligible function.
    seed = []
    for f in fm.getFunctions(True):
        if not eligible(f):
            continue
        if SEED == 'class' and not is_class(f):
            continue
        seed.append(f.getEntryPoint())

    decomp = DecompInterface()
    decomp.openProgram(cp)

    applied_count = {}      # entrypoint -> times committed (oscillation cap)
    proposals = []          # (func, slot, old, new) for the CSV / dry-run report
    total_slots = 0
    rounds_done = 0

    def neighbours(f):
        out = set()
        try:
            for g in f.getCallingFunctions(monitor):  # noqa: F821
                if eligible(g):
                    out.add(g.getEntryPoint())
            for g in f.getCalledFunctions(monitor):    # noqa: F821
                if eligible(g):
                    out.add(g.getEntryPoint())
        except Exception:
            pass
        return out

    def refine(f):
        """Decompile f; return list of (slot, old, new, apply_thunk). Applies are
        deferred to the caller so dry-run can skip them. slot is 'ret' or 'pN'."""
        res = []
        r = decomp.decompileFunction(f, TIMEOUT, monitor)  # noqa: F821
        if not (r and r.decompileCompleted()):
            return res
        proto = r.getHighFunction().getFunctionPrototype()
        if proto is None:
            return res
        # return type
        pr = proto.getReturnType()
        old_ret = f.getReturnType().getName()
        if pr is not None and pp.safe_refinement(old_ret, pr.getName()):
            res.append(('ret', old_ret, pr.getName(),
                        lambda dt=pr: f.setReturnType(dt, SourceType.ANALYSIS)))
        # parameters
        params = f.getParameters()
        for i in range(min(proto.getNumParams(), len(params))):
            old = params[i].getDataType().getName()
            ndt = proto.getParam(i).getDataType()
            if pp.safe_refinement(old, ndt.getName()):
                res.append(('p%d' % i, old, ndt.getName(),
                            (lambda idx=i, dt=ndt: params[idx].setDataType(dt, SourceType.ANALYSIS))))
        return res

    worklist = list(dict.fromkeys(seed))   # de-dup, preserve order
    # Apply opens ONE transaction, always committed (a nested commit=False would
    # poison the MCP's outer transaction and discard the whole run). Dry-run opens
    # none and mutates nothing.
    tx = cp.startTransaction('type-propagate') if APPLY else None
    try:
        while worklist and rounds_done < MAX_ROUNDS:
            rounds_done += 1
            nxt = set()
            changed_fns = 0
            round_slots = 0
            for ep in worklist:
                f = fm.getFunctionAt(ep)
                if f is None or not eligible(f):
                    continue
                if applied_count.get(ep, 0) >= APPLY_CAP:
                    continue
                refs = refine(f)
                if not refs:
                    continue
                # record proposals (dry-run report is the same set we would apply)
                for slot, old, new, _do in refs:
                    proposals.append((f.getParentNamespace().getName(), f.getName(), slot, old, new))
                round_slots += len(refs)
                if APPLY:
                    for _slot, _old, _new, do in refs:
                        try:
                            do()
                        except Exception:
                            pass
                    applied_count[ep] = applied_count.get(ep, 0) + 1
                    changed_fns += 1
                    nxt |= neighbours(f)        # the gain can now flow one edge out
            total_slots += round_slots
            print('  round %d: worklist=%d  refined-funcs=%d  slots=%d  next=%d'
                  % (rounds_done, len(worklist), changed_fns, round_slots, len(nxt)))
            if not APPLY:
                break                            # dry-run is a single pass (no fixpoint)
            # only revisit neighbours that haven't hit the apply cap
            worklist = [e for e in nxt if applied_count.get(e, 0) < APPLY_CAP]
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)          # always commit; never poison

    # write the proposal CSV (high-value, reviewable -- every row is a concrete
    # named-type gain over a generic slot)
    try:
        with open(OUT_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['class', 'function', 'slot', 'old_type', 'new_type'])
            for row in proposals:
                w.writerow(row)
    except Exception as e:
        print('  (csv write failed: %s)' % e)

    print('type-propagate (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN (no changes made)'))
    print('  seed=%s  seeded=%d  rounds=%d  concrete-slot-gains=%d  funcs-touched=%d'
          % (SEED, len(seed), rounds_done, total_slots, len(applied_count)))
    print('  -> %s' % OUT_CSV)
    for row in proposals[:20]:
        print('   %s::%s  %s  %s -> %s' % row)


run()
