"""Globals harvester (READ-ONLY): identify untyped global singletons by the class
whose methods they are passed to.

Engine singletons live in untyped global data (`DAT_*`, an `undefined8` slot). The
decompiler can't propagate field accesses through an untyped global, so a class only
reached via a global is invisible to commonlib_discover (which mines `this`-PARAMETER
methods). This finds those globals: when a global flows into a call as arg-0 (`this`)
and the callee's param-0 is a known class C, that global is very likely a `C *`.

It decompiles each function once (reusing the DecompInterface pattern), walks CALL
pcode ops, back-traces arg-0 to a global data address, and records (global, class,
caller). globals_plan aggregates to a per-global consensus type + confidence, written
to <import>.globals_queue.csv -- a review worklist (same accept-then-apply pattern as
the field review queue). Typing the global is left to review/apply (a later step);
this stage only proposes, and never writes.

Why it matters beyond naming: a typed global is (a) a new discovery anchor -- its
referencing functions become mineable -- and (b) a dependency edge the incremental
cycle currently can't see (a class can depend on another's layout THROUGH a global).

Read-only always. Knobs: CLVR_GLOBALS_SCOPE (data|class|all, default data -- decompile
only functions that reference an untyped data global, found via one cheap reference
pass), CLVR_GLOBALS_CSV (output), CLVR_GLOBALS_MAX_FUNCS (cap functions decompiled,
0 = all). Run programs SEQUENTIALLY (shared os.environ).
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
OUT_CSV = os.environ.get('CLVR_GLOBALS_CSV', IMPORT_PATH + '.globals_queue.csv')
MAX_FUNCS = int(os.environ.get('CLVR_GLOBALS_MAX_FUNCS', '0') or 0)
# Scan scope (CLVR_GLOBALS_SCOPE):
#   data  (default) -- GLOBALS-FIRST sampling. Singletons are untyped data globals with
#                      a HIGH in-degree (referenced by many functions: PlayerCharacter
#                      ~1246, TESDataHandler ~389), while one-off data globals are
#                      referenced once or twice. A cheap reference pass ranks untyped
#                      globals by in-degree, keeps those >= MIN_INDEG (a few hundred),
#                      and decompiles only a SAMPLE of each one's referrers -- enough
#                      for type consensus. This bounds work by (candidate globals x
#                      sample cap), NOT the caller set (singletons are referenced by
#                      tens of thousands of functions, so a function-scoped filter never
#                      shrinks).
#   class           -- all class-method functions (parent namespace is a CLASS).
#   all             -- every function.
SCOPE = os.environ.get('CLVR_GLOBALS_SCOPE', 'data').lower()
# data-scope tuning: min in-degree for an untyped global to be a singleton candidate,
# and how many of its referrers to sample for consensus.
MIN_INDEG = int(os.environ.get('CLVR_GLOBALS_MIN_INDEG', '15') or 15)
SAMPLES = int(os.environ.get('CLVR_GLOBALS_SAMPLES', '6') or 6)

import importlib.util as _ilu  # noqa: E402
_gpspec = _ilu.spec_from_file_location('clvr_globals_plan', os.path.join(SCRIPT_DIR, 'globals_plan.py'))
gp = _ilu.module_from_spec(_gpspec)
_gpspec.loader.exec_module(gp)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)


def _ram_addr(vn, mem, addr_space, depth=0):
    """Back-trace an arg varnode to the global data address it denotes -- the inline
    singleton's address (`&g`) or the pointer slot it was loaded from. None if it does
    not resolve to a data-section address within a few hops. Returns (addr, is_ptr):
    is_ptr is True when the value was LOADed from the address (the global is a pointer
    SLOT holding a `T *`), False when the address is the object itself (an INLINE
    singleton, type `T`). That distinction is what the apply step needs to choose
    between typing the global `T *` vs `T`."""
    from ghidra.program.model.pcode import PcodeOp
    if vn is None or depth > 4:
        return (None, False)
    if vn.isConstant():
        try:
            a = addr_space.getAddress(vn.getOffset())
        except Exception:
            return (None, False)
        return (a, False) if mem.contains(a) else (None, False)
    if vn.isAddress():
        a = vn.getAddress()
        return (a, False) if (a.isMemoryAddress() and mem.contains(a)) else (None, False)
    d = vn.getDef()
    if d is None:
        return (None, False)
    op = d.getOpcode()
    if op in (PcodeOp.CAST, PcodeOp.COPY, PcodeOp.PTRSUB, PcodeOp.PTRADD,
              PcodeOp.INT_ADD, PcodeOp.MULTIEQUAL):
        # MULTIEQUAL is a phi: following input-0 is a heuristic (one branch may not be
        # the global), but a wrong guess only adds a review-queue row a human rejects.
        return _ram_addr(d.getInput(0), mem, addr_space, depth + 1)
    if op == PcodeOp.LOAD:
        addr, _ = _ram_addr(d.getInput(1), mem, addr_space, depth + 1)
        return (addr, True)              # loaded FROM a global slot -> it holds a T *
    return (None, False)


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    addr_space = cp.getAddressFactory().getDefaultAddressSpace()

    listing = cp.getListing()

    # only globals in non-executable (data) memory are singleton candidates
    def _in_data(addr):
        blk = mem.getBlock(addr)
        return blk is not None and not blk.isExecute()

    def _is_untyped_data(addr):
        # a fillable global: raw-undefined (no data item) or an undefined* placeholder,
        # in data memory. A concrete-typed datum (string, typed pointer) is not a target.
        if not _in_data(addr):
            return False
        d = listing.getDefinedDataAt(addr)
        return d is None or d.getDataType().getName().startswith('undefined')

    from ghidra.program.model.symbol import SymbolType
    gns = cp.getGlobalNamespace()

    def _is_class_method(f):
        p = f.getParentNamespace()
        return (p is not gns and p.getSymbol() is not None
                and p.getSymbol().getSymbolType() == SymbolType.CLASS)

    def _data_scoped_funcs():
        # globals-first: rank untyped globals by in-degree (distinct referrers), keep
        # the high-in-degree singleton candidates, and sample a few referrers of each
        # to decompile. Returns (functions_to_decompile, candidate_global_offsets).
        rm = cp.getReferenceManager()
        refs_by_g = {}                       # gaddr offset -> set(function)
        scanned = 0
        it = rm.getReferenceIterator(mem.getMinAddress())
        while it.hasNext():
            ref = it.next()
            scanned += 1
            rt = ref.getReferenceType()
            if not rt.isData() or ref.isStackReference() or ref.isRegisterReference():
                continue
            to = ref.getToAddress()
            if not _is_untyped_data(to):
                continue
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is not None:
                refs_by_g.setdefault(to.getOffset(), set()).add(f)
        cand_globals = set(g for g, s in refs_by_g.items() if len(s) >= MIN_INDEG)
        sampled = set()
        for g in cand_globals:
            for f in list(refs_by_g[g])[:SAMPLES]:
                sampled.add(f)
        print('  data-scope: %d refs scanned, %d untyped globals, %d with in-degree>=%d, '
              'sampling<=%d referrers -> %d funcs to decompile'
              % (scanned, len(refs_by_g), len(cand_globals), MIN_INDEG, SAMPLES, len(sampled)))
        return list(sampled), cand_globals

    cand_globals = None                      # data-scope filters observations to these
    if SCOPE == 'all':
        funcs = list(fm.getFunctions(True))
    elif SCOPE == 'class':
        funcs = [f for f in fm.getFunctions(True) if _is_class_method(f)]
    else:                                    # 'data' (default)
        funcs, cand_globals = _data_scoped_funcs()

    decomp = DecompInterface()
    decomp.openProgram(cp)
    observations = []
    ptr_votes = {}                       # addr -> [is_ptr bools]; majority -> CSV column
    n = done = 0
    print('Globals harvest (%s): scope=%s, scanning %d functions for global-as-this ...'
          % (cp.getName(), SCOPE, len(funcs)))
    for f in funcs:
        if MAX_FUNCS and done >= MAX_FUNCS:
            break
        done += 1
        if done % 2000 == 0:
            monitor.setMessage('globals: %d funcs, %d obs' % (done, len(observations)))  # noqa: F821
            print('  ... %d funcs scanned, %d observations' % (done, len(observations)))
        try:
            r = decomp.decompileFunction(f, 30, monitor)  # noqa: F821
            if not (r and r.decompileCompleted()):
                continue
            hf = r.getHighFunction()
            for op in hf.getPcodeOps():
                if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 2:
                    continue
                target = op.getInput(0)
                if not target.isAddress():
                    continue
                callee = fm.getFunctionAt(target.getAddress())
                if callee is None:
                    continue
                cls = gu.param0_class_name(callee)
                if not cls:
                    continue
                gaddr, is_ptr = _ram_addr(op.getInput(1), mem, addr_space)
                if gaddr is None or not _in_data(gaddr):
                    continue
                # in data-scope, only the high-in-degree singleton candidates count
                if cand_globals is not None and gaddr.getOffset() not in cand_globals:
                    continue
                observations.append((gaddr.getOffset(), cls, f.getName()))
                ptr_votes.setdefault(gaddr.getOffset(), []).append(is_ptr)
                n += 1
        except Exception:
            continue
    decomp.dispose()

    aggregated = gp.aggregate_global_types(observations)
    rows = gp.to_rows(aggregated)
    st = cp.getSymbolTable()
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['global_addr', 'current_symbol', 'inferred_type', 'is_pointer',
                    'confidence', 'votes', 'total', 'distinct_classes', 'class_votes',
                    'callers', 'decision_type'])
        for g, typ, conf, votes, total, distinct, classes_str, callers in rows:
            addr = addr_space.getAddress(g)
            sym = st.getPrimarySymbol(addr)
            cur = sym.getName() if sym is not None else ''
            pv = ptr_votes.get(g, [])
            is_ptr = sum(1 for b in pv if b) > len(pv) / 2.0    # majority loaded-from
            w.writerow(['0x%X' % g, cur, typ, '1' if is_ptr else '0', conf, votes,
                        total, distinct, classes_str, callers, ''])

    high = sum(1 for r in rows if r[2] == 'high')
    med = sum(1 for r in rows if r[2] == 'medium')
    print('\n=== Globals harvest summary (%s) ===' % cp.getName())
    print('  functions scanned=%d  global-as-this observations=%d' % (done, n))
    print('  candidate globals=%d  (high=%d, medium=%d, low=%d)'
          % (len(rows), high, med, len(rows) - high - med))
    for g, typ, conf, votes, total, distinct, classes_str, callers in rows[:15]:
        print('   0x%X -> %s* [%s] votes=%d/%d  %s' % (g, typ, conf, votes, total, classes_str))
    print('  -> ' + OUT_CSV)
    print('  (read-only: review/fill decision_type, then apply to type the global)')


run()
