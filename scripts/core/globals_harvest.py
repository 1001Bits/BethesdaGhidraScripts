"""Ghidra driver: globals harvester (READ-ONLY) -- identify untyped global
singletons by the class whose methods they are passed to.
Technique adapted from alandtse's CommonLibVR fork.

Engine singletons live in untyped global data (``DAT_*``, an
``undefined8`` slot).  The decompiler can't propagate field accesses
through an untyped global, so a class reached only via a global is
invisible to constructor/this-parameter discovery.  When a global flows
into a call as arg-0 (``this``) and the callee's param-0 is a known
class C, that global is very likely a ``C *``.

This decompiles each in-scope function, walks CALL pcode ops, back-traces
arg-0 to a global data address, and records (global, class, caller).
globals_plan aggregates to a per-global consensus type + confidence,
written to a review CSV.  Read-only: proposes, never writes.

Knobs (env):
  BGS_GLOBALS_CSV        output path (default: refs/globals_queue_<prog>.csv)
  BGS_GLOBALS_SCOPE      data|class|all (default data -- only functions that
                         reference a high-in-degree untyped global)
  BGS_GLOBALS_MAX_FUNCS  cap functions decompiled (0 = all)
  BGS_GLOBALS_MIN_INDEG  min distinct referrers for a data-scope global (default 8)
  BGS_GLOBALS_SAMPLES    referrers sampled per candidate global (default 4)
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import globals_plan as gp  # noqa: E402
from evidence_identity import bind_evidence  # noqa: E402

SCOPE = os.environ.get('BGS_GLOBALS_SCOPE', 'data').lower()
MAX_FUNCS = int(os.environ.get('BGS_GLOBALS_MAX_FUNCS', '0') or 0)
MIN_INDEG = int(os.environ.get('BGS_GLOBALS_MIN_INDEG', '8') or 8)
SAMPLES = int(os.environ.get('BGS_GLOBALS_SAMPLES', '4') or 4)


def _param0_class_name(callee):
    """Class name of the callee's param-0 (the ``this`` type), but ONLY when
    param-0 is a pointer to an actual Structure (class).

    A name-string reject list is not enough: every Ghidra builtin
    (``longlong``, ``float``, ``bool``, ``uint64_t``, ``code *`` ...) would
    otherwise pass as a "class", giving an untyped global a bogus vote that
    inflates the competing-class count and demotes a genuinely consistent
    singleton to low confidence.  So we unwrap pointer levels and require
    the base to be a Structure.
    """
    from ghidra.program.model.data import Pointer, Structure
    ps = callee.getParameters()
    if not ps:
        return None
    dt = ps[0].getDataType()
    while isinstance(dt, Pointer):
        dt = dt.getDataType()
    if not isinstance(dt, Structure):
        return None
    return dt.getName()


def _signed_constant(vn):
    value = int(vn.getOffset())
    try:
        bits = int(vn.getSize()) * 8
    except Exception:
        bits = 64
    if bits > 0:
        # Java ``long`` may expose a 64-bit Varnode offset as already signed,
        # while narrower constants arrive zero-extended.  Normalize both
        # representations before sign extension so -16 is never adjusted a
        # second time to ``-(2**64)-16``.
        value &= (1 << bits) - 1
        if value & (1 << (bits - 1)):
            value -= 1 << bits
    return value


def _same_space(address, addr_space):
    try:
        return bool(address.getAddressSpace().equals(addr_space))
    except Exception:
        return address.getAddressSpace() == addr_space


def _valid_address(address, mem, addr_space, image_start, image_end):
    try:
        offset = int(address.getOffset())
    except Exception:
        return False
    return (_same_space(address, addr_space) and
            image_start <= offset < image_end and mem.contains(address))


def _ram_addr(vn, mem, addr_space, depth=0, pc=None,
              image_start=0, image_end=(1 << 64)):
    """Back-trace an arg varnode to the global data address it denotes.
    Returns (addr, is_ptr): is_ptr True when the value was LOADed from the
    address (the global is a pointer SLOT holding a ``T *``), False when the
    address is the object itself (an INLINE singleton, type ``T``)."""
    if pc is None:
        from ghidra.program.model.pcode import PcodeOp as pc
    if vn is None or depth > 7:
        return (None, False)
    if vn.isConstant():
        try:
            a = addr_space.getAddress(vn.getOffset())
        except Exception:
            return (None, False)
        return ((a, False) if _valid_address(
            a, mem, addr_space, image_start, image_end)
                else (None, False))
    if vn.isAddress():
        a = vn.getAddress()
        return ((a, False) if (a.isMemoryAddress() and
                               _valid_address(a, mem, addr_space,
                                              image_start, image_end))
                else (None, False))
    d = vn.getDef()
    if d is None:
        return (None, False)
    op = d.getOpcode()
    if op in (pc.CAST, pc.COPY):
        return _ram_addr(d.getInput(0), mem, addr_space, depth + 1, pc,
                         image_start, image_end)
    if op in (pc.PTRSUB, pc.INT_ADD):
        if d.getNumInputs() < 2 or not d.getInput(1).isConstant():
            return (None, False)
        addr, is_ptr = _ram_addr(
            d.getInput(0), mem, addr_space, depth + 1, pc,
            image_start, image_end)
        if addr is None:
            return (None, False)
        try:
            result = addr.add(_signed_constant(d.getInput(1)))
        except Exception:
            return (None, False)
        return ((result, is_ptr) if _valid_address(
            result, mem, addr_space, image_start, image_end)
                else (None, False))
    if op == pc.PTRADD:
        if (d.getNumInputs() < 3 or not d.getInput(1).isConstant() or
                not d.getInput(2).isConstant()):
            return (None, False)
        addr, is_ptr = _ram_addr(
            d.getInput(0), mem, addr_space, depth + 1, pc,
            image_start, image_end)
        if addr is None:
            return (None, False)
        delta = (_signed_constant(d.getInput(1)) *
                 _signed_constant(d.getInput(2)))
        try:
            result = addr.add(delta)
        except Exception:
            return (None, False)
        return ((result, is_ptr) if _valid_address(
            result, mem, addr_space, image_start, image_end)
                else (None, False))
    if op == pc.MULTIEQUAL:
        values = [_ram_addr(iv, mem, addr_space, depth + 1, pc,
                            image_start, image_end)
                  for iv in d.getInputs()]
        return values[0] if values and all(value == values[0] and
                                           value[0] is not None
                                           for value in values) else (None, False)
    if op == pc.LOAD:
        addr, _ = _ram_addr(
            d.getInput(1), mem, addr_space, depth + 1, pc,
            image_start, image_end)
        return (addr, True)
    return (None, False)


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import SymbolType
    cp = currentProgram  # noqa: F821
    from binary_identity import inspect_pe, verify_ghidra_program
    backing_manifest = inspect_pe(str(cp.getExecutablePath()))
    verify_ghidra_program(cp, [backing_manifest])
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    addr_space = cp.getAddressFactory().getDefaultAddressSpace()
    listing = cp.getListing()
    gns = cp.getGlobalNamespace()
    image_start = int(backing_manifest['image_base'])
    image_end = image_start + int(backing_manifest['image_size'])

    out_csv = os.environ.get('BGS_GLOBALS_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'globals_queue_%s.csv' % cp.getName().replace('.', '_'))

    def _in_data(addr):
        if not _valid_address(addr, mem, addr_space, image_start, image_end):
            return False
        blk = mem.getBlock(addr)
        return blk is not None and not blk.isExecute()

    def _is_untyped_data(addr):
        if not _in_data(addr):
            return False
        d = listing.getDefinedDataAt(addr)
        return d is None or d.getDataType().getName().startswith('undefined')

    def _is_class_method(f):
        p = f.getParentNamespace()
        return (p is not gns and p.getSymbol() is not None
                and p.getSymbol().getSymbolType() == SymbolType.CLASS)

    def _data_scoped_funcs():
        rm = cp.getReferenceManager()
        refs_by_g = {}
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
        cand = set(g for g, s in refs_by_g.items() if len(s) >= MIN_INDEG)
        sampled = set()
        for g in cand:
            for f in list(refs_by_g[g])[:SAMPLES]:
                sampled.add(f)
        print('  data-scope: %d refs scanned, %d untyped globals, %d with '
              'in-degree>=%d -> %d funcs to decompile'
              % (scanned, len(refs_by_g), len(cand), MIN_INDEG, len(sampled)))
        return list(sampled), cand

    cand_globals = None
    if SCOPE == 'all':
        funcs = list(fm.getFunctions(True))
    elif SCOPE == 'class':
        funcs = [f for f in fm.getFunctions(True) if _is_class_method(f)]
    else:
        funcs, cand_globals = _data_scoped_funcs()

    decomp = DecompInterface()
    decomp.openProgram(cp)
    observations = []
    ptr_votes = {}
    n = done = 0
    print('Globals harvest (%s): scope=%s, scanning %d functions ...'
          % (cp.getName(), SCOPE, len(funcs)))
    for f in funcs:
        if MAX_FUNCS and done >= MAX_FUNCS:
            break
        done += 1
        if done % 2000 == 0:
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
                cls = _param0_class_name(callee)
                if not cls:
                    continue
                gaddr, is_ptr = _ram_addr(
                    op.getInput(1), mem, addr_space,
                    image_start=image_start, image_end=image_end)
                if gaddr is None or not _in_data(gaddr):
                    continue
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
    if not os.path.isdir(os.path.dirname(out_csv)):
        os.makedirs(os.path.dirname(out_csv))
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['global_addr', 'current_symbol', 'inferred_type', 'is_pointer',
                    'confidence', 'votes', 'total', 'distinct_classes', 'class_votes',
                    'callers', 'decision_type'])
        for g, typ, conf, votes, total, distinct, classes_str, callers in rows:
            addr = addr_space.getAddress(g)
            sym = st.getPrimarySymbol(addr)
            cur = sym.getName() if sym is not None else ''
            pv = ptr_votes.get(g, [])
            is_ptr = sum(1 for b in pv if b) > len(pv) / 2.0
            w.writerow(['0x%X' % g, cur, typ, '1' if is_ptr else '0', conf, votes,
                        total, distinct, classes_str, callers, ''])
    bind_evidence(out_csv, cp, 'globals_evidence', address_coordinate='VA')

    high = sum(1 for r in rows if r[2] == 'high')
    med = sum(1 for r in rows if r[2] == 'medium')
    print('\n=== Globals harvest summary (%s) ===' % cp.getName())
    print('  functions scanned=%d  global-as-this observations=%d' % (done, n))
    print('  candidate globals=%d  (high=%d, medium=%d, low=%d)'
          % (len(rows), high, med, len(rows) - high - med))
    for g, typ, conf, votes, total, distinct, classes_str, callers in rows[:15]:
        print('   0x%X -> %s* [%s] votes=%d/%d  %s'
              % (g, typ, conf, votes, total, classes_str))
    print('  -> ' + out_csv)


if 'currentProgram' in globals():
    run()
