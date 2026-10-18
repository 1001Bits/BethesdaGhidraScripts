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
written to a review CSV.  Read-only: proposes, never writes.  The CSV is
replaced atomically and only by a healthy run: a decompiler that does not
start, or fails (almost) every function, raises and leaves the previous
evidence in place.

Knobs (env):
  BGS_GLOBALS_CSV        output path (default: refs/globals_evidence_<folder>_<prog>.csv)
  BGS_GLOBALS_SCOPE      data|class|all (default data -- only functions that
                         reference a high-in-degree untyped global)
  BGS_GLOBALS_MAX_FUNCS  cap functions decompiled (0 = all)
  BGS_GLOBALS_MIN_INDEG  min distinct referrers for a data-scope global (default 8)
  BGS_GLOBALS_SAMPLES    referrers sampled per candidate global (default 4)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import globals_plan as gp  # noqa: E402
from evidence_identity import bind_evidence  # noqa: E402
from review_queue import (GLOBALS, open_decompiler, queue_paths,  # noqa: E402
                          require_decompile_health, write_csv_atomically)

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
        # ``isAddress`` means the varnode is STORED in memory: its value is the
        # content of that global, i.e. the global is a pointer slot.
        a = vn.getAddress()
        return ((a, True) if (a.isMemoryAddress() and
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
        if (op == pc.PTRSUB and d.getInput(0).isConstant() and
                int(d.getInput(0).getOffset()) == 0):
            # The decompiler renders ``&global`` as PTRSUB(const 0, const VA):
            # input 0 is the RAM space base, never an image address.
            return _ram_addr(d.getInput(1), mem, addr_space, depth + 1, pc,
                             image_start, image_end)
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


def _entry_offset(function):
    return int(function.getEntryPoint().getOffset())


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import SymbolType
    cp = currentProgram  # noqa: F821
    from target_pe import driver_target_manifest
    # BGS_TARGET_PE (launcher-verified) or the recorded import path; either
    # way the file is identity-verified against the Program here.
    backing_manifest = driver_target_manifest(cp)
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    addr_space = cp.getAddressFactory().getDefaultAddressSpace()
    listing = cp.getListing()
    gns = cp.getGlobalNamespace()
    image_start = int(backing_manifest['image_base'])
    image_end = image_start + int(backing_manifest['image_size'])

    # The same path the launchers and globals_apply use (BGS_GLOBALS_CSV wins).
    out_csv = queue_paths(GLOBALS, cp)[0]

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
        # JPype hands out a fresh wrapper per call: ``p is not gns`` is True
        # even for the global namespace itself.  Ask Ghidra instead.
        return (p is not None and not p.isGlobal() and p != gns
                and p.getSymbol() is not None
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
        # Deterministic sample: a set of Java objects has no stable order, so
        # ``list(set)[:N]`` mined different evidence on every run.
        for g in sorted(cand):
            for f in sorted(refs_by_g[g], key=_entry_offset)[:SAMPLES]:
                sampled.add(f)
        print('  data-scope: %d refs scanned, %d untyped globals, %d with '
              'in-degree>=%d -> %d funcs to decompile'
              % (scanned, len(refs_by_g), len(cand), MIN_INDEG, len(sampled)))
        return sorted(sampled, key=_entry_offset), cand

    cand_globals = None
    if SCOPE == 'all':
        funcs = list(fm.getFunctions(True))
    elif SCOPE == 'class':
        funcs = [f for f in fm.getFunctions(True) if _is_class_method(f)]
    else:
        funcs, cand_globals = _data_scoped_funcs()

    decomp = DecompInterface()
    try:
        open_decompiler(decomp, cp, 'globals-harvest')
    except Exception:
        decomp.dispose()
        raise
    observations = []
    ptr_votes = {}
    n = done = failed = 0
    failures = []
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
                failed += 1
                if len(failures) < 5:
                    failures.append('%s: %s' % (
                        f.getName(), r.getErrorMessage() if r else 'no result'))
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
        except Exception as exc:  # noqa: BLE001  (one bad function, not the pass)
            failed += 1
            if len(failures) < 5:
                failures.append('%s: %s' % (f.getName(), exc))
            continue
    decomp.dispose()
    # Before anything is written: a broken decompiler must not replace the
    # last good evidence with an empty CSV (nor print the sentinel).
    require_decompile_health('globals-harvest', done, failed, failures)

    aggregated = gp.aggregate_global_types(observations)
    rows = gp.to_rows(aggregated)
    st = cp.getSymbolTable()
    out_rows = []
    for g, typ, conf, votes, total, distinct, classes_str, callers in rows:
        addr = addr_space.getAddress(g)
        sym = st.getPrimarySymbol(addr)
        cur = sym.getName() if sym is not None else ''
        pv = ptr_votes.get(g, [])
        is_ptr = sum(1 for b in pv if b) > len(pv) / 2.0
        out_rows.append(['0x%X' % g, cur, typ, '1' if is_ptr else '0', conf,
                         votes, total, distinct, classes_str, callers, ''])
    write_csv_atomically(
        out_csv, ['global_addr', 'current_symbol', 'inferred_type',
                  'is_pointer', 'confidence', 'votes', 'total',
                  'distinct_classes', 'class_votes', 'callers',
                  'decision_type'], out_rows)
    bind_evidence(out_csv, cp, 'globals_evidence', address_coordinate='VA')

    high = sum(1 for r in rows if r[2] == 'high')
    med = sum(1 for r in rows if r[2] == 'medium')
    print('\n=== Globals harvest summary (%s) ===' % cp.getName())
    print('  functions scanned=%d  global-as-this observations=%d' % (done, n))
    if failed:
        print('  %d of %d decompile(s) failed (first: %s)'
              % (failed, done, '; '.join(failures[:3])))
    print('  candidate globals=%d  (high=%d, medium=%d, low=%d)'
          % (len(rows), high, med, len(rows) - high - med))
    for g, typ, conf, votes, total, distinct, classes_str, callers in rows[:15]:
        print('   0x%X -> %s* [%s] votes=%d/%d  %s'
              % (g, typ, conf, votes, total, classes_str))
    print('  -> ' + out_csv)


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('globals_harvest'))
