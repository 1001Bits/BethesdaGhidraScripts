"""Ghidra driver: constructor-mining field recovery (READ-ONLY).
Technique adapted from alandtse's CommonLibVR fork.

A class constructor assigns each member from a typed, named parameter
(``this->Object_18 = a_object``, ``a_object:TESBoundObject*``), so one
decompile yields a field's NAME and TYPE together -- far more reliable
than size-only dataflow guesses.

For each CommonLib/PDB struct with unknown fields (``unk*``/``pad*``/
``undefined*``) this finds its constructor (param-0 is the class, name
looks like a ctor), decompiles it, and reads ``this->field@offset =
a_param`` assignments out of the pcode.  Proposals -- (class, offset,
type, name) -- are written to a CSV, unknown-slot fillers first.

NON-DESTRUCTIVE: only decompiles + writes a CSV; never modifies the
program.  The CSV is replaced atomically and only by a healthy run: a
decompiler that does not start, or fails (almost) every function, raises and
leaves the previous evidence in place.  Knobs (env):
  BGS_CTOR_CSV          output path (default: <repo>/scripts/core/refs/ctor_fields_<folder>_<prog>.csv)
  BGS_CTOR_CATEGORY     only mine structs whose category path contains this
                        substring (default: empty = all structs)
  BGS_CTOR_MAX_CLASSES  cap classes mined (0 = all)
  BGS_CTOR_TIMEOUT      decompile seconds per function (default 45)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctor_plan as cp_plan  # noqa: E402
from evidence_identity import bind_evidence  # noqa: E402
from review_queue import (CTORS, open_decompiler, queue_paths,  # noqa: E402
                          require_decompile_health, write_csv_atomically)

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATEGORY = os.environ.get('BGS_CTOR_CATEGORY', '')
MAX_CLASSES = int(os.environ.get('BGS_CTOR_MAX_CLASSES', '0') or 0)
TIMEOUT = int(os.environ.get('BGS_CTOR_TIMEOUT', '45') or 45)


def _high_name(vn):
    h = vn.getHigh() if vn is not None else None
    return h.getName() if h is not None else None


def _signed_constant(vn):
    value = int(vn.getOffset())
    try:
        bits = int(vn.getSize()) * 8
    except Exception:
        bits = 64
    if bits > 0:
        # ``getOffset`` is a Java long: 64-bit negative constants can already
        # be negative, whereas narrower constants are commonly zero-extended.
        # Mask first so both forms receive exactly one sign extension.
        value &= (1 << bits) - 1
        if value & (1 << (bits - 1)):
            value -= 1 << bits
    return value


def _addr_off(vn, this_name, pc, depth=0):
    """Back-trace varnode ``vn`` to ``this + k``; return k or None.  Matches
    ``this`` by param NAME (Ghidra hands out distinct HighVariable objects
    for param-0 body instances, so identity comparison fails)."""
    if vn is None or depth > 7:
        return None
    if _high_name(vn) == this_name:
        return 0
    d = vn.getDef()
    if d is None:
        return None
    oc, ins = d.getOpcode(), d.getInputs()
    if oc in (pc.COPY, pc.CAST, pc.INDIRECT) and ins:
        return _addr_off(ins[0], this_name, pc, depth + 1)
    # PTRADD is pointer arithmetic base + index*elem_size: the BYTE offset is
    # ins[1] (index) * ins[2] (element size), NOT the raw index.  Using the
    # raw index yields offset/8 for 8-byte pointer fields (a pointer field
    # reported at +0x9 instead of +0x48).
    if oc == pc.PTRADD and len(ins) >= 3 and ins[1].isConstant() and ins[2].isConstant():
        s = _addr_off(ins[0], this_name, pc, depth + 1)
        if s is not None:
            return s + _signed_constant(ins[1]) * _signed_constant(ins[2])
    # PTRSUB / INT_ADD carry the byte offset directly in ins[1].
    if oc in (pc.INT_ADD, pc.PTRSUB) and len(ins) >= 2 and ins[1].isConstant():
        s = _addr_off(ins[0], this_name, pc, depth + 1)
        if s is not None:
            return s + _signed_constant(ins[1])
    return None


def _val_param(vn, param_names, pc, depth=0):
    """If ``vn`` (through copy/cast/phi) is one of the parameters by name,
    return its name; else None."""
    if vn is None or depth > 5:
        return None
    nm = _high_name(vn)
    if nm in param_names:
        return nm
    d = vn.getDef()
    if d is None:
        return None
    if d.getOpcode() in (pc.COPY, pc.CAST, pc.INDIRECT):
        inputs = list(d.getInputs())
        return (_val_param(inputs[0], param_names, pc, depth + 1)
                if inputs else None)
    if d.getOpcode() == pc.MULTIEQUAL:
        values = [_val_param(iv, param_names, pc, depth + 1)
                  for iv in d.getInputs()]
        if values and all(value is not None and value == values[0]
                          for value in values):
            return values[0]
    return None


def _ctor_assignments(hf, this_name):
    """{offset: (typename, param_name)} for ``this->field@off = a_param``."""
    from ghidra.program.model.pcode import PcodeOp
    lsm = hf.getLocalSymbolMap()
    param_type = {}
    for i in range(1, lsm.getNumParams()):
        ps = lsm.getParamSymbol(i)
        param_type[ps.getName()] = ps.getDataType().getName()
    out = {}
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.STORE:
            continue
        ins = op.getInputs()
        if len(ins) < 3:
            continue
        off = _addr_off(ins[1], this_name, PcodeOp)
        if off is None:
            continue
        pn = _val_param(ins[2], param_type, PcodeOp)
        if pn is None:
            continue
        out[off] = (param_type[pn], pn)
    return out


def _embedded_objects(hf, this_name, vtmap, fm, callee_class):
    """{offset: class_name} for ``CALL ctor_of_T(this+off, ...)`` -- the
    object at ``this+off`` is constructed by T's constructor, so field@off
    has type T.  This is the SF-appropriate signal: constructors there
    initialise members by calling sub-constructors rather than assigning
    typed parameters (which CommonLib hasn't typed yet).  off==0 is the
    base-class subobject (inheritance); off!=0 is an embedded member."""
    from ghidra.program.model.pcode import PcodeOp
    out = {}
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue
        ins = op.getInputs()
        if len(ins) < 2 or not ins[0].isAddress():
            continue
        off = _addr_off(ins[1], this_name, PcodeOp)   # arg0 (RCX) == this+off?
        if off is None or off in out:
            continue
        cf = fm.getFunctionAt(ins[0].getAddress())
        if cf is None:
            continue
        cc = callee_class(cf)
        if cc is not None:
            out[off] = cc
    return out


def _unk_offsets(dt):
    offs = set()
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        if fn.startswith(('unk', 'pad')) or 'undefined' in c.getDataType().getName():
            offs.add(c.getOffset())
    return offs


def _vtable_class_map(prog):
    """{vtable_address_offset: class_name} from VTABLE_<Class> symbols."""
    st = prog.getSymbolTable()
    out = {}
    it = st.getAllSymbols(False)
    while it.hasNext():
        sym = it.next()
        n = sym.getName()
        if n.startswith('VTABLE_'):
            out[sym.getAddress().getOffset()] = n[len('VTABLE_'):]
    return out


def _const_addr_off(vn, depth=0):
    """Resolve a varnode to a constant RAM address offset (the ``&VTABLE``
    target) through copy/cast/ptrsub.  None if not a constant address."""
    from ghidra.program.model.pcode import PcodeOp
    if vn is None or depth > 6:
        return None
    if vn.isConstant():
        return int(vn.getOffset())
    if vn.isAddress():
        return int(vn.getAddress().getOffset())
    d = vn.getDef()
    if d is None:
        return None
    oc, ins = d.getOpcode(), d.getInputs()
    if oc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT) and ins:
        return _const_addr_off(ins[0], depth + 1)
    if (oc == PcodeOp.PTRSUB and len(ins) >= 2
            and ins[0].isConstant() and ins[1].isConstant()):
        return int(ins[0].getOffset()) + int(ins[1].getOffset())
    return None


def pick_constructed_class(stored_classes, virtual):
    """Own class from the vtables written to ``this+0``, in address order.

    With an INLINED base, more than one vtable is stored.  A constructor
    writes base-first, so its own class is the LAST store; a destructor
    writes its own vtable first and the bases after it.  Constructors are
    never virtual, so a function that sits in a vtable is the destructor
    shape.  (The old "first store" rule attributed every such constructor's
    fields to its BASE class.)
    """
    ordered = []
    for cls in stored_classes:
        if not ordered or ordered[-1] != cls:
            ordered.append(cls)
    if not ordered:
        return None
    if len(set(ordered)) == 1:
        return ordered[0]
    return ordered[0] if virtual else ordered[-1]


def _this_vtable_stores(hf, this_name, vtmap):
    """Classes whose vtable is stored to ``this+0``, ordered by address."""
    from ghidra.program.model.pcode import PcodeOp
    stores = []
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.STORE:
            continue
        ins = op.getInputs()
        if len(ins) < 3:
            continue
        if _addr_off(ins[1], this_name, PcodeOp) != 0:
            continue
        v = _const_addr_off(ins[2])
        if v is not None and v in vtmap:
            seq = op.getSeqnum()
            stores.append((int(seq.getTarget().getOffset()),
                           int(seq.getTime()), vtmap[v]))
    stores.sort(key=lambda item: (item[0], item[1]))
    return [cls for _addr, _time, cls in stores]


def _is_vtable_referenced(prog, function):
    """True when a data slot (a vtable entry) points at the function."""
    memory = prog.getMemory()
    refs = prog.getReferenceManager().getReferencesTo(function.getEntryPoint())
    for ref in refs:
        if not ref.getReferenceType().isData():
            continue
        block = memory.getBlock(ref.getFromAddress())
        if block is not None and not block.isExecute():
            return True
    return False


def _constructed_class(hf, this_name, vtmap, virtual=False):
    """If the function stores a known vtable address to ``this+0``, return
    the class name (from vtmap).  Identifies a constructor STRUCTURALLY --
    a ctor writes its class vtable to offset 0 -- so it works regardless of
    whether the function carries a constructor-shaped NAME (ours don't)."""
    return pick_constructed_class(
        _this_vtable_stores(hf, this_name, vtmap), virtual)


def run():
    from ghidra.app.decompiler import DecompInterface
    prog = currentProgram  # noqa: F821
    dtm = prog.getDataTypeManager()
    fm = prog.getFunctionManager()

    # The same path the launchers and ctor_apply use (BGS_CTOR_CSV wins).
    out_csv = queue_paths(CTORS, prog)[0]

    unk_by_class = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if CATEGORY and CATEGORY not in str(dt.getCategoryPath()):
            continue
        offs = _unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs

    # Candidate constructors are found STRUCTURALLY, not by name: a ctor
    # references (and stores to this+0) its class's vtable.  Our binaries
    # don't carry constructor-shaped function names, so the name heuristic
    # (cp_plan.is_ctor) finds nothing -- the vtable cross-reference does.
    rm = prog.getReferenceManager()
    af = prog.getAddressFactory().getDefaultAddressSpace()
    vtmap = _vtable_class_map(prog)
    target_vt = {off: c for off, c in vtmap.items() if c in unk_by_class}

    cand_funcs = set()
    for off in target_vt:
        addr = af.getAddress(off)
        for ref in rm.getReferencesTo(addr):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is not None:
                cand_funcs.add(f)
    # Deterministic order: a set of Java objects has no stable iteration
    # order, so the MAX_CLASSES slice mined different functions every run.
    cand_list = sorted(cand_funcs,
                       key=lambda fn: int(fn.getEntryPoint().getOffset()))
    if MAX_CLASSES:
        cand_list = cand_list[:MAX_CLASSES * 6]

    decomp = DecompInterface()
    # second decompiler for callee-class resolution -- calling decompile on
    # the main interface again would invalidate the in-flight HighFunction.
    decomp2 = DecompInterface()
    try:
        open_decompiler(decomp, prog, 'ctor-mine')
        open_decompiler(decomp2, prog, 'ctor-mine (callee resolver)')
    except Exception:
        decomp.dispose()
        decomp2.dispose()
        raise
    ctor_class_memo = {}                     # callee entry -> class or None

    def callee_class(fn):
        ea = fn.getEntryPoint().getOffset()
        if ea in ctor_class_memo:
            return ctor_class_memo[ea]
        ctor_class_memo[ea] = None
        try:
            r2 = decomp2.decompileFunction(fn, TIMEOUT, monitor)  # noqa: F821
            if r2 and r2.decompileCompleted():
                hf2 = r2.getHighFunction()
                lsm2 = hf2.getLocalSymbolMap()
                if lsm2.getNumParams() >= 1:
                    ctor_class_memo[ea] = _constructed_class(
                        hf2, lsm2.getParamSymbol(0).getName(), vtmap,
                        virtual=_is_vtable_referenced(prog, fn))
        except Exception:
            pass
        return ctor_class_memo[ea]

    rows = []
    named = typed_unk = n_embed = 0
    attempted = failed = 0
    failures = []
    evidence_by_class = {}                  # cls -> [(function, assignments, embedded)]
    print('ctor-mine: %d unk-bearing structs, %d unk-class vtables, '
          '%d functions reference a target vtable'
          % (len(unk_by_class), len(target_vt), len(cand_list)))
    for f in cand_list:
        attempted += 1
        try:
            r = decomp.decompileFunction(f, TIMEOUT, monitor)  # noqa: F821
            if not (r and r.decompileCompleted()):
                failed += 1
                if len(failures) < 5:
                    failures.append('%s: %s' % (
                        f.getName(), r.getErrorMessage() if r else 'no result'))
                continue
            hf = r.getHighFunction()
            lsm = hf.getLocalSymbolMap()
            if lsm.getNumParams() < 1:
                continue
            this_name = lsm.getParamSymbol(0).getName()
            cls = _constructed_class(hf, this_name, vtmap,
                                     virtual=_is_vtable_referenced(prog, f))
            if cls is None or cls not in unk_by_class:
                continue
            asg = _ctor_assignments(hf, this_name)
            emb = _embedded_objects(hf, this_name, vtmap, fm, callee_class)
            if not asg and not emb:         # destructors / no usable info
                continue
            source = '{}@0x{:X}'.format(f.getName(), f.getEntryPoint().getOffset())
            evidence_by_class.setdefault(cls, []).append((source, asg, emb))
        except Exception as exc:  # noqa: BLE001  (one bad function, not the pass)
            failed += 1
            if len(failures) < 5:
                failures.append('%s: %s' % (f.getName(), exc))
            continue
    decomp.dispose()
    decomp2.dispose()
    # Before anything is written: a broken decompiler must not replace the
    # last good evidence with an empty CSV (nor print the sentinel).
    require_decompile_health('ctor-mine', attempted, failed, failures)

    for cls, class_evidence in evidence_by_class.items():
        unk = unk_by_class.get(cls, set())
        observations = []
        for source, asg, emb in class_evidence:
            for off, (tn, pname) in asg.items():
                observations.append((off, tn, cp_plan.field_label(pname) or '', source))
            for off, ecls in emb.items():
                observations.append((off, ecls, 'base' if off == 0 else 'embedded', source))
        resolved, ambiguous = cp_plan.field_consensus(observations, min_independent=2)
        for off, info in sorted(resolved.items()):
            tn = info['type']
            label = info['name'] or ''
            is_unk = off in unk
            rows.append((cls, '0x%X' % off, tn, label,
                         'unknown' if is_unk else 'known', info['votes'],
                         'high', ' | '.join(info['constructors'])))
            if label:
                named += 1
            if is_unk:
                typed_unk += 1
            if label == 'embedded':
                n_embed += 1
        # Keep rejected conflicts in the queue for review, but mark them low so
        # ctor_apply will never mutate them automatically.
        for off, proposals in sorted(ambiguous.items()):
            if not proposals:
                continue
            top = proposals[0]
            is_unk = off in unk
            rows.append((cls, '0x%X' % off, top['type'], top['name'] or '',
                         'unknown' if is_unk else 'known', top['votes'],
                         'low', ' | '.join(top['constructors'])))
    classes_done = len(evidence_by_class)

    rows.sort(key=lambda r: (r[6] != 'high', r[4] != 'unknown', r[0], int(r[1], 16)))
    write_csv_atomically(out_csv, ['class', 'offset', 'type', 'name',
                                   'slot_state', 'votes', 'confidence',
                                   'constructors', 'decision'], rows)
    # Rows contain class-relative member offsets, not executable addresses.
    bind_evidence(out_csv, prog, 'ctor_fields', address_coordinate='NONE')
    print('ctor-mine (%s): %d classes mined, %d field proposals '
          '(%d name a field, %d embedded-object types, %d fill an unknown slot)'
          % (prog.getName(), classes_done, len(rows), named, n_embed, typed_unk))
    if failed:
        print('  %d of %d decompile(s) failed (first: %s)'
              % (failed, attempted, '; '.join(failures[:3])))
    for r in rows[:20]:
        print('   %s +%s %s %s [%s] votes=%s conf=%s' % r[:7])
    print('  -> ' + out_csv)


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('ctor_mine'))
