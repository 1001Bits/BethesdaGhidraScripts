"""Constructor-mining review aid (READ-ONLY).

A class constructor assigns each member from a typed, named parameter
(`this->Object_18 = a_object`, `a_object:TESBoundObject*`), so one decompile yields a
field's NAME and TYPE together -- far more reliable than the discovery cycle's
size-only dataflow guesses (which mis-typed Crime+0x58 as a faction; the ctor showed
0x18 is the TESBoundObject `object` and 0x58 a 4-byte scalar).

For each /types.h class with unknown fields, this finds its constructor (param-0 is
the class, name looks like a ctor), decompiles it, and reads `this->field@offset =
a_param` assignments out of the pcode (value traced to a parameter; address traced to
`this + offset`). It writes proposals -- (class, offset, type, name) -- to
<import>.ctor_fields.csv, ranked so offsets the discovery still has as unknown come
first. Feed these into the review queue / cross-version apply: high-accuracy field
names + types a human can rubber-stamp instead of guessing.

NON-DESTRUCTIVE: only decompiles + writes a CSV; never modifies the program. Knobs:
CLVR_CTOR_MAX_CLASSES (0=all), CLVR_CTOR_TIMEOUT (decompile seconds, default 45).
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
OUT_CSV = os.environ.get('CLVR_CTOR_CSV', IMPORT_PATH + '.ctor_fields.csv')
MAX_CLASSES = int(os.environ.get('CLVR_CTOR_MAX_CLASSES', '0') or 0)
TIMEOUT = int(os.environ.get('CLVR_CTOR_TIMEOUT', '45') or 45)

import importlib.util as _ilu  # noqa: E402
_cspec = _ilu.spec_from_file_location('clvr_ctor_plan', os.path.join(SCRIPT_DIR, 'ctor_plan.py'))
cm = _ilu.module_from_spec(_cspec)
_cspec.loader.exec_module(cm)


def _high_name(vn):
    h = vn.getHigh() if vn is not None else None
    return h.getName() if h is not None else None


def _addr_off(vn, this_name, pc, depth=0):
    """Back-trace varnode `vn` to `this + k`; return k or None. Matches `this` by the
    param NAME, because Ghidra hands out distinct HighVariable objects for param-0's
    body instances (so object identity against the param symbol's high var fails)."""
    if vn is None or depth > 7:
        return None
    if _high_name(vn) == this_name:
        return 0
    d = vn.getDef()
    if d is None:
        return None
    oc = d.getOpcode()
    ins = d.getInputs()
    if oc in (pc.COPY, pc.CAST, pc.INDIRECT) and ins:
        return _addr_off(ins[0], this_name, pc, depth + 1)
    if oc in (pc.INT_ADD, pc.PTRSUB, pc.PTRADD) and len(ins) >= 2 and ins[1].isConstant():
        s = _addr_off(ins[0], this_name, pc, depth + 1)
        if s is not None:
            return s + int(ins[1].getOffset())
    return None


def _val_param(vn, param_names, pc, depth=0):
    """If `vn` (through copy/cast/phi) is one of the parameters (by name), return its
    name; else None. Captures `this->field = a_param` (value IS the param)."""
    if vn is None or depth > 5:
        return None
    nm = _high_name(vn)
    if nm in param_names:
        return nm
    d = vn.getDef()
    if d is None:
        return None
    if d.getOpcode() in (pc.COPY, pc.CAST, pc.INDIRECT, pc.MULTIEQUAL):
        for iv in d.getInputs():
            r = _val_param(iv, param_names, pc, depth + 1)
            if r is not None:
                return r
    return None


def _ctor_assignments(hf, this_name):
    """{offset: (typename, param_name)} for `this->field@off = a_param` in the ctor."""
    from ghidra.program.model.pcode import PcodeOp
    lsm = hf.getLocalSymbolMap()
    param_type = {}                                 # name -> typename (skip param-0)
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


def _unk_offsets(dt):
    offs = set()
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        if fn.startswith(('unk', 'pad')) or 'undefined' in c.getDataType().getName():
            offs.add(c.getOffset())
    return offs


def run():
    from ghidra.app.decompiler import DecompInterface
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()

    unk_by_class = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() == 'StructureDB' and 'types.h' in str(dt.getCategoryPath()):
            offs = _unk_offsets(dt)
            if offs:
                unk_by_class[dt.getName()] = offs

    # candidate constructors per class: param-0 is the class AND name looks like a ctor
    ctors_by_class = {}
    for f in fm.getFunctions(True):
        ps = f.getParameters()
        if not ps:
            continue
        cls = ps[0].getDataType().getName().rstrip('64').rstrip(' *')
        if cls in unk_by_class and cm.is_ctor(f.getName(), cls):
            ctors_by_class.setdefault(cls, []).append(f)

    decomp = DecompInterface()
    decomp.openProgram(cp)
    rows = []
    classes_done = named = typed_unk = 0
    targets = list(ctors_by_class.items())
    if MAX_CLASSES:
        targets = targets[:MAX_CLASSES]
    print('ctor-mine: %d unk-bearing /types.h classes, %d have a candidate constructor'
          % (len(unk_by_class), len(ctors_by_class)))
    for cls, ctors in targets:
        classes_done += 1
        # pick the constructor that assigns the most fields
        scored = []
        cache = {}
        for f in ctors[:6]:
            try:
                r = decomp.decompileFunction(f, TIMEOUT, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                hf = r.getHighFunction()
                lsm = hf.getLocalSymbolMap()
                if lsm.getNumParams() < 1:
                    continue
                this_name = lsm.getParamSymbol(0).getName()
                asg = _ctor_assignments(hf, this_name)
                cache[f.getEntryPoint().toString()] = asg
                scored.append((f.getEntryPoint().toString(), len(asg)))
            except Exception:
                continue
        best = cm.best_ctor(scored)
        if best is None:
            continue
        unk = unk_by_class.get(cls, set())
        for off, (tn, pname) in sorted(cache[best].items()):
            label = cm.field_label(pname) or ''
            is_unk = off in unk
            rows.append((cls, '0x%X' % off, tn, label, 'unknown' if is_unk else 'known'))
            if label:
                named += 1
            if is_unk:
                typed_unk += 1
    decomp.dispose()

    # unknown-slot proposals first (those resolve discovery gaps), then by class/offset
    rows.sort(key=lambda r: (r[4] != 'unknown', r[0], int(r[1], 16)))
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'type', 'name', 'slot_state'])
        for r in rows:
            w.writerow(r)
    print('ctor-mine (%s): %d classes mined, %d field proposals (%d name a field, '
          '%d fill an unknown slot)' % (cp.getName(), classes_done, len(rows), named, typed_unk))
    for r in rows[:20]:
        print('   %s +%s %s %s [%s]' % r)
    print('  -> ' + OUT_CSV)


run()
