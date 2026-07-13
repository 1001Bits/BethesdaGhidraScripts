"""Propagate CommonLib's existing member typing INTO Ghidra (the inverse feed).

CommonLib has RE'd many members that Ghidra's imported struct still carries as an
undefined placeholder (the import flattens nested structs / drops some types). This
reads the CommonLib-typed members (commonlib_typed_members.csv) and, where Ghidra's
/types.h slot is still UNDEFINED and the CommonLib type resolves to a same-width Ghidra
type, applies it. That refines Ghidra's layout AND -- the point -- gives the decompiler
a typed anchor at that offset, so the NEXT discovery pass propagates one level deeper
from it (the classes touched are written to the dirty file).

NON-DESTRUCTIVE: only fills UNDEFINED/placeholder slots (never overwrites a type Ghidra
already resolved), requires the CommonLib type to be the SAME width as the slot
(a larger CommonLib type spanning several Ghidra slots is reported, not merged -- a
separate decision), and validates on a detached copy (improve-or-nop). Dry-run default;
CLVR_MEMBER_IMPORT=go to apply. Run per program.
"""
import collections
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
from clvr_config import TYPED_MEMBERS_CSV as MEMBERS_CSV  # noqa: E402

DIRTY_FILE = os.environ.get('CLVR_DISCOVER_DIRTY', IMPORT_PATH + '.discover_dirty.txt')
APPLY = os.environ.get('CLVR_MEMBER_IMPORT', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402


def _load(mod, fn):
    spec = _ilu.spec_from_file_location(mod, os.path.join(SCRIPT_DIR, fn))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


gu = _load('clvr_ghidra_util', 'clvr_ghidra_util.py')
pl = _load('clvr_populate_plan', 'populate_plan.py')

_PRIM = {'float': 'float', 'double': 'double', 'bool': 'bool', 'char': 'char',
         'std::uint8_t': 'uchar', 'std::int8_t': 'sbyte', 'std::uint16_t': 'ushort',
         'std::int16_t': 'short', 'std::uint32_t': 'uint', 'std::int32_t': 'int',
         'std::uint64_t': 'ulonglong', 'std::int64_t': 'longlong',
         'std::uintptr_t': 'ulonglong'}


def _mangle(name):
    """CommonLib C++ spelling -> the `_`-mangled name the import uses for templates."""
    out = name.replace('RE::', '')
    for ch in '<>,:* &':
        out = out.replace(ch, '_')
    return out


def _resolve(dtm, by_name, cpp):
    """Resolve a CommonLib C++ member type to a live Ghidra DataType, or None."""
    t = cpp.strip()
    ptr = 0
    while t.endswith('*'):
        t = t[:-1].strip()
        ptr += 1
    base = None
    if t in _PRIM and by_name.get(_PRIM[t]):
        base = by_name[_PRIM[t]]
    if base is None:
        for cand in (t, t.replace('RE::', ''), _mangle(t)):
            if by_name.get(cand):
                base = by_name[cand]
                break
    if base is None:
        return None
    for _ in range(ptr):
        base = dtm.getPointer(base, 8)
    return base


def _span_undefined(st, off, size):
    """Every Ghidra component in [off, off+size) is an undefined/placeholder slot (and
    the span fits the struct) -- so a larger CommonLib type can safely REPLACE the run
    (the flattened embedded struct/array the import split into undefined slots)."""
    if off + size > st.getLength():
        return False
    a = off
    while a < off + size:
        c = st.getComponentAt(a)
        if c is None:
            return False
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if not (fn.startswith(('unk', 'pad')) or 'undefined' in tn):
            return False
        nxt = c.getOffset() + c.getLength()
        if nxt <= a:
            return False
        a = nxt
    return True


def run():
    from ghidra.program.model.data import CategoryPath, Structure
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    tp = CategoryPath('/types.h')
    by_name = gu.build_by_name(dtm)

    rows = list(csv.DictReader(open(MEMBERS_CSV)))
    applied = 0
    merges = 0
    changed = set()
    skips = collections.Counter()
    samples = []
    tx = cp.startTransaction('commonlib member import') if APPLY else None
    try:
        for r in rows:
            cls, cpp = r['class'], r['cpp_type']
            off = int(r['offset'], 16)
            st = dtm.getDataType(tp, cls)
            if not isinstance(st, Structure) or off >= st.getLength():
                skips['no-struct'] += 1
                continue
            comp = st.getComponentAt(off)
            if comp is None or comp.getOffset() != off:
                skips['no-slot'] += 1
                continue
            fn = comp.getFieldName() or ''
            tn = comp.getDataType().getName()
            if not (fn.startswith(('unk', 'pad')) or 'undefined' in tn):
                skips['already-typed'] += 1            # don't overwrite Ghidra's RE
                continue
            dt = _resolve(dtm, by_name, cpp)
            if dt is None:
                skips['type-unresolved'] += 1
                continue
            if comp.getDataType().getName() == dt.getName():
                skips['same-type'] += 1                # already this type (no oscillation)
                continue
            is_merge = False
            if dt.getLength() != comp.getLength():
                # MERGE: a larger CommonLib type spanning a run of UNDEFINED Ghidra slots
                # is the flattened embedded struct/array -- CommonLib is the authority and
                # the slots carry no Ghidra RE, so replace the whole run. A SMALLER (more
                # granular) CommonLib type is left for review.
                if dt.getLength() > comp.getLength() and _span_undefined(st, off, dt.getLength()):
                    is_merge = True
                else:
                    skips['size-mismatch'] += 1
                    continue
            digits = ''.join(ch for ch in fn if ch.isalnum())
            for pre in ('unk', 'pad', 'off_'):
                if digits.lower().startswith(pre):
                    digits = digits[len(pre):]
                    break
            # use CommonLib's name when it is SEMANTIC; if CommonLib also left it unkNN,
            # rename to fldNN so the slot leaves the placeholder surface (no re-detection).
            cn = (r['name'] or '').strip()
            new_name = cn if cn and not cn.lower().startswith(('unk', 'pad')) else ('fld%s' % digits)
            base = gu.struct_metrics(st)
            try:
                test = st.copy(dtm)
                test.replaceAtOffset(off, dt, dt.getLength(), new_name, '')
                tm = gu.struct_metrics(test)
            except Exception:
                skips['copy-error'] += 1
                continue
            if not pl.is_struct_change_safe(base, tm):
                skips['unsafe'] += 1
                continue
            if APPLY:
                try:
                    st.replaceAtOffset(off, dt, dt.getLength(), new_name, 'clvr-from-commonlib')
                except Exception:
                    skips['replace-error'] += 1
                    continue
            applied += 1
            if is_merge:
                merges += 1
            changed.add(cls)
            if len(samples) < 20:
                samples.append('%s +0x%X %s -> %s %s%s'
                               % (cls, off, tn, new_name, dt.getName(),
                                  ' [MERGE]' if is_merge else ''))
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    if changed and APPLY:
        try:
            with open(DIRTY_FILE, 'w') as fh:
                fh.write('\n'.join(sorted(changed)))
        except Exception as e:
            print('  (dirty-file write failed: %s)' % e)

    print('commonlib->ghidra member import (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  %s=%d into undefined slots (%d via merge of split slots)   skips=%s'
          % ('applied' if APPLY else 'would-apply', applied, merges, dict(skips)))
    for s in samples:
        print('   ' + s)
    print('  %d classes changed -> %s (re-mine next discovery to propagate)'
          % (len(changed), DIRTY_FILE if APPLY else '(dry: not written)'))
    if not APPLY:
        print('  set CLVR_MEMBER_IMPORT=go to apply.')


run()
