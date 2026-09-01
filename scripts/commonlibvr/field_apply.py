"""Shared improve-or-nop field apply for the discovery drivers (commonlib_discover,
globals_anchor).

Both drivers aggregate (class, offset) -> inferred-type observations and then write the
high-confidence named ones into the live /types.h structs under the same guarantee, so
the apply loop lived twice. One copy here.

NON-DESTRUCTIVE: each field is validated on a DETACHED struct.copy() first and the live
struct is touched only when the change is provably improve-or-nop (length unchanged,
protected bytes not decreased -- populate_plan.is_struct_change_safe). The unk*/pad*
slot is renamed to `fld<digits>` so it leaves the discovery surface. One transaction,
never rolled back for an individual field (the MCP nests it, so that would discard
the whole group) and discarded only if an exception escapes the run.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import SCRIPT_DIR  # noqa: E402

import importlib.util as _ilu  # noqa: E402


def _load(mod, fn):
    spec = _ilu.spec_from_file_location(mod, os.path.join(SCRIPT_DIR, fn))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pl = _load('clvr_populate_plan', 'populate_plan.py')
gu = _load('clvr_ghidra_util', 'clvr_ghidra_util.py')


def _fld_name(cur_name, off):
    """`unk58`/`pad58`/`off_58` -> `fld58` (keep the offset digits for traceability)."""
    digits = ''.join(ch for ch in cur_name if ch.isalnum())
    for pre in ('unk', 'pad', 'off_'):
        if digits.lower().startswith(pre):
            digits = digits[len(pre):]
            break
    return 'fld%s' % (digits or ('%X' % off))


def apply_fields(cp, dtm, struct_by_class, dt_by_typename, aggregated, tag, do_apply):
    """Write the aggregated high-confidence named fields into their /types.h structs.
    `tag` is the comment prefix recorded on each field (e.g. 'clvr-discovered'). Returns
    (applied, skips Counter, changed_classes set, samples). do_apply=False -> no-op
    (returns zeros), so callers can gate on their own dry/apply flag."""
    applied = 0
    samples = []
    skips = collections.Counter()
    changed = set()
    if not do_apply:
        return applied, skips, changed, samples
    success = False
    txid = cp.startTransaction(tag + ' apply fields')
    try:
        for (cls, off), info in aggregated.items():
            struct = struct_by_class.get(cls)
            dt = dt_by_typename.get(info['type'])
            if struct is None or dt is None:
                skips['unresolved'] += 1
                continue
            comp = struct.getComponentAt(off)
            if comp is None or comp.getOffset() != off:
                skips['no-slot'] += 1
                continue
            cur_name = comp.getFieldName() or ''
            ok, why = pl.should_apply_field(
                cur_name, comp.getDataType().getName(), info['type'],
                dt.getLength(), comp.getLength(), info['confidence'])
            if not ok:
                skips[why] += 1
                continue
            new_name = _fld_name(cur_name, off)
            # improve-or-nop: prove on a detached copy before touching the live struct
            base = gu.struct_metrics(struct)
            try:
                test = struct.copy(dtm)
                tc = test.getComponentAt(off)
                if tc is None or tc.getOffset() != off:
                    skips['no-slot'] += 1
                    continue
                test.replaceAtOffset(off, dt, dt.getLength(), new_name, '')
                tm = gu.struct_metrics(test)
            except Exception:
                skips['copy-error'] += 1
                continue
            if not pl.is_struct_change_safe(base, tm):
                skips['unsafe(would-degrade)'] += 1
                continue
            try:
                struct.replaceAtOffset(off, dt, dt.getLength(), new_name,
                                       tag + ' ' + info['type'])
                if gu.struct_metrics(struct) != tm:        # live must match the sandbox
                    skips['live-mismatch(bug)'] += 1
                    continue
                applied += 1
                changed.add(cls)
                if len(samples) < 15:
                    samples.append('%s +0x%X %s -> %s %s'
                                   % (cls, off, cur_name, new_name, info['type']))
            except Exception:
                skips['replace-error'] += 1
        success = True
    finally:
        cp.endTransaction(txid, success)       # commit only if the loop ran to completion
    return applied, skips, changed, samples
