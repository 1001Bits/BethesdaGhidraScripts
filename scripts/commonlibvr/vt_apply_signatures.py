"""Apply trustworthy SE function signatures onto their accepted-VT twins (AE/VR).

Source of the candidate set: vt_apply_candidates.csv (built from vt_lost_params.csv,
filtered to real game functions). Each row is an ACCEPTED Version Tracking match where
the destination twin lost all parameters but the SE source has a recovered signature.

This is NOT a blind prototype copy. Two cross-version hazards corrupt a naive copy, so
the apply is gated by a deterministic per-function correctness check (this replaces the
slow / lenient "LLM eyeballs a sample" loop -- it runs on every row):

  1. Duplicate-`this`.  Some SE sources carry a spurious explicit `longlong a_this`
     parameter sitting right after the auto __thiscall `this` -- a bad recovery, never
     referenced in the body. Copied verbatim onto a __thiscall twin it produces a
     double-this and shifts every real arg by one. We drop a leading explicit integer
     param named this/a_this before copying. (~146 of 942 candidates carry it.)

  2. Silent param drop.  Ghidra's DYNAMIC_STORAGE allocator silently DROPS a parameter
     whose resolved type is a pointer to certain destination structs (e.g. SegVisitor is
     an empty stub in AE; some clean structs trigger it too -- it is a storage-allocator
     quirk, not a length issue). The candidate set is by definition "twin lost ALL params",
     so correct ARITY is the prize and pointee precision is secondary. The arity guard
     catches a short count: snapshot the dst signature, apply with full types, and if a
     param dropped, retry coercing every pointer param to void* (preserves the register
     slot and the arg-is-a-pointer fact, losing only the pointee type); if it is STILL
     short, restore the snapshot so nothing is ever degraded.

Run inside Ghidra (GhidrAssistMCP eval) with the helper globals available:
    exec(open(r'...vt_apply_signatures.py').read(), globals())
    print(run(0, 20, dry=False))          # apply rows [0,20)
    print(run(0, 0, dry=True))            # dry-run the whole file (end<=0 => all)
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import APPLY_CSV as _CSV  # noqa: E402

import java.util.ArrayList as AL
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import Pointer, PointerDataType, VoidDataType
from ghidra.program.model.data import DataTypeConflictHandler

# Cross-program type copy must REUSE the destination's existing type, never mint a
# `.conflict` twin. The default resolve() handler appends `.conflict` whenever the source
# type differs even slightly from the dst's same-named type (e.g. a self-referential
# VFTable pointer), which sprays duplicate types into the program. KEEP_HANDLER returns
# the dst's existing canonical type on any conflict, so a signature copy can never grow
# the type table. (The pre-existing `.conflict` residual is a separate dedup job.)
_KEEP = DataTypeConflictHandler.KEEP_HANDLER

_UT = Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
_INT = set(['longlong', 'ulonglong', 'undefined8', 'int', 'uint',
            'undefined', '__int64', 'uint64_t', 'int64_t'])
_VOIDP = PointerDataType(VoidDataType.dataType)


def _gfa(prog, addr):
    return prog.getAddressFactory().getDefaultAddressSpace().getAddress('0x' + addr)


def _explicit(func):
    return [p for p in func.getParameters() if not p.isAutoParameter()]


def _sanitize(explicit):
    """Drop a leading explicit integer param named this/a_this (duplicate-this artifact)."""
    if explicit and explicit[0].getName().lower() in ('this', 'a_this') \
            and explicit[0].getDataType().getName() in _INT:
        return explicit[1:], 1
    return explicit, 0


def _coerce_voidp(dt):
    """Retry-path only: any pointer that the storage allocator dropped is replaced with
    void* so the register slot (and the arg-is-a-pointer fact) survives. We lose only the
    pointee type, which is acceptable for a set whose twins currently have ZERO params."""
    if isinstance(dt, Pointer):
        return _VOIDP
    return dt


def _build(explicit, ddtm, dp, coerce_ptrs):
    params = AL()
    for p in explicit:
        dt = ddtm.resolve(p.getDataType(), _KEEP)
        if coerce_ptrs:
            dt = _coerce_voidp(dt)
        params.add(ParameterImpl(p.getName(), dt, dp))
    return params


def _load_rows():
    if not os.path.isfile(_CSV):
        raise IOError('candidate CSV not found: %s (set CLVR_APPLY_CSV)' % _CSV)
    with open(_CSV) as fh:
        return list(csv.DictReader(fh))


def run(start=0, end=0, dry=True):
    sessions = ghidra.get_vt_sessions()  # noqa: F821 -- Ghidra-injected eval global
    rows = _load_rows()
    if end <= 0 or end > len(rows):
        end = len(rows)
    tally = {'ok': 0, 'sanitized': 0, 'coerced': 0, 'restored': 0, 'miss': 0, 'err': 0}
    log = []
    for row in rows[start:end]:
        sess = sessions[int(row['session'])]
        sp, dp = sess.getSourceProgram(), sess.getDestinationProgram()
        ddtm = dp.getDataTypeManager()
        sf = sp.getFunctionManager().getFunctionAt(_gfa(sp, row['src_addr']))
        df = dp.getFunctionManager().getFunctionAt(_gfa(dp, row['dst_addr']))
        if sf is None or df is None:
            tally['miss'] += 1
            log.append('MISS %s' % row['dst_name'])
            continue
        explicit, dropped = _sanitize(_explicit(sf))
        want = len(explicit)
        conv = sf.getCallingConventionName()
        ret_dt = sf.getReturnType()
        if dry:
            tally['ok'] += 1
            if dropped:
                tally['sanitized'] += 1
            log.append('DRY %s want=%d drop=%d conv=%s' % (row['dst_name'], want, dropped, conv))
            continue
        # snapshot for restore-on-degrade (built outside the tx -- no DTM mutation here)
        snap_conv = df.getCallingConventionName()
        snap_ret = df.getReturnType()
        snap_explicit = [ParameterImpl(p.getName(), p.getDataType(), dp) for p in _explicit(df)]
        snap_src = df.getSignatureSource()
        tx = dp.startTransaction('apply sig ' + row['dst_name'])
        result = None
        try:
            # a fresh ReturnParameterImpl per call -- a Variable cannot be reused across
            # updateFunction calls (the second call silently misbehaves otherwise).
            rret = ddtm.resolve(ret_dt, _KEEP)
            df.updateFunction(conv, ReturnParameterImpl(rret, dp),
                              _build(explicit, ddtm, dp, False), _UT, True, SourceType.IMPORTED)
            got = len(_explicit(df))
            coerced = False
            if got < want:  # storage allocator dropped a pointer -> retry coercing to void*
                df.updateFunction(conv, ReturnParameterImpl(rret, dp),
                                  _build(explicit, ddtm, dp, True), _UT, True, SourceType.IMPORTED)
                got = len(_explicit(df))
                coerced = True
            if got < want:  # still short -> restore, never degrade
                snap_params = AL()
                for p in snap_explicit:
                    snap_params.add(p)
                df.updateFunction(snap_conv, ReturnParameterImpl(snap_ret, dp),
                                  snap_params, _UT, True, snap_src)
                result = 'RESTORE want=%d got=%d' % (want, got)
                tally['restored'] += 1
            else:
                result = 'OK want=%d got=%d%s%s' % (
                    want, got, ' drop' if dropped else '', ' coerce' if coerced else '')
                tally['ok'] += 1
                if dropped:
                    tally['sanitized'] += 1
                if coerced:
                    tally['coerced'] += 1
        except Exception as e:
            result = 'ERR ' + str(e)
            tally['err'] += 1
        dp.endTransaction(tx, True)
        log.append('%s :: %s' % (row['dst_name'], result))
    return {'range': (start, end), 'tally': tally, 'log': log}
