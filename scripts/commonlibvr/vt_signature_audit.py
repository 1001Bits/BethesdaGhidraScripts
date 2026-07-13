"""Sanity-check ACCEPTED Version Tracking matches by signature/decompile consistency.

Complements version_track.py (which audits accepted matches against CommonLib's
ground-truth ADDRESS): this walks every ACCEPTED, FUNCTION-type association in the
open VT session(s) and flags ones where the two matched functions don't look like the
same function -- mismatched param count / return / param ABI class, a wildly different
body size, or (the strongest signal) a dst whose decompile LEAKS incoming-register
params the applied signature never declared (`in_RCX`/`in_ECX`...), i.e. the prototype
doesn't fit the dst. Decision logic is in vt_audit_plan.py (unit-tested); leaked-param
counting reuses decompile_score._inparam_count.

REPORT-ONLY, non-destructive: writes <import>.vt_sig_audit.csv of SUSPECT matches with
reasons; never rejects a match. Review the CSV, then reject the bad ones by hand (or
with version_track once corrected).

Run INSIDE Ghidra with the SE/AE/VR programs and the VT session(s) open (the MCP
`ghidra` helper supplies the sessions). Cheap structural checks run on every match;
the decompile check runs too (default on) but is bounded -- VT_AUDIT_DECOMPILE=off to
skip it, VT_AUDIT_MAX (default 2000) caps how many matches get decompiled, and each
decompile uses a short timeout. See the MCP-timeout notes: this can be long, so prefer
running it as an async eval (sync:false) and poll, rather than an unbounded sync call.
"""
import csv
import os
import sys
import importlib.util as _ilu

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402

OUT_CSV = IMPORT_PATH + '.vt_sig_audit.csv'
DECOMPILE = os.environ.get('VT_AUDIT_DECOMPILE', 'on').lower() != 'off'
MAX_DECOMP = int(os.environ.get('VT_AUDIT_MAX', '2000'))


def _load(name, fn):
    spec = _ilu.spec_from_file_location(name, os.path.join(SCRIPT_DIR, fn))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ap = _load('clvr_vt_audit_plan', 'vt_audit_plan.py')
ds = _load('clvr_decompile_score', 'decompile_score.py')


def _cat(dt):
    from ghidra.program.model.data import Pointer, Structure, Union
    if dt is None:
        return 'void'
    n = dt.getName().lower()
    if n == 'void':
        return 'void'
    if isinstance(dt, Pointer):
        return 'ptr'
    if isinstance(dt, (Structure, Union)):
        return 'struct'
    if 'float' in n or 'double' in n:
        return 'float'
    return 'int'   # integers, enums, undefinedN (register-width return/arg)


def _decomp_iface(prog):
    from ghidra.app.decompiler import DecompInterface
    di = DecompInterface()
    di.openProgram(prog)
    return di


def _inparams(di, func, monitor):
    """Leaked incoming-register param count from the function's decompile, or 0."""
    try:
        res = di.decompileFunction(func, 15, monitor)
        if res and res.decompileCompleted():
            return ds._inparam_count(res.getDecompiledFunction().getC())
    except Exception:
        pass
    return 0


def _profile(func, di, monitor, want_decomp):
    from ghidra.program.model.symbol import SourceType
    params = list(func.getParameters())
    return {
        'name': func.getName(),
        'params': len(params),
        'ret_cat': _cat(func.getReturnType()),
        'param_cats': [_cat(p.getDataType()) for p in params],
        'size': int(func.getBody().getNumAddresses()),
        'inparams': _inparams(di, func, monitor) if (want_decomp and di) else 0,
        # an applied prototype (not the bare default `undefined f(void)`); only then is
        # a param/return mismatch meaningful rather than "not recovered yet".
        'has_sig': func.getSignatureSource() != SourceType.DEFAULT,
    }


def run():
    from ghidra.feature.vt.api.main import VTAssociationStatus, VTAssociationType
    g = globals().get('ghidra')
    if g is None or not hasattr(g, 'get_vt_sessions'):
        print('No VT session resolver (MCP ghidra helper). Open the VT session(s) and run via MCP.')
        return
    mon = globals().get('monitor')
    names = g.get_vt_sessions()
    sessions = [g.get_vt_session(i) for i in range(len(names))]

    rows = []
    decompiled = 0
    for si, sess in enumerate(sessions):
        sp, dp = sess.getSourceProgram(), sess.getDestinationProgram()
        sfm, dfm = sp.getFunctionManager(), dp.getFunctionManager()
        sdi = _decomp_iface(sp) if DECOMPILE else None
        ddi = _decomp_iface(dp) if DECOMPILE else None
        am = sess.getAssociationManager()
        for a in am.getAssociations():
            if a.getStatus() != VTAssociationStatus.ACCEPTED:
                continue
            if a.getType() != VTAssociationType.FUNCTION:
                continue
            sf = sfm.getFunctionAt(a.getSourceAddress())
            df = dfm.getFunctionAt(a.getDestinationAddress())
            if sf is None or df is None:
                continue
            want = DECOMPILE and decompiled < MAX_DECOMP
            src = _profile(sf, sdi, mon, want)
            dst = _profile(df, ddi, mon, want)
            if want:
                decompiled += 1
            verdict, reasons = ap.audit_match(src, dst)
            if verdict == 'SUSPECT':
                rows.append((si, str(a.getSourceAddress()), src['name'],
                             str(a.getDestinationAddress()), dst['name'], '; '.join(reasons)))
        if sdi:
            sdi.dispose()
        if ddi:
            ddi.dispose()

    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['session', 'src_addr', 'src_name', 'dst_addr', 'dst_name', 'reasons'])
        for r in rows:
            w.writerow(r)
    print('VT signature audit: %d SUSPECT accepted matches (decompiled %d%s) -> %s'
          % (len(rows), decompiled, ' [CAPPED]' if decompiled >= MAX_DECOMP else '', OUT_CSV))
    for r in rows[:25]:
        print('   s%s %s -> %s : %s' % (r[0], r[2], r[4], r[5]))


run()
