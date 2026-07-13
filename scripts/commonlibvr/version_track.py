"""CommonLib-driven Version Tracking: seed exact cross-version matches + audit.

CommonLib's RELOCATION_ID(se, ae) / VariantID(se, ae, vr) give each symbol's exact
address in every runtime. The generated SYMBOLS carry those as per-runtime offsets
(s=SE, a=AE, v=VR). This script turns that ground truth into Ghidra Version
Tracking ACCEPTED matches:

  SEED  -- for a src with no accepted match, inject our exact (src->dst) match and
           accept it (type Function for 'func', Data for labels).
  AUDIT -- where a src already has an accepted match to a DIFFERENT dst, that is a
           correlator error; record it to a CSV for review (never auto-changed).

Run INSIDE Ghidra with the SE/AE/VR programs AND the VT sessions open. Dry-run by
default (audit + counts only, no writes); set VT_APPLY=go to seed. The decision
logic lives in vt_plan.py (unit-tested); this file is the Ghidra glue only.

Sessions are resolved from the MCP `ghidra` helper when present, else from the
running tool's open Version Tracking session. Pairs are taken from the generated
CommonLibImport_CLVR_VR.py SYMBOLS (it already carries s/a/v for all runtimes).
"""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
AUDIT_CSV = os.environ.get('VT_AUDIT_CSV', IMPORT_PATH + '.vt_audit.csv')
APPLY = os.environ.get('VT_APPLY', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_vt_plan', os.path.join(SCRIPT_DIR, 'vt_plan.py'))
vt_plan = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(vt_plan)


def _load_symbols():
    with open(IMPORT_PATH) as f:
        for line in f:
            if line.startswith('SYMBOLS = '):
                return json.loads(line[len('SYMBOLS = '):])
    raise RuntimeError('SYMBOLS not found in ' + IMPORT_PATH)


def _resolve_sessions():
    """Return the open VT session objects. Prefers the MCP `ghidra` helper."""
    g = globals().get('ghidra')
    if g is not None and hasattr(g, 'get_vt_sessions'):
        names = g.get_vt_sessions()
        return [g.get_vt_session(i) for i in range(len(names))]
    raise RuntimeError(
        'No VT session resolver. Run with the MCP `ghidra` helper available, or '
        'pass session objects in. VT sessions must be open in the tool.')


def _accepted_dst_offset(am, src_addr, dbase_off, VTAssociationStatus):
    rel = am.getRelatedAssociationsBySourceAddress(src_addr)
    for i in range(rel.size()):
        a = rel.get(i)
        if a.getStatus() == VTAssociationStatus.ACCEPTED:
            return a.getDestinationAddress().getOffset() - dbase_off
    return None


def process_session(sess, symbols, src_key, dst_key, label, audit_rows):
    from ghidra.feature.vt.api.main import (
        VTMatchInfo, VTAssociationType, VTScore, VTAssociationStatus)
    src_prog = sess.getSourceProgram()
    dst_prog = sess.getDestinationProgram()
    sbase = src_prog.getImageBase()
    dbase = dst_prog.getImageBase()
    dbase_off = dbase.getOffset()

    expected = vt_plan.build_expected(symbols, src_key, dst_key)
    am = sess.getAssociationManager()
    existing = {}
    for src_off in expected:
        d = _accepted_dst_offset(am, sbase.add(src_off), dbase_off, VTAssociationStatus)
        if d is not None:
            existing[src_off] = d
    plan = vt_plan.plan_vt(expected, existing)

    seeded = seed_fail = 0
    if APPLY and plan['seed']:
        ms = sess.getManualMatchSet()
        txid = sess.startTransaction('CLVR VT seed ' + label)
        try:
            for src, dst, kind in plan['seed']:
                try:
                    info = VTMatchInfo(ms)
                    info.setSourceAddress(sbase.add(src))
                    info.setDestinationAddress(dbase.add(dst))
                    info.setSourceLength(1)
                    info.setDestinationLength(1)
                    info.setAssociationType(
                        VTAssociationType.FUNCTION if kind == 'func' else VTAssociationType.DATA)
                    info.setSimilarityScore(VTScore(1.0))
                    info.setConfidenceScore(VTScore(1.0))
                    m = ms.addMatch(info)
                    m.getAssociation().setAccepted()
                    seeded += 1
                except Exception:
                    seed_fail += 1
        finally:
            sess.endTransaction(txid, True)

    for src, dst, got, kind in plan['conflict']:
        audit_rows.append((
            label, kind,
            '0x%X' % sbase.add(src).getOffset(),
            '0x%X' % dbase.add(dst).getOffset(),     # CommonLib says this
            '0x%X' % dbase.add(got).getOffset()))    # VT currently accepts this

    print('VT %s [%s]: expected=%d confirmed=%d conflict=%d seed=%d (seeded=%d fail=%d)'
          % (label, 'APPLIED' if APPLY else 'DRY-RUN', len(expected),
             len(plan['confirmed']), len(plan['conflict']), len(plan['seed']),
             seeded, seed_fail))
    return plan


def run():
    symbols = _load_symbols()
    sessions = _resolve_sessions()
    audit_rows = []
    for sess in sessions:
        sname = sess.getDestinationProgram().getName()
        # choose the runtime offset for the destination program
        if 'VR' in sname:
            dst_key = 'v'
        elif '1170' in sname or 'AE' in sname:
            dst_key = 'a'
        else:
            continue   # not a runtime we map
        label = 'SE->' + ('VR' if dst_key == 'v' else 'AE')
        process_session(sess, symbols, 's', dst_key, label, audit_rows)

    with open(AUDIT_CSV, 'w') as fh:
        w = csv.writer(fh)
        w.writerow(['session', 'kind', 'src_addr', 'commonlib_dst', 'vt_accepted_dst'])
        for r in audit_rows:
            w.writerow(r)
    print('VT audit conflicts: %d -> %s' % (len(audit_rows), AUDIT_CSV))


run()
