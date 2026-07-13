"""Ghidra -> CommonLib write-back detector (read-only report).

Closes the loop: the pipeline imports CommonLib into Ghidra; this reports what
the live Ghidra program knows that CommonLib does not, so it can flow back to the
canonical source. For each CommonLib function symbol it compares the live Ghidra
function's name against CommonLib's at that address and classifies the delta:

  NAME_DELTA        Ghidra has a trusted (USER_DEFINED/IMPORTED) name whose leaf
                    differs from CommonLib's -> write-back candidate (PDB/manual
                    RE knows a different name; review which is right vs binary).
  MISSING_IN_GHIDRA CommonLib named it but the Ghidra function is still generic
                    or only analyzer-named -> a gap in our own apply (QA signal).

Writes <import>.writeback.csv with the cross-version ids so each row is locatable
in CommonLib. Read-only: never mutates the program. Run inside Ghidra against the
target program; the runtime is taken from the program name (s/a/v offset key).

Signature deltas are intentionally out of v1 (cross-representation signature
normalization is a separate step); commonlib_delta.classify_delta already has the
SIG_DELTA path, tested, for when that lands.
"""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
OUT_CSV = os.environ.get('CLVR_WRITEBACK_CSV', IMPORT_PATH + '.writeback.csv')

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location(
    'clvr_commonlib_delta', os.path.join(SCRIPT_DIR, 'commonlib_delta.py'))
cd = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(cd)


def _load_symbols():
    with open(IMPORT_PATH) as f:
        for line in f:
            if line.startswith('SYMBOLS = '):
                return json.loads(line[len('SYMBOLS = '):])
    raise RuntimeError('SYMBOLS not found in ' + IMPORT_PATH)


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    base = cp.getImageBase()
    nm = cp.getName().lower()
    vkey = 'v' if 'vr' in nm else ('a' if ('1170' in nm or 'ae' in nm) else 's')
    trusted = (SourceType.USER_DEFINED, SourceType.IMPORTED)

    symbols = _load_symbols()
    rows = []
    counts = {}
    for s in symbols:
        if s.get('t') != 'func':
            continue
        off = s.get(vkey)
        if not off:
            continue
        f = fm.getFunctionAt(base.add(int(off)))
        if f is None:
            continue
        gname = f.getName()
        src = f.getSignatureSource()
        g_generic = cd.is_generic(gname) or src not in trusted
        kind = cd.classify_delta(s['n'], gname, g_generic, '', '', None)
        counts[kind] = counts.get(kind, 0) + 1
        if kind in ('NAME_DELTA', 'MISSING_IN_GHIDRA'):
            rows.append((kind, s['n'], gname,
                         '0x%X' % f.getEntryPoint().getOffset(),
                         s.get('si') or '', s.get('ai') or ''))

    rows.sort()
    with open(OUT_CSV, 'w') as fh:
        w = csv.writer(fh)
        w.writerow(['kind', 'commonlib_name', 'ghidra_name', 'address', 'se_id', 'ae_id'])
        for r in rows:
            w.writerow(r)
    print('Write-back deltas (%s): %s' % (cp.getName(), counts))
    print('  NAME_DELTA + MISSING_IN_GHIDRA logged: %d -> %s' % (len(rows), OUT_CSV))


run()
