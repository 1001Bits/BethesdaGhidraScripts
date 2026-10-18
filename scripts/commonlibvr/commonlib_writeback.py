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
target program. The runtime (s/a/v offset key) is the import's own VERSION when the
live program is that import's bound target; any other program needs an explicit
CLVR_WRITEBACK_RUNTIME=svr|se|ae, and builds CommonLibVR has no offsets for
(1.6.640, 1.7.104, GOG, ...) are refused rather than read with another build's.

Signature deltas are intentionally out of v1 (cross-representation signature
normalization is a separate step); commonlib_delta.classify_delta already has the
SIG_DELTA path, tested, for when that lands.
"""
import ast
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
from generated_symbols import assignment_value as _assignment_value  # noqa: E402
OUT_CSV = os.environ.get('CLVR_WRITEBACK_CSV', IMPORT_PATH + '.writeback.csv')
RUNTIME = os.environ.get('CLVR_WRITEBACK_RUNTIME', '').strip().lower() or None

# Importer VERSION -> the symbol offset key CommonLibVR resolved for exactly that
# build (parse_commonlib_types._build_address_library: s = SE 1.5.97,
# a = AE 1.6.1170, v = VR 1.4.15).  Nothing else has offsets in these symbols.
RUNTIME_KEYS = {'se': 's', 'ae': 'a', 'svr': 'v'}

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location(
    'clvr_commonlib_delta', os.path.join(SCRIPT_DIR, 'commonlib_delta.py'))
cd = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(cd)


def _load_import(import_path, names=('VERSION', 'TARGET_MANIFESTS', 'SYMBOLS')):
    found = {}
    with open(import_path, encoding='utf-8') as f:
        for line in f:
            name = line.split(' = ', 1)[0]
            if name in names and name not in found and ' = ' in line:
                found[name] = _assignment_value(line)
                if len(found) == len(names):
                    break
    if 'SYMBOLS' in names and 'SYMBOLS' not in found:
        raise RuntimeError('SYMBOLS not found in ' + import_path)
    return found


def _load_symbols(import_path=None):
    return _load_import(import_path or IMPORT_PATH, ('SYMBOLS',))['SYMBOLS']


def resolve_runtime(import_version, target_manifests, program_sha256,
                    requested=None):
    """Return ``(runtime, offset_key)`` for the live program or raise.

    The import's VERSION is used only when the live program is one of its bound
    targets.  Otherwise the caller must name the runtime explicitly; unknown
    runtimes (and runtimes contradicting a bound target) fail closed.
    """
    sha = str(program_sha256 or '').lower()
    bound = sha and sha in {
        str(target.get('sha256') or '').lower()
        for target in target_manifests or () if isinstance(target, dict)}
    if bound:
        if requested and requested != import_version:
            raise ValueError(
                'live program is the {!r} import target; refusing runtime {!r}'
                .format(import_version, requested))
        runtime = import_version
    elif requested:
        runtime = requested
    else:
        raise ValueError(
            'live program (sha256 {}) is not a target of this import; set '
            'CLVR_WRITEBACK_RUNTIME to one of {}'.format(
                sha or 'unknown', ', '.join(sorted(RUNTIME_KEYS))))
    if runtime not in RUNTIME_KEYS:
        raise ValueError('CommonLibVR symbols carry no offsets for runtime {!r}; '
                         'known: {}'.format(runtime, ', '.join(sorted(RUNTIME_KEYS))))
    return runtime, RUNTIME_KEYS[runtime]


def run(runtime=RUNTIME):
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    base = cp.getImageBase()
    generated = _load_import(IMPORT_PATH)
    runtime, vkey = resolve_runtime(
        generated.get('VERSION'), generated.get('TARGET_MANIFESTS'),
        cp.getExecutableSHA256(), runtime)
    print('Write-back runtime: %s (offset key %r)' % (runtime, vkey))
    trusted = (SourceType.USER_DEFINED, SourceType.IMPORTED)

    symbols = generated['SYMBOLS']
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
    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['kind', 'commonlib_name', 'ghidra_name', 'address', 'se_id', 'ae_id'])
        for r in rows:
            w.writerow(r)
    print('Write-back deltas (%s): %s' % (cp.getName(), counts))
    print('  NAME_DELTA + MISSING_IN_GHIDRA logged: %d -> %s' % (len(rows), OUT_CSV))


if __name__ == '__main__':
    run()
