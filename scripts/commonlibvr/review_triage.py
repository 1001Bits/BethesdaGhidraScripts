"""Triage the LLM-review queue by UNLOCK SURFACE (+ cross-version free answers).

Turns the confidence-ranked review queue into an IMPACT-ranked worklist so LLM/human
judgement goes where it cascades. Two passes:

  1. Cross-version pre-fill -- a size-only field in THIS runtime that is already RESOLVED
     in a sibling (SE/VR <import>.resolved_fields.csv, matched on the CommonLib offset)
     needs no judgement; it is reported as a FREE answer to apply via crossver, and
     dropped from the worklist.
  2. Unlock-surface ranking -- score each remaining field by review_triage_plan: the
     remaining unknown-field count across its class's transitive dependents (the
     dirty-tracking dependency graph, run forward). Pointer fields (anchor-creating)
     and higher-vote fields break ties. Top of the list = type this and the next
     discovery cycle cascades.

READ-ONLY: writes <import>.review_triaged.csv (ranked, with unlock_score, dependents,
and any cross-version free answer) and prints the top. Run after a discovery pass (it
needs <import>.discover_state.json and <import>.review_queue.csv).
"""
import collections
import csv
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
STATE_JSON = os.environ.get('CLVR_DISCOVER_STATE', IMPORT_PATH + '.discover_state.json')
REVIEW_CSV = os.environ.get('CLVR_DISCOVER_REVIEW_CSV', IMPORT_PATH + '.review_queue.csv')
OUT_CSV = IMPORT_PATH + '.review_triaged.csv'
# CLVR_TRIAGE_APPLY=go also LANDS the cross-version free answers: it runs crossver in
# apply mode (which size-checks + improve-or-nop fills each unknown field already
# resolved in a sibling runtime) -- free RE that needs no LLM judgement.
APPLY_FREE = os.environ.get('CLVR_TRIAGE_APPLY', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402


def _load(mod, fn):
    spec = _ilu.spec_from_file_location(mod, os.path.join(SCRIPT_DIR, fn))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tp = _load('clvr_review_triage_plan', 'review_triage_plan.py')
cv = _load('clvr_crossver_plan', 'crossver_plan.py')
gu = _load('clvr_ghidra_util', 'clvr_ghidra_util.py')

import json  # noqa: E402

# pointer-sized guesses that could anchor (create a new typed edge); 4-byte scalars
# (uint/int) resolve in place and unlock nothing.
_PTRISH = {'void *', 'ulonglong', 'longlong', 'pointer', 'uint64', 'int64'}


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    # live unknown-field count per /types.h class (the unlock weight)
    unknown_counts = {}
    for dt in gu.types_structs(dtm):
        n = len(gu.unk_offsets(dt))
        if n:
            unknown_counts[dt.getName()] = n

    state = {}
    if os.path.exists(STATE_JSON):
        with open(STATE_JSON) as fh:
            state = (json.load(fh) or {}).get('classes', {})

    if not os.path.exists(REVIEW_CSV):
        print('No review queue at %s -- run commonlib_discover first.' % REVIEW_CSV)
        return

    # cross-version resolved fields from every sibling export: (class, cl_offset) -> type
    sib = collections.defaultdict(list)
    for path in glob.glob(os.path.join(os.path.dirname(IMPORT_PATH), '*.resolved_fields.csv')):
        if path == IMPORT_PATH + '.resolved_fields.csv':
            continue                         # skip our own
        with open(path, newline='') as fh:
            for row in csv.DictReader(fh):
                sib[(row['class'], int(row['cl_offset'], 16))].append(row['typename'])

    fields = []
    free = 0
    with open(REVIEW_CSV, newline='') as fh:
        for row in csv.DictReader(fh):
            cur = row.get('current_name', '')
            key = cv.field_key(cur)
            best, _conflict = cv.pick_best_type(sib.get((row['class'], key), []))
            guess = row.get('size_only_guess', '')
            fields.append({
                'class': row['class'], 'offset': row['offset'],
                'current_name': cur, 'size_only_guess': guess,
                'votes': int(row.get('votes', 0) or 0),
                'is_pointer': ('*' in guess) or (guess in _PTRISH),
                'crossver_answer': best or '',
            })
            if best:
                free += 1

    ranked = tp.triage(fields, state, unknown_counts)

    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['rank', 'class', 'offset', 'current_name', 'size_only_guess',
                    'is_pointer', 'votes', 'unlock_score', 'dependents',
                    'crossver_answer'])
        for i, f in enumerate(ranked, 1):
            w.writerow([i, f['class'], f['offset'], f['current_name'],
                        f['size_only_guess'], 1 if f['is_pointer'] else 0, f['votes'],
                        f['unlock_score'], f['dependents'], f['crossver_answer']])

    print('Review triage (%s): %d fields, %d have a cross-version FREE answer.'
          % (cp.getName(), len(ranked), free))
    print('  top by unlock surface (type these first -> next cycle cascades):')
    for f in ranked[:12]:
        tag = ('  <= FREE: %s' % f['crossver_answer']) if f['crossver_answer'] else ''
        print('   [%4d unlock / %3d deps] %s +%s  %s%s%s'
              % (f['unlock_score'], f['dependents'], f['class'], f['offset'],
                 f['size_only_guess'], ' *' if f['is_pointer'] else '', tag))
    print('  -> ' + OUT_CSV)
    if free and not APPLY_FREE:
        print('  %d cross-version free answers -> set CLVR_TRIAGE_APPLY=go (or run '
              'crossver.py apply) to land them without LLM review.' % free)

    # auto-apply the free answers by running crossver in apply mode (size-checked,
    # improve-or-nop). It propagates EVERY sibling-resolved field, a superset of the
    # ones surfaced above -- strictly more free RE.
    if APPLY_FREE and free:
        print('\n  CLVR_TRIAGE_APPLY=go -> landing cross-version free answers via crossver:')
        env = dict(os.environ)
        env['CLVR_XVER'] = 'apply'
        env['CLVR_XVER_APPLY'] = 'go'
        os.environ.update(env)
        g = dict(globals())
        g['__name__'] = '__main__'
        g['currentProgram'] = cp
        g['monitor'] = monitor  # noqa: F821
        with open(os.path.join(SCRIPT_DIR, 'crossver.py')) as fh:
            exec(compile(fh.read(), 'crossver.py', 'exec'), g)


run()
