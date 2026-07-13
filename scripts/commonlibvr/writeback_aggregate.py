"""Cross-runtime aggregation of the per-runtime write-back delta reports.

Joins the SE/AE/VR `<import>.writeback.csv` reports by CommonLib symbol name and
classifies each symbol by HOW its Ghidra-vs-CommonLib disagreement is distributed
across the runtimes it is mapped in. This turns three flat lists into a
prioritized, self-triaging write-back list.

CommonLib is iterative: a symbol often starts mapped for one runtime (SE or AE)
and gains runtime-specific addresses later, as divergences are found. So a delta
must be read relative to COVERAGE -- only runtimes where CommonLib actually has an
address (`present`) can have a verdict; the rest are ABSENT (not yet mapped), a
candidate for a future runtime-specific entry, not a gap.

The classify/aggregate functions are pure (no Ghidra, no I/O); the runner at the
bottom does the file join. Unit-tested.
"""
import csv
import json
import os

RUNTIMES = ('se', 'ae', 'vr')


def classify_symbol(present, deltas):
    """Classify one symbol across runtimes.

    present : set/iterable of runtimes where CommonLib HAS an address.
    deltas  : {runtime: kind} for runtimes that produced a delta row
              (kind is 'NAME_DELTA' or 'MISSING_IN_GHIDRA'); a mapped runtime
              absent from this dict is a MATCH.

    Returns (verdict, statuses) where statuses is {runtime: status} with status
    in NAME_DELTA / MISSING_IN_GHIDRA / MATCH / ABSENT, and verdict is:
      RECONCILE        NAME_DELTA in EVERY mapped runtime -> one CommonLib name fix
      RUNTIME_SPECIFIC NAME_DELTA in SOME mapped runtimes, MATCH in others ->
                       the diverging runtime's address is suspect (or a real
                       per-runtime divergence) -- verify that offset vs the binary
      APPLY_GAP        a MISSING_IN_GHIDRA with no contradicting name delta
      MATCH            nothing to report
    """
    present = set(present)
    statuses = {}
    for rt in RUNTIMES:
        if rt not in present:
            statuses[rt] = 'ABSENT'
        else:
            statuses[rt] = deltas.get(rt, 'MATCH')

    mapped = [statuses[rt] for rt in RUNTIMES if rt in present]
    has_name = any(s == 'NAME_DELTA' for s in mapped)
    all_name = mapped and all(s == 'NAME_DELTA' for s in mapped)
    has_missing = any(s == 'MISSING_IN_GHIDRA' for s in mapped)

    if all_name:
        verdict = 'RECONCILE'
    elif has_name:
        verdict = 'RUNTIME_SPECIFIC'
    elif has_missing:
        verdict = 'APPLY_GAP'
    else:
        verdict = 'MATCH'
    return verdict, statuses


def aggregate(names, present_by_rt, delta_by_rt):
    """Aggregate all symbols. Returns {name: (verdict, statuses)}.

    present_by_rt : {runtime: set(names mapped in that runtime)}
    delta_by_rt   : {runtime: {name: kind}}
    """
    out = {}
    for name in names:
        present = {rt for rt in RUNTIMES if name in present_by_rt.get(rt, ())}
        deltas = {rt: delta_by_rt[rt][name]
                  for rt in RUNTIMES if name in delta_by_rt.get(rt, {})}
        out[name] = classify_symbol(present, deltas)
    return out


def suspect_runtimes(statuses):
    """For a RUNTIME_SPECIFIC symbol: (delta_runtimes, trusted_runtimes) -- the
    runtimes whose address looks wrong vs the ones that agree with CommonLib."""
    delta = [rt for rt in RUNTIMES if statuses.get(rt) == 'NAME_DELTA']
    trusted = [rt for rt in RUNTIMES if statuses.get(rt) == 'MATCH']
    return delta, trusted


def absent_runtimes(statuses):
    """Runtimes CommonLib has not mapped yet (iterative-coverage candidates)."""
    return [rt for rt in RUNTIMES if statuses.get(rt) == 'ABSENT']


# --- runner (plain Python, no Ghidra): join the 3 writeback CSVs + SYMBOLS -------

_VERDICT_ORDER = {'RUNTIME_SPECIFIC': 0, 'RECONCILE': 1, 'APPLY_GAP': 2, 'MATCH': 3}


def _load_symbols(import_path):
    with open(import_path) as f:
        for line in f:
            if line.startswith('SYMBOLS = '):
                return json.loads(line[len('SYMBOLS = '):])
    raise RuntimeError('SYMBOLS not found in ' + import_path)


def _load_deltas(csv_path):
    """Return {name: kind} from a <import>.writeback.csv (NAME_DELTA wins over
    a same-name MISSING row). Missing file -> empty (that runtime not yet run)."""
    out = {}
    if not os.path.isfile(csv_path):
        return out
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            name, kind = row['commonlib_name'], row['kind']
            if out.get(name) != 'NAME_DELTA':
                out[name] = kind
    return out


def main(import_dir, out_csv):
    imports = {rt: os.path.join(import_dir, 'CommonLibImport_CLVR_%s.py' % rt.upper())
               for rt in RUNTIMES}
    # presence + ids from whichever import exists (all carry s/a/v + si/ai)
    syms = None
    for p in imports.values():
        if os.path.isfile(p):
            syms = _load_symbols(p)
            break
    if syms is None:
        raise RuntimeError('no CommonLibImport_CLVR_{SE,AE,VR}.py found in ' + import_dir)
    okey = {'se': 's', 'ae': 'a', 'vr': 'v'}
    present_by_rt = {rt: set() for rt in RUNTIMES}
    ids = {}
    for s in syms:
        if s.get('t') != 'func':
            continue
        nm = s['n']
        ids.setdefault(nm, (s.get('si') or '', s.get('ai') or ''))
        for rt in RUNTIMES:
            if s.get(okey[rt]):
                present_by_rt[rt].add(nm)
    delta_by_rt = {rt: _load_deltas(imports[rt] + '.writeback.csv') for rt in RUNTIMES}

    names = set().union(*present_by_rt.values(), *(d.keys() for d in delta_by_rt.values()))
    agg = aggregate(names, present_by_rt, delta_by_rt)

    rows = []
    counts = {}
    for nm, (verdict, st) in agg.items():
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict == 'MATCH':
            continue
        delta_rt, trusted_rt = suspect_runtimes(st)
        si, ai = ids.get(nm, ('', ''))
        rows.append((verdict, nm, st['se'], st['ae'], st['vr'],
                     '+'.join(delta_rt), '+'.join(trusted_rt),
                     '+'.join(absent_runtimes(st)), si, ai))
    rows.sort(key=lambda r: (_VERDICT_ORDER.get(r[0], 9), r[1]))
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['verdict', 'commonlib_name', 'se', 'ae', 'vr',
                    'suspect_runtimes', 'trusted_runtimes', 'unmapped_runtimes',
                    'se_id', 'ae_id'])
        for r in rows:
            w.writerow(r)
    print('Aggregated write-back verdicts:', counts)
    print('  actionable rows (non-MATCH): %d -> %s' % (len(rows), out_csv))


if __name__ == '__main__':
    import sys
    _dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'ghidrascripts')
    _out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(_dir, 'writeback_aggregated.csv')
    main(_dir, _out)
