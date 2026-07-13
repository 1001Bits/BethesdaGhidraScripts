"""Pure (Ghidra-free) logic for the globals harvester.

Technique adapted from alandtse's CommonLibVR fork.  Many engine
singletons live in untyped global data (``DAT_*``, an ``undefined8``
slot).  The decompiler can't propagate field accesses through an untyped
global, so a class reachable only via a global is invisible to
constructor/this-parameter discovery.

The high-signal, decompiler-cheap way to type a global: a global passed
as arg-0 (``this``) to a method whose param-0 is a known class C is
strong evidence the global is a ``C *``.  This module aggregates those
``(global_addr, class, caller)`` observations into a per-global consensus
type + confidence + review rank.  Kept Ghidra-free so the consensus logic
is unit-testable; the driver does the decompile + symbol typing.
"""
import collections


def aggregate_global_types(observations):
    """Aggregate ``(global_addr:int, class_name:str, caller:str)`` tuples.

    Returns ``{global_addr: {'type', 'votes', 'total', 'distinct',
    'classes', 'callers'}}`` where ``type`` is the most-voted class,
    ``votes`` its count, ``total`` all observations, ``distinct`` the
    number of competing classes, ``classes`` the full vote tally, and
    ``callers`` up to 6 example caller names (reviewer leads).
    """
    by_g = collections.defaultdict(list)
    seen_evidence = set()
    for g, cls, caller in observations:
        if g is None or not cls:
            continue
        evidence_key = (g, cls, caller or '')
        if evidence_key in seen_evidence:
            continue
        seen_evidence.add(evidence_key)
        by_g[g].append((cls, caller))
    out = {}
    for g, obs in by_g.items():
        tally = collections.Counter(cls for cls, _ in obs)
        best, votes = sorted(tally.items(), key=lambda item: (-item[1], item[0]))[0]
        callers = []
        for _cls, caller in obs:
            if caller and caller not in callers and len(callers) < 6:
                callers.append(caller)
        independent = len(set(caller for _cls, caller in obs if caller))
        out[g] = {'type': best, 'votes': votes, 'total': len(obs),
                  'distinct': len(tally), 'classes': dict(tally),
                  'callers': callers, 'independent': independent}
    return out


def global_confidence(info):
    """Confidence that a global's inferred type is right.

      high   -- one class, seen at >=2 independent call sites
      medium -- one class, a single call site (wants a second look)
      low    -- competing classes across call sites (reused global, or a
                base-class view leaked in) -> review must disambiguate
    """
    if info['distinct'] == 1:
        return 'high' if info.get('independent', 0) >= 2 else 'medium'
    if 2 * info['votes'] > info['total']:
        return 'medium'
    return 'low'


def review_rank(info):
    """Descending sort key for the review worklist: strongest evidence and
    least ambiguity first."""
    conf = {'high': 2, 'medium': 1, 'low': 0}[global_confidence(info)]
    return (conf, info['votes'], info['total'], -info['distinct'])


def to_rows(aggregated):
    """Flatten to review rows, best first: ``(global_addr, type,
    confidence, votes, total, distinct, classes_str, callers_str)``."""
    items = sorted(aggregated.items(),
                   key=lambda kv: review_rank(kv[1]), reverse=True)
    rows = []
    for g, info in items:
        classes_str = ' '.join('%s:%d' % (c, n) for c, n in
                               sorted(info['classes'].items(),
                                      key=lambda kv: -kv[1]))
        rows.append((g, info['type'], global_confidence(info), info['votes'],
                     info['total'], info['distinct'], classes_str,
                     ' '.join(info['callers'])))
    return rows
