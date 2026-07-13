"""Pure (Ghidra-free) logic for the GLOBALS harvester.

Many engine singletons live in untyped global data (`DAT_*`, an `undefined8` slot).
The decompiler can't propagate field accesses through an untyped global, so every
`[g_singleton]->+0x40` stays unknown -- and a class only reachable through a global
(never via an explicit `this` parameter) is invisible to the field discoverer. Worse
for the incremental cycle: a class can depend on another class's layout THROUGH a
global, an edge the struct-deref dependency model can't see.

The high-signal, decompiler-cheap way to type a global: a global passed as arg-0
(`this`) to a method whose param-0 is a known class C is strong evidence the global is
a `C *`. This module aggregates those `(global_addr, class, caller)` observations into
a per-global consensus type + confidence + a review rank -- the judgement call (accept
the type) is then a human/LLM decision applied authoritatively, exactly like the field
review queue. Kept Ghidra-free so the consensus logic is unit-testable; the driver does
the decompile + symbol typing.
"""
import collections


def aggregate_global_types(observations):
    """observations: iterable of (global_addr:int, class_name:str, caller:str).
    Returns {global_addr: {'type', 'votes', 'total', 'distinct', 'classes', 'callers'}}
    where `type` is the most-voted class, `votes` its count, `total` all observations,
    `distinct` the number of competing classes, `classes` the full vote tally, and
    `callers` up to 6 example caller names (reviewer leads)."""
    by_g = collections.defaultdict(list)
    for g, cls, caller in observations:
        if g is None or not cls:
            continue
        by_g[g].append((cls, caller))
    out = {}
    for g, obs in by_g.items():
        tally = collections.Counter(cls for cls, _ in obs)
        best, votes = tally.most_common(1)[0]
        callers = []
        for _cls, caller in obs:
            if caller and caller not in callers and len(callers) < 6:
                callers.append(caller)
        out[g] = {'type': best, 'votes': votes, 'total': len(obs),
                  'distinct': len(tally), 'classes': dict(tally), 'callers': callers}
    return out


def global_confidence(info):
    """Confidence that a global's inferred type is right.
      high   -- one class, seen at >=2 independent call sites (consensus, no conflict)
      medium -- one class, a single call site (plausible, wants a second look)
      low    -- competing classes across call sites (the global is reused, or some
                call site passes a base-class view) -> review must disambiguate."""
    if info['distinct'] == 1:
        return 'high' if info['total'] >= 2 else 'medium'
    # competing classes: a clear MAJORITY winner (more than half the call sites) is
    # still worth reviewing as mediumish; an even split means the global is genuinely
    # reused or a base-class view leaked in -> low, needs disambiguation.
    if 2 * info['votes'] > info['total']:
        return 'medium'
    return 'low'


def review_rank(info):
    """Sort key (descending) for the globals review worklist: strongest evidence and
    least ambiguity first, so a reviewer spends effort where the payoff is surest."""
    conf = {'high': 2, 'medium': 1, 'low': 0}[global_confidence(info)]
    return (conf, info['votes'], info['total'], -info['distinct'])


def to_rows(aggregated):
    """Flatten to review rows, best first: (global_addr, type, confidence, votes,
    total, distinct, classes_str, callers_str). decision left for the reviewer."""
    items = sorted(aggregated.items(), key=lambda kv: review_rank(kv[1]), reverse=True)
    rows = []
    for g, info in items:
        classes_str = ' '.join('%s:%d' % (c, n) for c, n in
                               sorted(info['classes'].items(), key=lambda kv: -kv[1]))
        rows.append((g, info['type'], global_confidence(info), info['votes'],
                     info['total'], info['distinct'], classes_str,
                     ' '.join(info['callers'])))
    return rows
