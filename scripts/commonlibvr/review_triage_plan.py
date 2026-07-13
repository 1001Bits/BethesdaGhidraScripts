"""Pure (Ghidra-free) logic to TRIAGE the LLM-review queue by UNLOCK SURFACE.

The review queue ranks size-only fields by CONFIDENCE (how sure the decompiler is the
field exists). That answers "is it real?", not "is it worth my judgment?". The
incremental cycle's dependency graph answers the second question: discover_state.json
records, per class, the `refs` it dereferences. INVERT that -> the set of classes that
DEPEND ON a class T. Typing a field that anchors T makes T's layout flow into every
dependent, so the unlock surface of resolving a field in class C is the remaining
unknown-field count across C's TRANSITIVE dependents. A keystone class (many dependents,
each with unknowns) is where one LLM decision cascades; a leaf class unlocks nothing.

So we point the same propagation the dirty-tracking uses (refs intersect changed) the
other way, to fixpoint, and weight by remaining unknowns. Pointer fields rank above
scalars because only a pointer creates a new anchor; a scalar (refcount/flag) resolves
in place and propagates nothing. Kept Ghidra-free so the ranking is unit-testable; the
driver supplies the live state, queue, and per-class unknown counts.
"""
import collections


def build_dependents(state_classes):
    """Invert the refs graph: type name -> set of class names that dereference it.
    `state_classes` is {class: {'refs': [base type names], ...}} from discover_state."""
    dep = collections.defaultdict(set)
    for cls, rec in state_classes.items():
        refs = rec.get('refs') if isinstance(rec, dict) else None
        for r in (refs or ()):
            dep[r].add(cls)
    return dep


def unlock_closure(seed, dependents, max_nodes=5000):
    """The transitive set of classes that depend on `seed` (the classes that would be
    re-mined, and could surface new fields, once `seed` becomes a better anchor).
    Includes `seed` itself (typing its field re-mines it). Capped for safety."""
    seen = {seed}
    frontier = [seed]
    while frontier:
        n = frontier.pop()
        for d in dependents.get(n, ()):
            if d not in seen:
                seen.add(d)
                frontier.append(d)
                if len(seen) >= max_nodes:
                    return seen
    return seen


def unlock_score(seed, dependents, unknown_counts):
    """(weighted unlock, dependent count): weighted = total remaining unknown fields
    across seed's dependent-closure -- how many fields could become discoverable if a
    field anchoring `seed` is resolved."""
    closure = unlock_closure(seed, dependents)
    weighted = sum(int(unknown_counts.get(c, 0)) for c in closure)
    return weighted, len(closure)


def triage(fields, state_classes, unknown_counts):
    """Rank review candidates by unlock surface. `fields` is a list of dicts with at
    least 'class' (and optionally 'offset', 'is_pointer', 'votes'). Returns the list
    annotated with 'unlock_score' / 'dependents' and sorted highest-unlock first;
    pointer fields (anchor-creating) and higher-vote fields break ties."""
    dep = build_dependents(state_classes)
    cache = {}
    out = []
    for f in fields:
        cls = f['class']
        if cls not in cache:
            cache[cls] = unlock_score(cls, dep, unknown_counts)
        weighted, ndep = cache[cls]
        g = dict(f)
        g['unlock_score'] = weighted
        g['dependents'] = ndep
        out.append(g)
    out.sort(key=lambda x: (x['unlock_score'],
                            1 if x.get('is_pointer') else 0,
                            int(x.get('votes', 0))),
             reverse=True)
    return out
