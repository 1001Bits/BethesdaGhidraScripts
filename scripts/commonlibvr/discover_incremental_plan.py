"""Pure (Ghidra-free) logic for INCREMENTAL discovery -- decide which classes a
discovery pass must re-mine, instead of re-decompiling the whole function tree every
cycle.

A function's decompilation (and therefore the struct-field facts it yields) is a pure
function of its bytes, its signature, the types it dereferences, and its callees'
signatures. Its bytes never change. So across cycles of the population loop, re-mining
a class whose dependency closure was untouched reproduces identical facts -- pure
waste. Cycle 1 must be cold (mine everything); cycles 2..N only need the DIRTY set.

The unit of layout change here is the STRUCT, so one "changed" set drives invalidation:
the set of class names whose /types.h struct gained a field in the previous pass. A
class D is dirty next pass iff:
  * D's own struct changed         -- a new field is a fresh anchor; D's methods may
                                       now reveal MORE of D, OR
  * D dereferences a changed class -- refs(D) intersects `changed`; the decompiler now
                                       propagates that class's new field through D.

refs(D) is captured during mining (the base names of the types D's methods resolve at
its unknown offsets). The callee-SIGNATURE path (a propagate/thiscall stage changing a
function prototype) is NOT modelled here -- those stages converge in cycle 1, so from
cycle 2 on discovery is the only active stage and the deref rule is sound. The driver
falls back to a full (cold) pass for any cycle in which a signature-changing stage ran,
and whenever too many structs changed at once (cheap insurance against an
under-captured edge). Over-approximate, never under-approximate: a redundant decompile
costs time; a missed one costs a discovery.
"""


def base_type(typename):
    """Strip pointer/`*64` decoration and whitespace to the base type name
    ('TESBoundObject *64' -> 'TESBoundObject'). '' for empties."""
    t = (typename or '').replace(' ', '')
    while t.endswith('*') or t.endswith('64'):
        t = t[:-2] if t.endswith('64') else t[:-1]
    return t


def compute_dirty(prior_classes, changed, full_threshold=200):
    """Decide which classes the next discovery pass must re-mine.

    prior_classes: {class_name: {'refs': [base type names it dereferences], ...}} from
                   the previous pass's persisted state.
    changed:       iterable of class names whose struct gained a field last pass.
    full_threshold: if more than this many structs changed, force a cold pass (the
                   incremental set would be large and the risk of an under-captured
                   edge grows -- just re-mine everything).

    Returns (dirty, reason):
      * (None, 'cold')        -- no prior state; caller mines ALL classes.
      * (None, 'many-changed')-- too many structs changed; caller mines ALL classes.
      * (set(), 'noop')       -- nothing changed; caller mines nothing.
      * (set([...]), 'incremental') -- the dirty class names to re-mine.
    The driver intersects the returned names with classes that ACTUALLY still carry
    unknown fields (re-derived live), so a class with nothing left to fill is dropped
    even if it lands in the dirty set."""
    if not prior_classes:
        return (None, 'cold')
    changed = set(changed)
    if not changed:
        return (set(), 'noop')
    if len(changed) > full_threshold:
        return (None, 'many-changed')
    dirty = set(changed)                      # self-deepen: a changed struct re-mines
    for name, rec in prior_classes.items():
        refs = rec.get('refs') if isinstance(rec, dict) else None
        if refs and (set(refs) & changed):
            dirty.add(name)                   # D dereferences a changed class
    return (dirty, 'incremental')


def merge_state(prior_classes, mined):
    """Carry forward state for classes NOT mined this pass; overwrite the ones that
    were. `prior_classes` and `mined` are {class_name: record}. Returns the merged map
    so a warm (partial) pass does not drop the refs of classes it skipped."""
    out = dict(prior_classes or {})
    out.update(mined or {})
    return out
