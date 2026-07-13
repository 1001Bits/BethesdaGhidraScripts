"""Pure (Ghidra-free) planning logic for the CommonLibVR enrich apply.

Kept separate from apply_enrich.py (which imports Ghidra) so the decision logic is
unit-testable without a Ghidra session. apply_enrich imports ACTION and
select_fill_targets from here.
"""

# Conflict-status -> high-level apply action.
ACTION = {
    'NEW': 'CREATE',
    'MATCH': 'REUSE',
    'GEN_EMPTY': 'REUSE',
    'STUB_FILL': 'FILL',      # existing is an EMPTY SAME-SIZE stub -> define its fields
                              # IN PLACE (fast replaceAtOffset); no replaceDataType /
                              # reference rewiring (type identity kept, size unchanged).
                              # Staging+replaceDataType per stub is ~2-3s each (rescans
                              # all functions) -- hours for AE's ~16.9k same-size stubs.
    'STUB_UPGRADE': 'REPLACE',  # empty stub of a DIFFERENT size -> must resize, so
                                # stage a correctly-sized shell and swap it in.
    'EXTENDS': 'REPLACE',
    'DIVERGENT': 'REPLACE',
    'DOUBLED': 'REPLACE',   # existing == 2x generated: import doubling artifact, generated correct
    'HANDCURATED': 'PROTECT',
    'VFTABLE_LOSS': 'PROTECT',
    'SUSPICIOUS': 'PROTECT',
    'EMBED_BASE': 'PROTECT',
}


def select_write_targets(plan, exclude_names=None, max_writes=0, prioritize_category=None):
    """Decide which write-actioned (CREATE/FILL/REPLACE) struct names should actually
    be applied this run, given a full computed `plan` (list of tuples whose first
    three elements are (name, status, action, ...) -- matches both apply_enrich.run's
    `plan` rows and conflict_report's CSV row shape).

    exclude_names : names to always skip this run (e.g. owned by concurrent manual
                    work) -- reported with their true status, never written.
    max_writes    : 0/None = unlimited; otherwise only the first N write-actioned,
                    non-excluded names (in `plan`'s order, or priority order if
                    prioritize_category is set) are selected, letting a caller
                    re-run with the same cap repeatedly to drain a backlog in
                    batches (already-applied structs classify as REUSE/MATCH on the
                    next call and are no longer write-actioned, so this is naturally
                    resumable without re-deriving progress).
    prioritize_category : if given (e.g. '/types.h'), write-actioned entries whose
                    existing_category (plan row index 5) equals this string are
                    selected before any others, preserving relative order within
                    each group. A capped batch would otherwise spend its budget
                    proportional to `plan`'s natural order -- and CommonLib's own
                    std/fmt/REX namespaces generate a huge volume of low-value,
                    deeply-nested template-instantiation noise (SFINAE helpers,
                    allocator/iterator internals) that can dominate a batch and
                    starve genuinely curated RE-relevant /types.h progress. This
                    lets curated work drain first; low-value library-internal
                    noise still gets applied, just after.

    Returns a set of names whose action should actually be applied this call.
    """
    excluded = set(exclude_names or ())
    eligible = []
    for entry in plan:
        name, _status, action = entry[0], entry[1], entry[2]
        if action not in ('CREATE', 'FILL', 'REPLACE'):
            continue
        if name in excluded:
            continue
        eligible.append(entry)

    if prioritize_category:
        cat_idx = 5
        def _is_priority(e):
            return len(e) > cat_idx and e[cat_idx] == prioritize_category
        eligible = [e for e in eligible if _is_priority(e)] + \
                   [e for e in eligible if not _is_priority(e)]

    allowed = set()
    for entry in eligible:
        if max_writes and len(allowed) >= max_writes:
            break
        allowed.add(entry[0])
    return allowed


def split_qualified(name):
    """Split a C++ qualified name on '::' at depth 0 only.

    A naive name.split('::') corrupts template instantiations -- e.g.
    'BSTArray<RE::TESForm>::push_back' must split to
    ['BSTArray<RE::TESForm>', 'push_back'], NOT on the '::' inside the angle
    brackets. We only split at '::' that sit outside any <>, (), [] nesting.

    Operators (operator<<, operator()) appear only as the trailing leaf, after
    every real class-level '::', so their unbalanced brackets do not affect the
    class-path splits that precede them.
    """
    parts = []
    depth = 0
    cur = []
    i = 0
    n = len(name)
    while i < n:
        c = name[i]
        if c in '<([':
            depth += 1
            cur.append(c)
        elif c in '>)]':
            if depth > 0:
                depth -= 1
            cur.append(c)
        elif c == ':' and depth == 0 and i + 1 < n and name[i + 1] == ':':
            parts.append(''.join(cur))
            cur = []
            i += 2
            continue
        else:
            cur.append(c)
        i += 1
    parts.append(''.join(cur))
    return parts


def class_namespace_plan(name, class_names):
    """Decide the namespace placement for a function whose name is a flat
    'A::B::Method' string.

    Returns None if the name has no qualifier (free function). Otherwise returns
    (ns_chain, leaf, class_index) where:
      ns_chain    = the qualifier components (everything before the leaf)
      leaf        = the method/short name to set on the function
      class_index = index into ns_chain that should be a GhidraClass (the class),
                    or None if the qualifier is not a known class (treat all
                    components as plain namespaces, e.g. a C++ namespace).

    class_names is a set of known class names; both the full qualifier
    ('A::B') and the leaf class component ('B') are accepted so a class is
    recognised whether class_names stores full or short names.

    Also normalizes two non-'::' forms to the real Ghidra class scheme:
      * IDA-style 'Class__Method' (double underscore, since IDA has no class
        namespaces) -> 'Class::Method' when 'Class' is a known class.
      * a redundant doubled class prefix in the leaf ('Class::Class_Method')
        -> 'Class::Method'.
    """
    # IDA-style Class__Method -> Class::Method (only when the head is a real class)
    if '::' not in name and '__' in name:
        head, _, rest = name.partition('__')
        if rest and head in class_names:
            name = head + '::' + rest

    parts = [p for p in split_qualified(name) if p]   # drop empty '::::' components
    if len(parts) < 2:
        return None
    leaf = parts[-1]
    if not leaf:
        return None
    ns_chain = parts[:-1]
    qual_full = '::'.join(ns_chain)
    class_index = None
    if qual_full in class_names or ns_chain[-1] in class_names:
        class_index = len(ns_chain) - 1
        cls = ns_chain[class_index]
        # strip a redundant 'Class_' / 'Class__' prefix the leaf sometimes carries
        # (e.g. MessageBoxMenu_RemoveMessageFromQueue, Actor__ProcessInWater).
        # Guard: keep the prefix when the remainder would start with a digit -- that
        # is an overload disambiguator (Class_2), not a doubled prefix.
        if leaf.startswith(cls + '_'):
            rest = leaf[len(cls):].lstrip('_')
            if rest and not rest[0].isdigit():
                leaf = rest
    return (ns_chain, leaf, class_index)


def enum_parent_key(category, name):
    """Parent-scoped match key for an enum: (last category component, leaf name),
    ignoring the root category (/CommonLibSSE, /CommonLibVR.pdb, /types.h, ...).
    Bare leaf names collide (every class has a 'Flag'); the parent component
    disambiguates, e.g. ('ACTOR_BASE_DATA', 'Flag')."""
    _ROOTS = ('CommonLibSSE', 'CommonLibVR.pdb', 'CommonLibVR', 'types.h',
              'Demangler', 'SkyrimSE.pdb', 'SkyrimVR.pdb', 'SkyrimAE.pdb', 'auto_structs')
    parts = [p for p in category.strip('/').split('/') if p]
    if parts and parts[0] in _ROOTS:
        parts = parts[1:]
    return (parts[-1] if parts else '', name)


def classify_enum(gen_size, gen_values, existing_size, existing_names):
    """Decide how a generated enum relates to an existing one. Lossless: EXTEND only
    ADDS names the existing enum lacks; it never removes manual values.

    Returns (action, add_values):
      NEW       existing is None                          -> create with gen_values
      KEEP_SIZE size differs                              -> keep existing, review (no repack)
      MATCH     same size, gen names subset of existing   -> reuse, nothing to add
      EXTEND    same size, gen has names existing lacks    -> add those (name,value) pairs
    """
    if existing_size is None:
        return ('NEW', list(gen_values))
    if gen_size != existing_size:
        return ('KEEP_SIZE', [])
    have = set(existing_names)
    add = [(n, v) for (n, v) in gen_values if n not in have]
    return ('MATCH', []) if not add else ('EXTEND', add)


def select_fill_targets(structs, classify_fn, live, create_struct, stage_struct,
                        register=None, action_map=ACTION):
    """Decide an action per generated struct and return (fill_list, staging).

    fill_list : [(struct_dt, st)] -- the shells WE own and must fill (CREATE +
                REPLACE). REUSE/PROTECT structs are never filled (existing types
                are not edited).
    staging   : {name: (staging_dt, existing_dt)} for the REPLACE swaps.

    create_struct(name, size, category) -> dt  creates a new shell (caller picks the
                                               target category from the generated one).
    stage_struct(name, size, existing) -> dt creates a staging shell to swap in.
    register(st, dt)                        optional: record dt (e.g. into created[]).

    REGRESSION GUARD: fill_list is built ONLY from struct CREATE/REPLACE actions,
    captured at creation time. It must never be re-derived from a shared name->dt
    map (e.g. `created`) that the enum pass also writes to -- an enum sharing a
    struct's leaf name would otherwise redirect a fill onto the enum object and
    crash (EnumDB has no getNumDefinedComponents). See
    test_apply_plan.test_enum_name_collision_does_not_pollute_fill_targets.
    """
    staging = {}
    fill_list = []
    for st in structs:
        name, gsize = st[0], st[1]
        c = classify_fn(st, live)
        action = action_map.get(c['status'], 'PROTECT')
        if action == 'CREATE':
            dt = create_struct(name, gsize, st[2])   # st[2] = generated category
            fill_list.append((dt, st))
        elif action == 'FILL':
            # existing empty stub: fill its fields IN PLACE (no staging, no
            # replaceDataType). The same-size existing type IS the keeper.
            dt = c['best']
            fill_list.append((dt, st))
        elif action == 'REPLACE':
            dt = stage_struct(name, gsize, c['best'])
            staging[name] = (dt, c['best'])
            fill_list.append((dt, st))
        else:  # REUSE / PROTECT -> keep existing, never fill
            dt = c['best']
        if register is not None:
            register(st, dt)
    return fill_list, staging
