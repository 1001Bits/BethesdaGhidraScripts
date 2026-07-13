"""Pure (Ghidra-free) logic for constructor-mining field recovery.

Technique adapted from alandtse's CommonLibVR fork.  A class constructor
assigns each member from a typed, named parameter
(``this->Object_18 = a_object`` where ``a_object`` is ``TESBoundObject*``),
so decompiling ONE constructor yields both the NAME and the TYPE of many
fields at once -- far more reliable than size-only dataflow guesses.

This module holds the rule-expressible bits: recognizing a constructor by
name and turning a constructor parameter name into a field name.  The
driver (ctor_mine.py) finds the constructor, decompiles it, and reads the
``this->field = a_param`` assignments out of the pcode.  Kept Ghidra-free
so it is unit-testable.
"""
import re

_ARG_PREFIX = re.compile(r'^(?:a_|p_|param_?)', re.IGNORECASE)
# Generic decompiler-invented arg names that carry no field meaning.
_NOISE = {'this', 'param', 'arg', 'a', 'p', 'x', 'in', 'out', 'result', 'retval'}


def is_ctor(func_name, class_name):
    """Heuristic: is ``func_name`` a constructor of ``class_name``?

    Matches a ``_ctor`` suffix, the bare class-name leaf (``Class::Class``),
    a trailing ``::Class``, or 'constructor' in the leaf.  Conservative --
    a ``_ctor`` suffix is the strong signal; a bare 'ctor' substring would
    false-match names like 'DoActor'.
    """
    if not func_name:
        return False
    leaf = func_name.split('::')[-1]
    lower_leaf = leaf.lower()
    if leaf.startswith('~') or 'destructor' in lower_leaf or 'deleting_dtor' in lower_leaf:
        return False
    return (leaf == class_name
            or leaf.endswith('_ctor')
            or leaf.endswith('::' + class_name)
            or 'constructor' in lower_leaf)


def field_label(param_name):
    """Constructor parameter name -> field name.

    Drops the ``a_``/``p_`` arg prefix ('a_object' -> 'object').  Returns
    None for absent or noise-only names so the driver keeps the type but
    not a meaningless name.
    """
    if not param_name:
        return None
    n = _ARG_PREFIX.sub('', param_name).strip()
    if not n or n.lower() in _NOISE:
        return None
    return n


def best_ctor(candidates):
    """Pick the most informative constructor from (func_id, assign_count).

    The one that assigns the most fields (ties -> first); None if none
    assign any.
    """
    best = None
    for fid, n in candidates:
        if n > 0 and (best is None or n > best[1]):
            best = (fid, n)
    return best[0] if best else None


def field_consensus(observations, min_independent=2):
    """Resolve constructor field evidence without last-writer-wins guesses.

    ``observations`` contains ``(offset, type_name, field_name, constructor)``.
    Duplicate observations from the same constructor count once.  A proposal
    is returned only when at least ``min_independent`` constructors agree and
    no competing type/name has equal support.
    """
    by_offset = {}
    seen = set()
    for offset, type_name, field_name, constructor in observations:
        if offset is None or not type_name or not constructor:
            continue
        key = (int(offset), type_name, field_name or '', constructor)
        if key in seen:
            continue
        seen.add(key)
        proposal = (type_name, field_name or '')
        by_offset.setdefault(int(offset), {}).setdefault(proposal, set()).add(constructor)

    resolved = {}
    ambiguous = {}
    for offset, proposals in by_offset.items():
        ranked = sorted(proposals.items(), key=lambda item: (-len(item[1]), item[0]))
        winner, constructors = ranked[0]
        runner_count = len(ranked[1][1]) if len(ranked) > 1 else 0
        if len(constructors) >= min_independent and len(constructors) > runner_count:
            resolved[offset] = {
                'type': winner[0], 'name': winner[1] or None,
                'votes': len(constructors),
                'constructors': sorted(constructors),
                'confidence': 'high',
            }
        else:
            ambiguous[offset] = [
                {'type': proposal[0], 'name': proposal[1] or None,
                 'votes': len(ctors), 'constructors': sorted(ctors)}
                for proposal, ctors in ranked
            ]
    return resolved, ambiguous
