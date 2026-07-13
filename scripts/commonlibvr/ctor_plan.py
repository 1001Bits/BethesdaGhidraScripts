"""Pure (Ghidra-free) logic for the constructor-mining review aid.

A class constructor assigns each member from a typed, named parameter
(`this->Object_18 = a_object` where `a_object` is `TESBoundObject*`), so one decompile
both NAMES and TYPES many fields at once -- far more reliable than the size-only
dataflow guesses the discovery cycle makes (which mis-typed Crime+0x58 as a faction).

This module holds the rule-expressible bits: recognizing a constructor by name and
turning a constructor parameter name into a field name. The driver (ctor_mine.py)
finds the constructor, decompiles it, and reads the `this->field = a_param`
assignments out of the pcode; the proposals feed the review queue / cross-version
apply (high-accuracy field names + types). Kept Ghidra-free so it is unit-testable.
"""
import re

_ARG_PREFIX = re.compile(r'^(?:a_|p_|param_?)', re.IGNORECASE)
# generic decompiler-invented arg names that carry no field meaning
_NOISE = {'this', 'param', 'arg', 'a', 'p', 'x', 'in', 'out', 'result', 'retval'}


def is_ctor(func_name, class_name):
    """Heuristic: is `func_name` a constructor of `class_name`? Matches a `_ctor`
    suffix, the bare class name (`Class::Class` leaf), or 'constructor' in the name.
    Deliberately conservative -- a `_ctor` suffix is the strong signal; a substring
    like 'ctor' alone would false-match names like 'DoActor'."""
    if not func_name:
        return False
    leaf = func_name.split('::')[-1]
    return (leaf == class_name
            or leaf.endswith('_ctor')
            or leaf.endswith('::' + class_name)
            or 'constructor' in leaf.lower())


def field_label(param_name):
    """Turn a constructor parameter name into a field name: drop the `a_`/`p_` arg
    prefix ('a_object' -> 'object'). Returns None for absent or noise-only names so the
    driver keeps the type but not a meaningless name."""
    if not param_name:
        return None
    n = _ARG_PREFIX.sub('', param_name).strip()
    if not n or n.lower() in _NOISE:
        return None
    return n


def best_ctor(candidates):
    """Pick the most informative constructor from (func_id, assignment_count) pairs:
    the one that assigns the most fields (ties -> first). None if none assign any."""
    best = None
    for fid, n in candidates:
        if n > 0 and (best is None or n > best[1]):
            best = (fid, n)
    return best[0] if best else None
