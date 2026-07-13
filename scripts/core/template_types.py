"""
template_types.py
-----------------
Optional pipeline step for handling C++ template instantiation type names in
the Ghidra import pipeline.

Scans struct field/vtable descriptors and raw signature strings for template
instantiation names (anything of the form ``Word<...>``), and produces an
embeddable ``TEMPLATE_TYPE_MAP`` dict for generated Ghidra scripts.

At Ghidra runtime the generated script uses the map to resolve template
struct references in field type descriptors via ``_resolve_struct_name()``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class TemplateResult:
    """
    Output of :func:`process_template_types` / :func:`build_template_result`.

    Attributes
    ----------
    template_map:
        Maps the original C++ template instantiation name to itself (identity).
        Used at Ghidra runtime by ``_resolve_struct_name()`` to look up
        template struct types in the ``created`` dict.
    map_source:
        Python source text for the ``TEMPLATE_TYPE_MAP`` variable, ready to
        be embedded verbatim in a generated Ghidra script.
    """
    template_map: Dict[str, str] = dc_field(default_factory=dict)
    map_source: str = 'TEMPLATE_TYPE_MAP = {}\n'



# ---------------------------------------------------------------------------
# Template name extraction
# ---------------------------------------------------------------------------

# Matches an optionally namespace-qualified identifier immediately followed by
# '<', e.g. "NiPointer<", "RE::NiPointer<", "RE::BSTArray<"
_IDENT_LT = re.compile(r'((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*<')


def extract_template_names(text: str) -> Set[str]:
    """Extract all C++ template instantiation names from *text*.

    Handles arbitrarily-nested angle brackets.  Returns every distinct
    ``Word<...>`` substring found, including inner templates.  Comparisons
    (``operator<``, ``a < b``) are filtered out because they don't match the
    ``identifier<`` pattern or have unbalanced brackets.

    Examples::

        >>> extract_template_names('NiPointer<BSTriShape> * foo(BSTArray<int> a)')
        {'NiPointer<BSTriShape>', 'BSTArray<int>'}
        >>> extract_template_names('BSTArray<NiPointer<X>>')
        {'BSTArray<NiPointer<X>>', 'NiPointer<X>'}
    """
    found: Set[str] = set()
    _collect_templates(text, found)
    return found


def _collect_templates(text: str, found: Set[str]) -> None:
    """Recursive worker for :func:`extract_template_names`."""
    i = 0
    n = len(text)
    while i < n:
        m = _IDENT_LT.search(text, i)
        if m is None:
            break
        id_start = m.start()   # start of identifier
        lt_pos   = m.end() - 1  # position of '<'

        # Walk forward to find the matching '>'
        depth = 1
        j = lt_pos + 1
        while j < n and depth > 0:
            c = text[j]
            if c == '<':
                depth += 1
            elif c == '>':
                depth -= 1
            j += 1

        if depth != 0:
            # Unmatched '<' (e.g. comparison operator) — skip past it
            i = lt_pos + 1
            continue

        full_name = text[id_start:j]
        found.add(full_name)

        # Recurse into the argument list to capture nested instantiations
        inner = text[lt_pos + 1 : j - 1]
        _collect_templates(inner, found)

        i = j


def _templates_from_descriptor(desc: str) -> Set[str]:
    """Extract template instantiation names from a type descriptor string.

    Descriptors produced by ``_map_type`` look like::

        'ptr:struct:RE::NiPointer<RE::BSTriShape>'
        'struct:BSTArray<NiPointer<X>>'
        'arr:8:struct:BSSimpleList<TESForm *>'

    The type name (which may contain ``::`` namespace separators) is everything
    after the last recognised prefix token (``ptr``, ``struct``, ``enum``,
    ``arr``, or a numeric array size).  A naive ``.split(':')`` would break
    ``::`` into empty segments, so we protect ``::`` with a sentinel first.
    """
    if '<' not in desc:
        return set()
    # Protect C++ '::' namespace separators from being split on ':'
    protected = desc.replace('::', '\x00')
    for part in reversed(protected.split(':')):
        restored = part.replace('\x00', '::')
        if '<' in restored:
            return extract_template_names(restored)
    return set()


# ---------------------------------------------------------------------------
# Collection pass
# ---------------------------------------------------------------------------

def collect_template_names(
    structs: dict,
    sig_strings: Optional[List[str]] = None,
) -> Set[str]:
    """Scan struct field/vtable descriptors and optional signature strings.

    Parameters
    ----------
    structs:
        Dict of struct info dicts as produced by ``clang_types.collect_types()``.
        Each entry is expected to have:

        - ``'fields'``: list of ``{'type': descriptor_str, ...}``
        - ``'vtable_slots'``: list of
          ``{'ret': descriptor_str, 'params': [(name, descriptor_str), ...]}``

    sig_strings:
        Optional list of raw C/C++ signature strings (e.g. ``symbol['sig']``
        values from the relocation symbol table).

    Returns
    -------
    Set[str]
        Unique template instantiation name strings found across all inputs.
    """
    found: Set[str] = set()

    def collect_value(value) -> None:
        if isinstance(value, str):
            if '<' in value:
                found.update(extract_template_names(value))
            return
        if isinstance(value, dict):
            for nested in value.values():
                collect_value(nested)
            return
        if isinstance(value, (list, tuple, set)):
            for nested in value:
                collect_value(nested)

    for info in structs.values():
        # Include the instantiation itself and template base classes, even when
        # the type has no data fields.
        collect_value(info.get('full_name', ''))
        collect_value(info.get('bases', []))
        for f in info.get('fields', []):
            found |= _templates_from_descriptor(f.get('type', ''))

        for slot in info.get('vtable_slots', []):
            found |= _templates_from_descriptor(slot.get('ret', ''))
            for _pname, ptype in slot.get('params', []):
                found |= _templates_from_descriptor(ptype)

        # clang_types stores callable types in these dictionaries rather than
        # ``vtable_slots``.  Missing them dropped templates that appeared only
        # in method returns/parameters (a common smart-pointer/container case).
        for key in ('vmethods', 'methods', 'method_sigs'):
            collect_value(info.get(key, {}))

    for sig in (sig_strings or []):
        if '<' in sig:
            found |= extract_template_names(sig)

    return found


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def build_template_result(template_names: Set[str]) -> TemplateResult:
    """Build a :class:`TemplateResult` from a set of template instantiation names.

    If *template_names* is empty the returned result is still valid: the
    Python source defines an empty map so the generated Ghidra scripts
    compile and run without special-casing.

    Parameters
    ----------
    template_names:
        Output of :func:`collect_template_names`.

    Returns
    -------
    TemplateResult
    """
    if not template_names:
        return TemplateResult()

    template_map: Dict[str, str] = {}
    for name in sorted(template_names):
        template_map[name] = name

    if not template_map:
        return TemplateResult()

    map_lines = ['TEMPLATE_TYPE_MAP = {']
    for orig in sorted(template_map):
        map_lines.append(f'    {orig!r}: {template_map[orig]!r},')
    map_lines.append('}')
    map_source = '\n'.join(map_lines) + '\n'

    return TemplateResult(
        template_map=template_map,
        map_source=map_source,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def process_template_types(
    structs: dict,
    sig_strings: Optional[List[str]] = None,
) -> TemplateResult:
    """Scan for template instantiation names and build the type map.

    Parameters
    ----------
    structs:
        Struct info dict from ``clang_types.collect_types()``.
        Pass ``{}`` when only scanning signature strings.
    sig_strings:
        Optional list of raw C++ signature strings to scan.

    Returns
    -------
    TemplateResult
        Write ``.map_source`` verbatim into the generated Ghidra script
        alongside the other module-level constants.
    """
    names  = collect_template_names(structs, sig_strings)
    result = build_template_result(names)

    return result
