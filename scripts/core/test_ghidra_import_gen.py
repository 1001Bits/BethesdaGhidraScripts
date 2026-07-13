"""Unit tests for the pure parts of ghidra_import_gen's type-resolution helpers.

``ghidra_import_gen.py`` calls ``currentProgram.getDataTypeManager()`` at module
level, so it cannot be imported outside Ghidra.  ``_lookup_type`` and
``_resolve_struct_name`` depend only on the module-level ``created`` /
``_created_by_leaf`` / ``TEMPLATE_TYPE_MAP`` dicts, so their exact source is
extracted and exec'd in a sandboxed namespace with fake dicts -- no Ghidra
required.  Run with::

    python -m pytest scripts/core/test_ghidra_import_gen.py
"""
import os
import re

_SRC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'ghidra_import_gen.py')


def _extract(text, name, until):
    m = re.search(r'\ndef %s\(name\):.*?(?=\ndef %s)' % (name, until),
                  text, re.DOTALL)
    assert m, 'could not find %s in ghidra_import_gen.py' % name
    return m.group(0)


def _load_resolver(created, template_type_map):
    """Exec the real ``_lookup_type`` + ``_resolve_struct_name`` against fake
    globals, deriving ``_created_by_leaf`` the way ``_register_type`` does."""
    with open(_SRC_PATH, 'r', encoding='utf-8') as handle:
        text = handle.read()

    by_leaf = {}
    for full_name, dt in created.items():
        # _register_type indexes by the leaf of the *declared* name.  Template
        # instantiations are looked up exactly, never through the leaf index.
        if '<' in full_name:
            continue
        by_leaf.setdefault(full_name.split('::')[-1], []).append(dt)

    ns = {'created': created, '_created_by_leaf': by_leaf,
          'TEMPLATE_TYPE_MAP': template_type_map}
    source = (_extract(text, '_lookup_type', 'get_builtin') + '\n'
              + _extract(text, '_resolve_struct_name', 'resolve_type'))
    exec(compile(source, _SRC_PATH, 'exec'), ns)
    return ns['_resolve_struct_name']


def test_resolve_struct_name_simple_namespaced():
    # regression guard: plain 'NS::Type' still resolves via the leaf index
    resolve = _load_resolver({'TESForm': 'TESFORM_DT'}, {})
    assert resolve('RE::TESForm') == 'TESFORM_DT'
    assert resolve('TESForm') == 'TESFORM_DT'


def test_resolve_struct_name_ambiguous_leaf_never_auto_resolves():
    # our leaf index deliberately refuses to guess between same-leaf types
    resolve = _load_resolver({'A::Thing': 'A_DT', 'B::Thing': 'B_DT'}, {})
    assert resolve('C::Thing') is None


def test_resolve_struct_name_template_full_name_hit():
    resolve = _load_resolver({'RE::BSTArray<int>': 'ARR_DT'}, {})
    assert resolve('RE::BSTArray<int>') == 'ARR_DT'


def test_resolve_struct_name_template_alias():
    resolve = _load_resolver({'BSTArray<int>_ALIAS_DT': 'ALIAS_DT'},
                             {'RE::BSTArray<int>': 'BSTArray<int>_ALIAS_DT'})
    assert resolve('RE::BSTArray<int>') == 'ALIAS_DT'


def test_resolve_struct_name_nested_namespaced_template_arg():
    # the bug: the OUTER namespace prefix must be stripped, but the template
    # argument's own qualification must survive -- the live type keeps 'RE::'
    # inside the <> but not outside it.
    resolve = _load_resolver({'BSTEventSink<RE::MenuOpenCloseEvent>': 'SINK_DT'}, {})
    assert resolve('RE::BSTEventSink<RE::MenuOpenCloseEvent>') == 'SINK_DT'


def test_resolve_struct_name_nested_template_arg_naive_split_would_break():
    # a naive split('::')[-1] would yield 'MenuOpenCloseEvent>' -- splitting
    # INSIDE the template argument.  Confirm that mangled key is never used.
    resolve = _load_resolver({'MenuOpenCloseEvent>': 'WRONG_DT'}, {})
    assert resolve('RE::BSTEventSink<RE::MenuOpenCloseEvent>') is None


def test_resolve_struct_name_template_no_match_returns_none():
    resolve = _load_resolver({}, {})
    assert resolve('RE::BSTEventSink<RE::SomeUnknownEvent>') is None


def test_resolve_struct_name_degenerate_self_alias_falls_through():
    # TEMPLATE_TYPE_MAP can map a name to ITSELF -- a no-op alias resolving
    # nowhere.  Early-returning on any truthy alias would give up here even
    # though the namespace-stripped name is registered; it must fall through.
    name = 'RE::BSTEventSink<RE::MenuOpenCloseEvent>'
    resolve = _load_resolver({'BSTEventSink<RE::MenuOpenCloseEvent>': 'SINK_DT'},
                             {name: name})
    assert resolve(name) == 'SINK_DT'
