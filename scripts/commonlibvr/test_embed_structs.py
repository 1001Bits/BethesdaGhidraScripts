#!/usr/bin/env python3
"""Unit tests for ghidra_import_gen.embed_structs (compositional base embedding).

embed_structs turns the flat per-record layout (own + inherited fields, full nested
base chain in pdb_bases) into a compositional layout: each DIRECT base becomes a
`_base[_<Name>]` struct member at its offset, only the record's OWN fields remain,
and a base whose tail padding is reused by a sibling/own field is embedded as a
trimmed (data-size) variant. Falls back to a flat layout per struct on any anomaly.

These tests feed the inputs embed_structs sees AFTER the parser's direct/own split
(clang_types.SKIP_NESTED_BASE_FIELDS=True): fields = own-only, pdb_bases = direct
bases. No Ghidra session or clang needed.

Run: python -m pytest test_embed_structs.py   (or: python test_embed_structs.py)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
import ghidra_import_gen as gig  # noqa: E402


def _st(full, name, size, fields, pdb_bases=(), dsize=None, has_vtable=True):
    return {
        'full_name': full, 'name': name, 'size': size, 'dsize': dsize or size,
        'fields': [{'name': n, 'type': t, 'offset': o, 'size': s}
                   for (n, t, o, s) in fields],
        'bases': [b for b, _ in pdb_bases], 'pdb_bases': list(pdb_bases),
        'has_vtable': has_vtable,
    }


def _members(st):
    """(name, type, offset, size) tuples sorted by offset."""
    return [(f['name'], f['type'], f['offset'], f['size'])
            for f in sorted(st['fields'], key=lambda f: f['offset'])]


def _ni_hierarchy():
    """NiRefObject <- NiObjectNET <- NiAVObject <- NiNode, with own-only fields."""
    S = {}

    def add(x):
        S[x['full_name']] = x
    add(_st('RE::NiRefObject', 'NiRefObject', 16,
            [('__vftable', 'vtblptr:NiRefObject_vtbl', 0, 8), ('_refCount', 'u32', 8, 4)]))
    add(_st('RE::NiObjectNET', 'NiObjectNET', 48,
            [('name', 'struct:RE::BSFixedString', 16, 8), ('extra', 'ptr:void', 24, 8),
             ('cnt', 'u16', 32, 2)],
            [('RE::NiRefObject', 0)], dsize=34))
    add(_st('RE::NiAVObject', 'NiAVObject', 312,
            [('parent', 'ptr:void', 48, 8), ('flags', 'u32', 0x10c, 4)],
            [('RE::NiObjectNET', 0)]))
    add(_st('RE::NiNode', 'NiNode', 336,
            [('children', 'struct:RE::NiTArray', 0x138, 24)],
            [('RE::NiAVObject', 0)]))
    return S


def test_single_inheritance_embeds_direct_base():
    S = _ni_hierarchy()
    gig.embed_structs(S)
    # NiNode = _base: NiAVObject(312) + children@0x138 (no inherited fields inlined)
    assert _members(S['RE::NiNode']) == [
        ('_base', 'struct:RE::NiAVObject', 0, 312),
        ('children', 'struct:RE::NiTArray', 0x138, 24),
    ]


def test_intermediate_class_keeps_own_fields_only():
    S = _ni_hierarchy()
    gig.embed_structs(S)
    # NiAVObject embeds NiObjectNET(48) then its own parent@0x30, flags@0x10C only.
    assert _members(S['RE::NiAVObject']) == [
        ('_base', 'struct:RE::NiObjectNET', 0, 48),
        ('parent', 'ptr:void', 48, 8),
        ('flags', 'u32', 0x10c, 4),
    ]


def test_injected_vftable_dropped_when_primary_base_at_zero():
    S = _ni_hierarchy()
    # simulate inject_vtable_fields having added __vftable@0 to a derived's own fields
    S['RE::NiNode']['fields'].insert(
        0, {'name': '__vftable', 'type': 'vtblptr:NiNode_vtbl', 'offset': 0, 'size': 8})
    gig.embed_structs(S)
    names = [m[0] for m in _members(S['RE::NiNode'])]
    assert '__vftable' not in names          # covered by _base at 0
    assert names[0] == '_base'


def test_root_class_unchanged():
    S = _ni_hierarchy()
    gig.embed_structs(S)
    # NiRefObject has no bases -> left as-is
    assert _members(S['RE::NiRefObject']) == [
        ('__vftable', 'vtblptr:NiRefObject_vtbl', 0, 8),
        ('_refCount', 'u32', 8, 4),
    ]


def test_multiple_inheritance_embeds_each_base_at_its_offset():
    S = {}

    def add(x):
        S[x['full_name']] = x
    add(_st('RE::TESForm', 'TESForm', 32, [('formID', 'u32', 20, 4)], has_vtable=True))
    add(_st('RE::BSHandleRefObject', 'BSHandleRefObject', 16,
            [('_refCount', 'u32', 8, 4)], has_vtable=True))
    add(_st('RE::IFoo', 'IFoo', 8, [], has_vtable=True))
    # own fields come AFTER all base subobjects (MSVC layout): data at 56.
    add(_st('RE::TESObjectREFR', 'TESObjectREFR', 64,
            [('data', 'ptr:void', 56, 8)],
            [('RE::TESForm', 0), ('RE::BSHandleRefObject', 32), ('RE::IFoo', 48)]))
    gig.embed_structs(S)
    m = _members(S['RE::TESObjectREFR'])
    assert ('_base', 'struct:RE::TESForm', 0, 32) in m
    assert ('_base_BSHandleRefObject', 'struct:RE::BSHandleRefObject', 32, 16) in m
    assert ('_base_IFoo', 'struct:RE::IFoo', 48, 8) in m
    assert ('data', 'ptr:void', 56, 8) in m


def test_tail_padding_reuse_creates_trimmed_variants():
    """B0 sizeof 0x20/dsize 0x1a, B1 sizeof 0x10/dsize 0xc; D packs B0@0, B1@0x1a,
    own@0x26 -> both bases reuse tail padding -> both embedded trimmed, own kept."""
    S = {}

    def add(x):
        S[x['full_name']] = x
    add(_st('RE::B0', 'B0', 0x20, [('__vftable', 'vtblptr:B0_vtbl', 0, 8),
                                    ('flag', 'u8', 0x10, 1)], dsize=0x1a))
    add(_st('RE::B1', 'B1', 0x10, [('__vftable', 'vtblptr:B1_vtbl', 0, 8),
                                   ('y', 'u32', 8, 4)], dsize=0xc))
    add(_st('RE::D', 'D', 0x30, [('own', 'u32', 0x26, 4)],
            [('RE::B0', 0), ('RE::B1', 0x1a)]))
    gig.embed_structs(S)
    m = _members(S['RE::D'])
    assert m == [
        ('_base', 'struct:RE::B0__embed_1A', 0, 0x1a),
        ('_base_B1', 'struct:RE::B1__embed_C', 0x1a, 0xc),
        ('own', 'u32', 0x26, 4),
    ]
    # trimmed variants exist, sized to dsize, byte-accurate prefix
    assert S['RE::B0__embed_1A']['size'] == 0x1a
    assert S['RE::B1__embed_C']['size'] == 0xc


def test_unresolved_base_falls_back_to_flatten():
    S = {}

    def add(x):
        S[x['full_name']] = x
    # base 'RE::Missing' not in the set -> cannot embed -> flatten using own fields
    add(_st('RE::Widget', 'Widget', 24,
            [('__vftable', 'vtblptr:Widget_vtbl', 0, 8), ('x', 'u32', 16, 4)],
            [('RE::Missing', 0)]))
    gig.embed_structs(S)
    m = _members(S['RE::Widget'])
    # no _base member; original own fields preserved (flatten fallback)
    assert all(not n.startswith('_base') for (n, _t, _o, _s) in m)
    assert ('x', 'u32', 16, 4) in m


def test_no_bases_left_unchanged():
    S = {}
    S['RE::Plain'] = _st('RE::Plain', 'Plain', 12,
                         [('a', 'u32', 0, 4), ('b', 'u64', 4, 8)], has_vtable=False)
    before = _members(S['RE::Plain'])
    gig.embed_structs(S)
    assert _members(S['RE::Plain']) == before


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print('PASS', fn.__name__)
        except Exception:
            failed += 1
            print('FAIL', fn.__name__)
            traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
