"""Skyrim SE and AE are different address-library ID namespaces.

Regression for 2026-09-21: SE-only symbols were resolved through the 1.7.104
(AE-namespace) database and 437 labels landed on unrelated addresses.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
_TABLE = re.compile(r"^(SYMBOLS|FALLBACK_SYMBOLS) = _json\w*\.loads\((.*)\)\s*$")


_GENERATOR = []


def _generator():
    """Import this directory's generator regardless of test order.

    Every game directory has its own ``address_library`` / ``reloc_parser``;
    in a full run another game's copy may already sit in ``sys.modules``.
    """
    if _GENERATOR:
        return _GENERATOR[0]
    shadowed = ("address_library", "reloc_parser", "vtable_policy")
    saved = {name: sys.modules.pop(name) for name in shadowed
             if name in sys.modules}
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_parse_commonlib_types", HERE / "parse_commonlib_types.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
        for name in shadowed:
            sys.modules.pop(name, None)
        sys.modules.update(saved)
    _GENERATOR.append(module)
    return module


def test_se_only_symbol_gets_no_ae_namespace_offset():
    gen = _generator()
    # ID 100 exists in BOTH databases, as ~387k AE IDs do in the real SE
    # library; only the namespace, never the number, may decide the lookup.
    extra = (("16640", {100: 0x1111, 200: 0x2222}), ("17104", {100: 0x3333}))

    se_only = {"n": "VTABLE_SeOnly", "t": "label", "s": 0x10, "si": 100}
    gen.attach_extra_ae_offsets(se_only, None, extra)
    assert "16640" not in se_only and "17104" not in se_only

    dual = {"n": "Dual", "t": "func", "s": 0x10, "a": 0x20, "si": 100, "ai": 200}
    gen.attach_extra_ae_offsets(dual, 200, extra)
    assert dual["16640"] == 0x2222
    assert "17104" not in dual          # AE ID 200 is absent there: no fallback


def test_generation_fails_closed_on_an_se_only_ae_offset():
    gen = _generator()
    gen.assert_no_se_only_ae_offsets(
        [{"n": "ok", "ai": 5, "17104": 1}, {"n": "se", "si": 7, "s": 1, "v": 2}])
    with pytest.raises(RuntimeError, match="VTABLE_Bad"):
        gen.assert_no_se_only_ae_offsets([{"n": "VTABLE_Bad", "si": 7, "17104": 1}])


@pytest.mark.parametrize("script", sorted(
    (REPO / "ghidrascripts").glob("CommonLibImport_AE*.py")), ids=lambda p: p.name)
def test_generated_ae_importers_carry_no_se_only_ae_offsets(script):
    gen = _generator()
    found = 0
    with script.open(encoding="utf-8") as handle:
        for line in handle:
            match = _TABLE.match(line)
            if not match:
                continue
            found += 1
            symbols = json.loads(ast.literal_eval(match.group(2)))
            offenders = [s["n"] for s in symbols if s.get("ai") is None and
                         any(key in s for key in gen.EXTRA_AE_RUNTIMES)]
            assert offenders == [], "{}: {} SE-only symbols carry AE offsets".format(
                match.group(1), len(offenders))
    assert found == 2


# ---------------------------------------------------------------------------
# F6 (2026-09-21 audit): every AE runtime is resolved from the AE ID itself,
# never through a 1.6.1170 RVA round trip, and skyrimae.rename rows get the
# kind each runtime's own executable proves.
# ---------------------------------------------------------------------------

class _Layout:
    """``pe_layout.PELayout`` stand-in: RVAs below 0x1000 are code."""

    def __init__(self, sha):
        self.sha256 = sha

    def classify_rva(self, rva):
        if rva >= 0x9000:
            return 'unmapped', None
        return ('func', '.text') if rva < 0x1000 else ('label', '.data')


class _Lib:
    se_db = {7: 0x10}
    ae_db = {20: 0x20, 21: 0x2021, 23: 0x23}      # 1.6.1170
    db_16640 = {20: 0x120, 21: 0x121, 22: 0x2122, 23: 0x2123, 7: 0x666}
    db_17104 = {20: 0x220, 21: 0x2221, 7: 0x777}
    vr_db = {7: 0x70}


def test_parser_ae_id_resolves_each_runtime_without_a_1170_rva():
    gen = _generator()
    # AE id 22 does not exist in 1.6.1170 at all: there is no 'a' RVA to
    # reverse-map, yet 1.6.640 has the function.
    sym = gen.symbol_from_parser(
        {'name': 'OnlyIn640', 'class_': 'Actor', 'se_off': None, 'ae_off': None,
         'se_id': None, 'ae_id': 22}, 'func', {}, _Lib)
    assert sym['n'] == 'Actor::OnlyIn640' and sym['ai'] == 22
    assert sym['16640'] == 0x2122 and 'a' not in sym and '17104' not in sym


def test_other_ae_runtimes_survive_when_validation_deletes_the_1170_offset():
    gen = _generator()
    layouts = {'a': _Layout('a' * 64), '16640': _Layout('b' * 64)}
    # 'func' at 0x2021 is data in the 1.6.1170 exe -> 'a' is rejected; the
    # 1.6.640 offset (0x121, code) is independent evidence and must stay.
    sym = gen.symbol_from_parser(
        {'name': 'F', 'class_': None, 'se_off': 0x10, 'ae_off': 0x2021,
         'vr_off': 0x70, 'se_id': 7, 'ae_id': 21}, 'func', layouts, _Lib)
    gen.attach_address_library_ids([sym], _Lib, layouts)
    assert 'a' not in sym and sym['rejected_offsets'] == {'a': 'label'}
    assert sym['ai'] == 21 and sym['16640'] == 0x121
    assert sym['17104'] == 0x2221                 # no 17104 exe staged: kept as is
    assert sym['si'] == 7 and sym['v'] == 0x70


def test_se_only_symbol_never_gets_an_offset_from_an_ae_database():
    gen = _generator()
    # SE id 7 exists numerically in both extra AE databases.
    sym = gen.symbol_from_parser(
        {'name': 'VTABLE_SeOnly', 'se_off': 0x10, 'ae_off': None,
         'se_id': 7, 'ae_id': None}, 'label', {}, _Lib)
    gen.attach_address_library_ids([sym], _Lib, {})
    assert sym['si'] == 7 and 'ai' not in sym
    assert not any(key in sym for key in gen.EXTRA_AE_RUNTIMES)


def test_rename_rows_are_keyed_on_the_ae_id_and_classified_per_runtime(tmp_path):
    gen = _generator()
    rename = tmp_path / 'skyrimae.rename'
    rename.write_text(
        'version\n20 Actor__Update_*\n22 Gone_In_1170\n23 g_data\n'
        '99 Nowhere\nbad line\n', encoding='utf-8')
    ids = gen.load_ae_rename_ids(str(rename))
    assert ids == {20: 'Actor__Update', 22: 'Gone_In_1170', 23: 'g_data', 99: 'Nowhere'}
    # the old RVA-keyed view cannot even represent id 22
    assert gen.load_ae_rename_db(str(rename), _Lib.ae_db) == {
        0x20: 'Actor__Update', 0x23: 'g_data'}

    # Only 1.6.640 is staged -- exactly the situation in which every row used
    # to be validated as 'func' and the data rows were deleted.
    layouts = {'16640': _Layout('b' * 64)}
    symbols, by_name = [], {}
    added, merged = gen.merge_ae_rename(symbols, by_name, ids, _Lib, layouts)
    gen.attach_address_library_ids(symbols, _Lib, layouts)
    assert (added, merged) == (3, 0)
    named = {s['n']: s for s in symbols}
    assert 'Nowhere' not in named                       # resolves in no AE runtime
    assert named['Gone_In_1170']['ai'] == 22 and 'a' not in named['Gone_In_1170']
    assert named['g_data']['16640'] == 0x2123           # data row is NOT deleted
    assert named['g_data']['kinds'] == {'16640': 'label'}

    for_640 = {s['n']: s for s in gen.specialise_kinds_for_runtime(symbols, '16640')}
    assert for_640['Actor__Update']['t'] == 'func'
    assert for_640['g_data']['t'] == 'label'
    assert for_640['Gone_In_1170']['t'] == 'label'
    assert all('kinds' not in s for s in for_640.values())
    # a runtime without a staged exe keeps the declared kind
    assert {s['t'] for s in gen.specialise_kinds_for_runtime(symbols, 'a')} == {'func'}
    gen.assert_no_se_only_ae_offsets(symbols)


def test_rename_name_merge_is_undone_when_a_runtime_contradicts_it():
    gen = _generator()
    layouts = {'16640': _Layout('b' * 64)}
    existing = {'n': 'g_data', 't': 'func', 's': 0x10, 'si': 7, 'src': 'CommonLibSSE'}
    symbols, by_name = [existing], {'g_data': [existing]}
    # id 23 is data in 1.6.640 but the only same-named symbol is a function.
    added, merged = gen.merge_ae_rename(symbols, by_name, {23: 'g_data'}, _Lib, layouts)
    assert (added, merged) == (0, 0)
    assert 'ai' not in existing and 'a' not in existing and '16640' not in existing


def test_dropped_vtable_reports_name_each_runtimes_own_id(monkeypatch):
    """vtable_labels_dropped_s.csv recorded the AE ID (215718) for an SE row."""
    gen = _generator()
    seen = {}

    def fake_validate(symbols, layouts, class_labels, **kwargs):
        seen.update(kwargs)
        return {}

    monkeypatch.setattr(gen, 'validate_vtable_labels_for_layouts', fake_validate)
    gen.validate_vtable_labels([], {})
    fields = seen['id_fields']
    assert fields['s'] == ('si',) and fields['v'] == ('si',)
    assert all(fields[key] == ('ai',) for key in ('a', '16640', '17104'))


def test_a_runtime_that_will_be_emitted_requires_its_database():
    gen = _generator()
    staged = {'s': object(), '16640': object()}
    # every runtime is generated by default: a staged 1.6.640 needs its .bin
    assert gen._runtime_requested('16640', None, staged)
    assert not gen._runtime_requested('17104', None, staged)
    assert gen._runtime_requested('17104', {'17104'}, staged)    # --only
    assert not gen._runtime_requested('16640', {'se'}, staged)
