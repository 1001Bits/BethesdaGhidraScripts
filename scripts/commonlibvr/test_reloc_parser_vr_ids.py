"""CommonLibVR address layer: no last-wins reverse maps, version-checked DBs.

Regression (2026-09-21 audit, F7): VR offsets of src/*.cpp functions were
recovered by reverse-mapping ``se_off`` through ``{rva: id}`` built with a dict
comprehension -- when two SE IDs share an RVA the LAST one wins and its VR
offset is attached.  The scanner now carries the SE ID it parsed; the generator
uses ``unique_reverse_ids`` and passes ``expected_version`` to ``load_bin``.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent

SRC_CPP = """namespace RE
{
	void Actor::AddSpell(SpellItem* a_spell)
	{
		using func_t = decltype(&Actor::AddSpell);
		static REL::Relocation<func_t> func{ RELOCATION_ID(100, 400) };
		return func(this, a_spell);
	}
}
"""


def _reloc_parser():
    spec = importlib.util.spec_from_file_location(
        "clvr_reloc_parser_under_test", HERE / "reloc_parser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_src_vr_offset_comes_from_the_parsed_se_id_not_a_last_wins_map(tmp_path):
    rp = _reloc_parser()
    (tmp_path / "Actor.cpp").write_text(SRC_CPP, encoding="utf-8")
    # SE ids 100 and 999 share one RVA; a {rva: id} comprehension keeps 999.
    lib = SimpleNamespace(
        se_db={100: 0x1000, 999: 0x1000}, ae_db={400: 0x4000},
        vr_db={100: 0x7100, 999: 0xBAD})
    funcs = rp.collect_src_relocations(str(tmp_path), lib, {})
    assert [(f["class_"], f["name"], f["se_id"], f["vr_off"]) for f in funcs] == [
        ("Actor", "AddSpell", 100, 0x7100)]


def test_reverse_lookup_fallback_refuses_an_ambiguous_rva():
    rp = _reloc_parser()
    reverse, ambiguous = rp.unique_reverse_ids({100: 0x1000, 999: 0x1000, 5: 0x2000})
    assert reverse == {0x2000: 5} and ambiguous == {0x1000}


def _calls(tree, attribute):
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == attribute]


def test_generator_checks_database_versions_and_uses_unique_reverse_maps():
    source = (HERE / "parse_commonlib_types.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    load_bins = _calls(tree, "load_bin")
    assert len(load_bins) == 2
    versions = []
    for call in load_bins:
        keywords = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
        versions.append(keywords.get("expected_version"))
    assert versions == [(1, 5, 97, 0), (1, 6, 1170, 0)]
    # no ``{v: k for k, v in <db>.items()}`` reverse map is left
    for node in ast.walk(tree):
        if isinstance(node, ast.DictComp):
            assert not (isinstance(node.key, ast.Name) and isinstance(node.value, ast.Name)
                        and len(node.generators) == 1
                        and isinstance(node.generators[0].iter, ast.Call)
                        and getattr(node.generators[0].iter.func, "attr", "") == "items"
                        and "_db" in ast.unparse(node.generators[0].iter))
    assert "unique_reverse_ids(addr_lib.se_db)" in source
    assert "unique_reverse_ids(addr_lib.ae_db)" in source


def _clvr_generator(monkeypatch):
    """Import parse_commonlib_types without the openvr/DirectXTK submodules
    (its module-level include check only matters for a real clang parse)."""
    import os
    import sys
    # Every game directory has its own copy of these; in a full run another
    # game's module may already sit in sys.modules.
    names = ("parse_commonlib_types", "vtable_policy", "address_library",
             "reloc_parser", "bytesig_evidence")
    saved_modules = {name: sys.modules.pop(name, None) for name in names}
    saved_path = list(sys.path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(os.path, "isdir", lambda _path: True)
            patch.setenv("CLVR_EMBED", "0")
            spec = importlib.util.spec_from_file_location(
                "clvr_generator_under_test", HERE / "parse_commonlib_types.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded = {name: sys.modules.get(name) for name in names}
    finally:
        sys.path[:] = saved_path
        for name, previous in saved_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    # _build_symbols imports address_library lazily: keep this game's copies
    # visible for the rest of the test (monkeypatch restores them).
    for name, loaded_module in loaded.items():
        if loaded_module is not None:
            monkeypatch.setitem(sys.modules, name, loaded_module)
    return module


class _Layout:
    """Staged VR executable: .text below 0x9000, .rdata/.data above."""
    sha256 = "e" * 64

    def classify_rva(self, rva):
        if rva < 0x9000:
            return "func", ".text"
        return "label", ".rdata"


def test_vr_symbols_are_validated_against_the_staged_exe(monkeypatch):
    gen = _clvr_generator(monkeypatch)
    funcs = [
        {"class_": "Actor", "name": "AddSpell", "vr_off": 0x1000},
        {"class_": "ActorValueList", "name": "GetSingleton", "vr_off": 0x9100},
        {"class_": "BGSEntryPoint", "name": "if", "vr_off": 0x1200},
    ]
    labels = [{"name": "VTABLE_Actor", "vr_off": 0x9200},
              {"name": "RTTI_Code", "vr_off": 0x1300}]
    fake_rp = SimpleNamespace(
        collect_relocations=lambda *a, **k: (funcs, labels, {}, set(), {}, {}),
        collect_src_relocations=lambda *a, **k: [])
    monkeypatch.setattr(gen, "_load_commonlibvr_reloc_parser", lambda: fake_rp)
    monkeypatch.setattr(gen, "CLVR_SRC", str(HERE / "does-not-exist"))
    lib = SimpleNamespace(se_db={}, ae_db={}, vr_db={})

    import json
    symbols = {s["n"]: s for s in json.loads(
        gen._build_symbols(lib, target_layouts={"v": _Layout()}))}

    assert "BGSEntryPoint::if" not in symbols            # keyword, not a method
    assert symbols["Actor::AddSpell"]["v"] == 0x1000
    assert symbols["Actor::AddSpell"]["target_sha256"] == {"v": "e" * 64}
    data_func = symbols["ActorValueList::GetSingleton"]   # .rdata: not a function
    assert "v" not in data_func and data_func["rejected_offsets"] == {"v": "label"}
    assert symbols["VTABLE_Actor"]["v"] == 0x9200
    assert "v" not in symbols["RTTI_Code"]                # label in code
