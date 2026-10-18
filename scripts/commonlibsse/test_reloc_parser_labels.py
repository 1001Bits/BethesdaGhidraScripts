"""Label / function coverage of the CommonLibSSE relocation scanner.

Regressions (2026-09-21 audit):
  F5  ``_RTTI_RE`` matched only brace-init ``RTTI_X{ n }``.  The SE half of
      Offsets_RTTI.h is call-init ``RTTI_X(static_cast<std::uint64_t>(n))`` so
      1 of 7,686 SE RTTI labels parsed, and Offsets_NiRTTI.h was never scanned.
  F7  the src/*.cpp scanner never set ``vr_off`` (718 VR functions lost).
  F6  the parser dropped the IDs it had just read, so later stages recovered
      the AE ID from a 1.6.1170 RVA.

Every ID below exists in BOTH namespaces with different RVAs -- as ~387k real
IDs do -- so a lookup in the wrong namespace shows up as a wrong offset.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def _parser():
    spec = importlib.util.spec_from_file_location(
        "sse_reloc_parser_under_test", HERE / "reloc_parser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rp = _parser()


def _addr_lib():
    ids = (100, 101, 200, 201, 300, 301, 400, 401, 500, 501)
    return SimpleNamespace(
        se_db={i: 0x1000000 + i for i in ids},
        vr_db={i: 0x2000000 + i for i in ids if i != 301},
        ae_db={i: 0xA000000 + i for i in ids if i != 501},
        db_16640={i: 0xB000000 + i for i in ids},
        db_17104={i: 0xC000000 + i for i in ids if i != 501},
    )


RTTI_H = """#pragma once
namespace RE
{
#ifdef SKYRIM_SUPPORT_AE
	inline constexpr REL::ID RTTI_Actor{ 100 };
	inline constexpr REL::ID RTTI_OnlyIn640{ 501 };
#else
	inline constexpr REL::ID RTTI_Actor(static_cast<std::uint64_t>(200));
	inline constexpr REL::ID RTTI_Foo_void_____ptr64_3_(static_cast<std::uint64_t>(201));
#endif
}
"""

NIRTTI_H = """#pragma once
namespace RE
{
#ifdef SKYRIM_SUPPORT_AE
	inline constexpr REL::ID NiRTTI_NiNode{ 300 };
#else
	inline constexpr REL::ID NiRTTI_NiNode(static_cast<std::uint64_t>(301));
#endif
}
"""

VTABLE_H = """#pragma once
namespace RE
{
#ifdef SKYRIM_SUPPORT_AE
	inline constexpr std::array<REL::ID, 2>  VTABLE_Actor{ REL::ID(400), REL::ID(401) };
#else
	inline constexpr std::array<REL::ID, 2>  VTABLE_Actor{ REL::ID(static_cast<std::uint64_t>(100)), REL::ID(static_cast<std::uint64_t>(101)) };
#endif
}
"""


def _labels(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return {l["name"]: l for l in rp._scan_rtti_vtable_file(str(path), _addr_lib())}


def test_both_rtti_initialiser_forms_parse_in_their_own_namespace(tmp_path):
    labels = _labels(tmp_path, "Offsets_RTTI.h", RTTI_H)
    actor = labels["RTTI_Actor"]
    # AE half: id 100 -> AE database only.  SE half: id 200 -> SE + VR only.
    assert (actor["ae_id"], actor["ae_off"]) == (100, 0xA000000 + 100)
    assert (actor["se_id"], actor["se_off"], actor["vr_off"]) == (
        200, 0x1000000 + 200, 0x2000000 + 200)
    # The old regex saw neither of these SE-half (call-init) labels.
    se_only = labels["RTTI_Foo_void_____ptr64_3_"]
    assert (se_only["se_id"], se_only["se_off"], se_only["ae_off"]) == (
        201, 0x1000000 + 201, None)
    assert se_only["ae_id"] is None


def test_nirtti_labels_are_scanned(tmp_path):
    labels = _labels(tmp_path, "Offsets_NiRTTI.h", NIRTTI_H)
    node = labels["NiRTTI_NiNode"]
    assert (node["ae_id"], node["ae_off"]) == (300, 0xA000000 + 300)
    assert (node["se_id"], node["se_off"]) == (301, 0x1000000 + 301)
    assert node["vr_off"] is None                 # 301 is absent from the VR CSV
    assert "Offsets_NiRTTI.h" in rp._LABEL_HEADERS


def test_vtable_ids_never_cross_the_se_ae_namespace(tmp_path):
    labels = _labels(tmp_path, "Offsets_VTABLE.h", VTABLE_H)
    first, second = labels["VTABLE_Actor"], labels["VTABLE_Actor_2"]
    # SE-half ids 100/101 also exist in ae_db: they must NOT be read from it.
    assert (first["se_id"], first["se_off"], first["vr_off"]) == (
        100, 0x1000000 + 100, 0x2000000 + 100)
    assert (first["ae_id"], first["ae_off"]) == (400, 0xA000000 + 400)
    assert (second["se_id"], second["ae_id"]) == (101, 401)
    assert (second["vtable_class"], second["vtable_index"]) == ("Actor", 1)


def test_ae_id_that_only_an_older_ae_runtime_has_survives_the_scan(tmp_path):
    labels = _labels(tmp_path, "Offsets_RTTI.h", RTTI_H)
    legacy = labels["RTTI_OnlyIn640"]             # 501: absent from 1.6.1170
    assert (legacy["ae_id"], legacy["ae_off"]) == (501, None)


def test_section_split_handles_ifndef_and_nested_conditionals():
    ae, se, conditional = rp._split_ae_se_sections(
        "#ifndef SKYRIM_SUPPORT_AE\nse1\n#if X\nse2\n#endif\n#else\nae1\n#endif\nafter\n")
    assert conditional
    assert [l for l in se.split("\n") if l and not l.startswith("#")] == ["se1", "se2"]
    assert ae.split("\n") == ["ae1"]
    assert rp._split_ae_se_sections("plain\n") == ("", "plain\n", False)


SRC_CPP = """#include "RE/A/Actor.h"
namespace RE
{
	void Actor::AddSpell(SpellItem* a_spell)
	{
		using func_t = decltype(&Actor::AddSpell);
		static REL::Relocation<func_t> func{ RELOCATION_ID(100, 400) };
		return func(this, a_spell);
	}

	void Actor::OnlyIn640()
	{
		using func_t = decltype(&Actor::OnlyIn640);
		static REL::Relocation<func_t> func{ RELOCATION_ID(999, 501) };
		return func(this);
	}
}
"""


def test_src_scanner_sets_vr_offset_and_carries_both_ids(tmp_path):
    (tmp_path / "Actor.cpp").write_text(SRC_CPP, encoding="utf-8")
    funcs = {f["name"]: f for f in rp.collect_src_relocations(
        str(tmp_path), _addr_lib(), {})}
    add = funcs["AddSpell"]
    assert add["class_"] == "Actor"
    assert (add["se_id"], add["ae_id"]) == (100, 400)
    assert add["se_off"] == 0x1000000 + 100
    assert add["vr_off"] == 0x2000000 + 100       # SE-namespace id -> vr_db
    assert add["ae_off"] == 0xA000000 + 400
    # SE id 999 resolves nowhere and AE id 501 only in 1.6.640: the symbol
    # must still reach the generator, which resolves 1.6.640 from the id.
    legacy = funcs["OnlyIn640"]
    assert (legacy["se_off"], legacy["ae_off"], legacy["vr_off"]) == (None, None, None)
    assert legacy["ae_id"] == 501


@pytest.mark.skipif(
    not (REPO / "extern" / "CommonLibSSE" / "include" / "RE" / "Offsets_RTTI.h").is_file()
    or not (REPO / "addresslibrary" / "sse" / "version-1-5-97-0.bin").is_file(),
    reason="CommonLibSSE submodule / address library not present")
def test_real_headers_yield_se_rtti_and_nirtti_labels():
    spec = importlib.util.spec_from_file_location(
        "sse_address_library_under_test", HERE / "address_library.py")
    address_library = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(address_library)
    lib = address_library.AddressLibrary()
    lib.load_all(str(REPO / "addresslibrary"))
    include = REPO / "extern" / "CommonLibSSE" / "include" / "RE"
    rtti = rp._scan_rtti_vtable_file(str(include / "Offsets_RTTI.h"), lib)
    assert sum(1 for l in rtti if l.get("se_off")) > 7000        # was 1
    nirtti = rp._scan_rtti_vtable_file(str(include / "Offsets_NiRTTI.h"), lib)
    assert sum(1 for l in nirtti if l.get("se_off")) > 400       # was 0
    for label in rtti + nirtti:
        if label.get("se_off"):
            assert lib.se_db[label["se_id"]] == label["se_off"]
        if label.get("ae_off"):
            assert lib.ae_db[label["ae_id"]] == label["ae_off"]


def test_an_elif_branch_belongs_to_neither_id_namespace():
    ae, se, conditional = rp._split_ae_se_sections(
        "#ifdef SKYRIM_SUPPORT_AE\nae1\n#elif defined(SKYRIMVR)\nvr1\n"
        "#else\nse1\n#endif\n")
    assert conditional
    assert ae.split("\n") == ["ae1"]               # vr1 used to stay in AE
    assert se.split("\n") == ["se1"]
    ae, se, _ = rp._split_ae_se_sections(
        "#ifndef SKYRIM_SUPPORT_AE\nse1\n#elif X\nother\n#else\nae1\n#endif\n")
    assert (ae, se) == ("ae1", "se1")


OFFSET_CPP = """namespace RE
{
	void Actor::Update()
	{
		using func_t = decltype(&Actor::Update);
		static REL::Relocation<func_t> func{ Offset::Actor::Update };
		return func(this);
	}
}
"""


def test_a_missing_namespace_map_never_falls_back_to_the_merged_map(tmp_path):
    (tmp_path / "Actor.cpp").write_text(OFFSET_CPP, encoding="utf-8")
    merged = {"Actor::Update": 400}               # an AE-only Offsets.h entry
    funcs = rp.collect_src_relocations(
        str(tmp_path), _addr_lib(), merged, ae_offset_map=merged)
    assert [(f["se_id"], f["ae_id"]) for f in funcs] == [(None, 400)]
    assert rp.collect_src_relocations(str(tmp_path), _addr_lib(), merged) == []


def test_alignas_and_declspec_classes_keep_their_scope():
    parser = _parser()
    for line, name in (("class alignas(16) NiPoint3A : public NiPoint3 {", "NiPoint3A"),
                       ("struct __declspec(novtable) Foo {", "Foo"),
                       ("class alignas(0x10) Q", "Q")):
        match = parser._CLASS_RE.search(line) or parser._CLASS_DECL_RE.search(line)
        assert match and match.group(1) == name
