"""CommonLibF4VR ships no IDs.h: the scanner must read its own layout.

Regression (2026-09-21 audit): ``reloc_parser`` only looked for ``IDs.h`` /
``IDs_RTTI.h`` / ``IDs_VTABLE.h``, so the CLF4VR importer got ZERO symbols.
CommonLibF4VR has ``RTTI_IDs.h`` / ``NiRTTI_IDs.h`` / ``VTABLE_IDs.h`` plus
inline ``REL::ID(og)`` and ``REL::RelocationID(og, ng)``.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rp = _load("f4_reloc_parser_under_test", "reloc_parser.py")

VTABLE_IDS = """#pragma once
namespace RE
{
	namespace VTABLE
	{
		inline constexpr std::array<REL::ID, 1>            AbsorbEffect{ REL::ID(1096743) };
		inline constexpr std::array<REL::RelocationID, 2>  Handles{ REL::RelocationID(902583, 2730081), REL::RelocationID(1201613, 2730082) };
	}
}
"""
RTTI_IDS = """#pragma once
namespace RE
{
	namespace RTTI
	{
		inline constexpr REL::RelocationID AStarSearchBase{ 640682, 2768425 };
		inline constexpr REL::ID           BSImagespaceShaderCopyNormals{ 2787389 };
	}
}
"""
NIRTTI_IDS = """#pragma once
namespace RE
{
	namespace Ni_RTTI
	{
		inline constexpr REL::RelocationID BSAnimNote{ 564983, 2703987 };
	}
}
"""
ACTOR_H = """#pragma once
namespace RE
{
	class __declspec(novtable) EquippedWeaponData :
		public EquippedItemData  // 00
	{
	public:
		static constexpr auto RTTI{ RTTI::EquippedWeaponData };

		void SetupFireSounds(Actor& a_actor)
		{
			using func_t = decltype(&EquippedWeaponData::SetupFireSounds);
			static REL::Relocation<func_t> func{ REL::RelocationID(1468462, 2232275) };
			return func(this, a_actor);
		}

		bool LegacyOnly()
		{
			using func_t = decltype(&EquippedWeaponData::LegacyOnly);
			static REL::Relocation<func_t> func{ REL::ID(533106) };
			return func(this);
		}

		[[nodiscard]] static ProcessLists* GetSingleton()
		{
			static REL::Relocation<ProcessLists**> singleton{ REL::RelocationID(1569706, 2688869) };
			return *singleton;
		}

		void WithMemberOffset()
		{
			static REL::Relocation<std::uintptr_t> func{ REL::ID(111111), 0x20 };
			// static REL::Relocation<func_t> func{ REL::ID(222222) };
		}
	};
}
"""
SOURCE_CPP = """#include "RE/Bethesda/BSResource.h"
namespace RE
{
	namespace BSResource
	{
		ErrorCode GetOrCreateStream(const char* a_fileName)
		{
			return ErrorCode::kNone;
		}
	}

	std::uint32_t BSResourceNiBinaryStream::DoRead(void* a_buffer)
	{
		using func_t = decltype(&BSResourceNiBinaryStream::DoRead);
		static REL::Relocation<func_t> func{ REL::ID(358512) };
		return func(this, a_buffer);
	}
}
"""


@pytest.fixture()
def clf4vr_tree(tmp_path):
    include = tmp_path / "CommonLibF4" / "include" / "RE"
    (include / "Bethesda").mkdir(parents=True)
    (include / "VTABLE_IDs.h").write_text(VTABLE_IDS, encoding="utf-8")
    (include / "RTTI_IDs.h").write_text(RTTI_IDS, encoding="utf-8")
    (include / "NiRTTI_IDs.h").write_text(NIRTTI_IDS, encoding="utf-8")
    (include / "Bethesda" / "Actor.h").write_text(ACTOR_H, encoding="utf-8")
    src = tmp_path / "CommonLibF4" / "src" / "RE"
    src.mkdir(parents=True)
    (src / "BSResourceNiBinaryStream.cpp").write_text(SOURCE_CPP, encoding="utf-8")
    return include


def _lib():
    return SimpleNamespace(get_ae=lambda id_: {2232275: 0xAE01, 2730081: 0xAE02}.get(id_))


def test_clf4vr_layout_yields_labels_with_both_ids(clf4vr_tree):
    funcs, labels, _statics = rp.collect_relocations(str(clf4vr_tree), _lib())
    by_name = {l["name"]: l for l in labels}
    assert set(by_name) == {
        "VTABLE_AbsorbEffect", "VTABLE_Handles", "VTABLE_Handles_2",
        "RTTI_AStarSearchBase", "RTTI_BSImagespaceShaderCopyNormals",
        "NiRTTI_BSAnimNote"}
    single = by_name["VTABLE_AbsorbEffect"]
    assert single["id"] == 1096743 and "og_id" not in single and "ng_id" not in single
    assert (single["vtable_class"], single["vtable_index"]) == ("AbsorbEffect", 0)
    second = by_name["VTABLE_Handles_2"]
    assert (second["og_id"], second["ng_id"], second["id"]) == (1201613, 2730082, 2730082)
    assert (second["vtable_class"], second["vtable_index"]) == ("Handles", 1)
    assert by_name["VTABLE_Handles"]["ae_off"] == 0xAE02
    rtti = by_name["RTTI_AStarSearchBase"]
    assert (rtti["og_id"], rtti["ng_id"]) == (640682, 2768425)
    assert by_name["RTTI_BSImagespaceShaderCopyNormals"]["id"] == 2787389
    assert by_name["NiRTTI_BSAnimNote"]["og_id"] == 564983


def test_clf4vr_inline_relocations_are_scanned_from_headers_and_src(clf4vr_tree):
    funcs, _labels, _statics = rp.collect_relocations(str(clf4vr_tree), _lib())
    by_name = {(f["class_"], f["name"]): f for f in funcs}
    # ``class __declspec(novtable) X`` must name the class X, not __declspec
    pair = by_name[("EquippedWeaponData", "SetupFireSounds")]
    assert (pair["kind"], pair["og_id"], pair["ng_id"], pair["ae_off"]) == (
        "func", 1468462, 2232275, 0xAE01)
    legacy = by_name[("EquippedWeaponData", "LegacyOnly")]
    assert legacy["id"] == 533106 and "og_id" not in legacy
    # data relocation: names the variable, declared as a label
    data = by_name[("EquippedWeaponData", "GetSingleton::singleton")]
    assert (data["kind"], data["og_id"]) == ("label", 1569706)
    # src/*.cpp: scope comes from the qualified definition
    src = by_name[("BSResourceNiBinaryStream", "DoRead")]
    assert (src["kind"], src["id"]) == ("func", 358512)
    # ``{ REL::ID(n), 0x20 }`` is NOT at the ID's address; comments are ignored
    assert not any(f["id"] in (111111, 222222) for f in funcs)
    assert len(funcs) == 4


def test_classic_commonlibf4_layout_is_untouched(tmp_path):
    include = tmp_path / "RE"
    include.mkdir()
    (include / "IDs.h").write_text(
        "namespace RE::ID\n{\n\tnamespace Actor\n\t{\n"
        "\t\tinline constexpr REL::ID AddPerk{ 2230121 };\n\t}\n}\n", encoding="utf-8")
    (include / "IDs_VTABLE.h").write_text(
        "namespace RE\n{\n\tnamespace VTABLE\n\t{\n"
        "\t\tinline constexpr std::array<REL::ID, 2> Actor{ REL::ID(1455516), REL::ID(985925) };\n"
        "\t}\n}\n", encoding="utf-8")
    (include / "Actor.h").write_text(
        "namespace RE\n{\n\tclass Actor\n\t{\n\tpublic:\n\t\tvoid AddPerk()\n\t\t{\n"
        "\t\t\tstatic REL::Relocation<func_t> func{ ID::Actor::AddPerk };\n"
        "\t\t\tstatic REL::Relocation<func_t> other{ REL::ID(5) };\n\t\t}\n\t};\n}\n",
        encoding="utf-8")
    funcs, labels, _statics = rp.collect_relocations(str(include), _lib())
    assert [(f["class_"], f["name"], f["id"]) for f in funcs] == [("Actor", "AddPerk", 2230121)]
    assert [(l["name"], l["id"], l["vtable_class"], l["vtable_index"]) for l in labels] == [
        ("VTABLE_Actor", 1455516, "Actor", 0), ("VTABLE_Actor_2", 985925, "Actor", 1)]


SCOPED_CPP = """namespace RE
{
    void Stream::dtor()
    {
        static REL::Relocation<func_t> func{ REL::ID(1516202) };
        return func(this);
    }

    [[nodiscard]] Stream* Stream::BinaryStreamWithRescan(const char* a_name)
    {
        static REL::Relocation<func_t> func{ REL::ID(543595) };
        return func(a_name);
    }

    void FreeHelper()
    {
        static REL::Relocation<func_t> func{ REL::ID(700001) };
        func();
    }

    bool Stream::Forward(int a_value)
    {
        return RE::Other::Thing(a_value,
            0);
        static REL::Relocation<func_t> func{ REL::ID(700002) };
    }

    int Stream::Declared(int a_first,
        int a_second);
    static REL::Relocation<std::uint32_t*> loose{ REL::ID(700003) };
}
"""
ALIGNAS_H = """namespace RE
{
    class __declspec(novtable) alignas(0x08) NiRefObject
    {
    public:
        static std::uint32_t* GetTotalObjectCount()
        {
            static REL::Relocation<std::uint32_t*> objects{ REL::ID(1161724) };
            return objects.get();
        }
    };

    class alignas(0x10) PlacementItemData
    {
    public:
        void Set(TESObjectREFR& a_refr)
        {
            static REL::Relocation<func_t> func{ REL::ID(1460935) };
            return func(this, a_refr);
        }
    };
}
"""


def test_cpp_scope_ends_with_the_definition_body(tmp_path):
    cpp = tmp_path / "Stream.cpp"
    cpp.write_text(SCOPED_CPP, encoding="utf-8")
    found = {f["id"]: (f["class_"], f["name"]) for f in rp._scan_inline_relocations(
        str(cpp), _lib(), qualified_definitions=True)}
    assert found[1516202] == ("Stream", "dtor")
    # a ``[[nodiscard]]`` definition is a new scope (was emitted as ``dtor``)
    assert found[543595] == ("Stream", "BinaryStreamWithRescan")
    # a free function after a member definition is NOT that member
    assert 700001 not in found
    # a continued ``return RE::Other::Thing(a,`` call is not a definition
    assert found[700002] == ("Stream", "Forward")
    # a namespace-scope declaration opens no scope
    assert 700003 not in found


def test_alignas_classes_keep_their_scope(tmp_path):
    header = tmp_path / "NiRefObject.h"
    header.write_text(ALIGNAS_H, encoding="utf-8")
    found = {f["id"]: (f["class_"], f["name"]) for f in rp._scan_inline_relocations(
        str(header), _lib())}
    assert found[1161724] == ("NiRefObject", "GetTotalObjectCount::objects")
    assert found[1460935] == ("PlacementItemData", "Set")


@pytest.mark.skipif(
    not (REPO / "extern" / "CommonLibF4VR" / "CommonLibF4" / "include" / "RE"
         / "VTABLE_IDs.h").is_file(),
    reason="CommonLibF4VR submodule not present")
def test_real_commonlibf4vr_checkout_is_no_longer_empty():
    include = REPO / "extern" / "CommonLibF4VR" / "CommonLibF4" / "include" / "RE"
    funcs, labels, _statics = rp.collect_relocations(str(include), _lib())
    assert len(funcs) > 600                         # was 0
    assert sum(1 for l in labels if l["name"].startswith("VTABLE_")) > 12000   # was 0
    assert all(f.get("class_") not in ("__declspec", "alignas") for f in funcs)
    by_id = {f["id"]: f for f in funcs}
    assert by_id[543595]["name"] == "BinaryStreamWithRescan"   # was ``dtor``
    assert by_id[1161724]["class_"] == "NiRefObject"           # was class-less
