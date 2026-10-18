"""VTABLE_* labels must agree with the executable's own RTTI.

Regression for 2026-09-21: upstream ``IDs_VTABLE.h`` lists one ID under several
class names; >= 1,600 labels of the Fallout 4 1.11.240 importer named a class
other than the one the binary's CompleteObjectLocator names, and the importer's
vtable walk then produced ``<WrongClass>::FuncN`` function names.

Everything runs on a synthetic in-memory image -- no game executable needed.
"""
from __future__ import annotations

import csv
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CORE = HERE.parent / "core"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module          # dataclasses resolve their own module
    spec.loader.exec_module(module)
    return module


vc = _load("vtable_label_check_under_test", CORE / "vtable_label_check.py")

IMAGE_BASE = 0x140000000
RDATA = 0x1000


class ImageBuilder:
    """Lay out TypeDescriptors, COLs and vtables in one ``.rdata`` blob."""

    def __init__(self):
        self.data = bytearray(0x40)      # keep RVA arithmetic away from 0

    def _append(self, blob, align=8):
        while len(self.data) % align:
            self.data.append(0)
        rva = RDATA + len(self.data)
        self.data += blob
        return rva

    def type_descriptor(self, decorated):
        return self._append(struct.pack("<QQ", IMAGE_BASE + 0x999, 0)
                            + decorated.encode("latin-1") + b"\0")

    def col(self, type_rva, offset=0, signature=1, self_rva=None):
        rva = RDATA + ((len(self.data) + 7) & ~7)
        return self._append(struct.pack(
            "<6I", signature, offset, 0, type_rva, type_rva,
            rva if self_rva is None else self_rva))

    def vtable(self, col_rva, slots=2):
        """Return the RVA of slot 0 (``vtable[-1]`` holds the COL pointer)."""
        rva = self._append(struct.pack("<Q", IMAGE_BASE + col_rva)
                           + struct.pack("<Q", IMAGE_BASE + 0x500) * slots)
        return rva + 8

    def vtable_for(self, decorated, **col):
        return self.vtable(self.col(self.type_descriptor(decorated), **col))

    def garbage_vtable(self):
        rva = self._append(struct.pack("<QQ", 0x746E742F636361, IMAGE_BASE + 0x500))
        return rva + 8

    def image(self):
        return vc.SectionImage(IMAGE_BASE, 0x100000, [(RDATA, bytes(self.data))])


# ---------------------------------------------------------------------------
# name comparison
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label, decorated", [
    ("ActorValueOwner", ".?AVActorValueOwner@@"),
    # namespaces / nested classes: A::B  <->  B@A@@
    ("BGSInventoryList__InventoryWeightFunctor",
     ".?AVInventoryWeightFunctor@BGSInventoryList@@"),
    ("BSResource__Archive2__Index", ".?AVIndex@Archive2@BSResource@@"),
    # templates, struct arguments, a nested argument type
    ("BSTEventSink_BGSInventoryListEvent__Event_",
     ".?AV?$BSTEventSink@UEvent@BGSInventoryListEvent@@@@"),
    # const pointer argument + integer constant ('$02' == 3)
    ("AStarSearch_BSNavmeshInfoconst_BSPathingDoor_3_",
     ".?AV?$AStarSearch@PEBVBSNavmeshInfo@@VBSPathingDoor@@$02@@"),
    # the SE header spelling keeps ``__ptr64``
    ("AStarSearch_BSNavmeshInfo_const_____ptr64_BSPathingDoor_3_",
     ".?AV?$AStarSearch@PEBVBSNavmeshInfo@@VBSPathingDoor@@$02@@"),
    # name back-reference inside the template's own table
    # [Outer, Bundle, Mods, bnet]: '3' is bnet
    ("bnet__Outer_bnet__Mods__Bundle_bnet__HttpResponseInfo_",
     ".?AV?$Outer@VBundle@Mods@bnet@@VHttpResponseInfo@3@@bnet@@"),
    # a nested instantiation is memorised as ONE name: [Params, UniquePtr<..>, bnet]
    ("bnet__Params_bnet__UniquePtr_bnet__Bundle__bnet__Info_",
     ".?AU?$Params@V?$UniquePtr@VBundle@bnet@@@bnet@@VInfo@2@@bnet@@"),
    # identifiers containing underscores, primitive arguments
    ("hkb_Clip_Generator_unsignedint_float_", ".?AV?$hkb_Clip_Generator@IM@@"),
    # anonymous namespace: the ``?A0x<hash>`` key differs per build
    ("CleanupQueue___Policy_A0xfa513cfc__", ".?AV?$CleanupQueue@UPolicy@?A0x02971ddc@@@@"),
    ("ActiveTriggers____hknpCollector", ".?AVhknpCollector@?A0x11223344@ActiveTriggers@@"),
    # member-function pointer argument: ret (Class::*)(params)
    ("MemberFunc_Context_Item_const_Context____void___",
     ".?AV?$MemberFunc@VContext@@P81@EBAAEBVItem@@XZ@@"),
    # lambda with the SAME hash
    ("Visitor__lambda_244bb79b4330f1e9a58c7deb5de915ab__",
     ".?AV?$Visitor@V<lambda_244bb79b4330f1e9a58c7deb5de915ab>@@@@"),
])
def test_label_matches_its_rtti_name(label, decorated):
    assert vc.compare_label(label, decorated) == (vc.MATCH, "")


@pytest.mark.parametrize("label, decorated", [
    # upstream: id 100021 listed as both of these; the exe says ActorValueOwner
    ("BGSInventoryList__InventoryWeightFunctor", ".?AVActorValueOwner@@"),
    # a longer name that merely CONTAINS the RTTI class name is another class
    ("IMovementHandlerAgent", ".?AVMovementHandlerAgent@@"),
    ("Foo__Bar", ".?AVFoo@@"),
    # same template, different argument
    ("AutoRegister_CombatMagicCasterCloak_", ".?AV?$AutoRegister@VCombatMagicCasterBoundItem@@@@"),
    # label carries an extra identifier the RTTI name lacks
    ("CombatNodeObjectBase_WaitForEvent_", ".?AV?$CombatNodeObject@VWaitForEvent@@@@"),
    # base/derived swap seen in Skyrim 1.7.104
    ("BSTDerivedCreator_Message_", ".?AU?$AutoRegisterCreator@VMessage@@@@"),
])
def test_label_provably_names_another_class(label, decorated):
    assert vc.compare_label(label, decorated)[0] == vc.MISMATCH


@pytest.mark.parametrize("label, decorated, why", [
    # locally scoped class: not parsed -> never guessed
    ("BSResource__RegisterPrefix__2__Traverser",
     ".?AVTraverser@?1??RegisterPrefix@BSResource@@YAXPEBD0PEAVLocation@2@@Z@", "unparsed"),
    # header generators cut std::function<void (A)> at the '('
    ("BSPlatform__BSAsyncRequest_std__function_void__",
     ".?AV?$BSAsyncRequest@V?$function@$$A6AXW4BNetResult@BSPlatform@@_KPEBD@Z@std@@@BSPlatform@@",
     "truncated"),
    # <lambda_HASH> is per translation unit, hence per build
    ("Functor__lambda_07749ecf6a2bb06bae9de8f93e40408f__",
     ".?AV?$Functor@V<lambda_f6cd6ece405e8e9125f3eafb02b3651f>@@@@", "lambda hash"),
    # identifiers agree, only the integer constant differs
    ("FxResponseArgs_12_", ".?AV?$FxResponseArgs@$0P@@@", "constants"),
])
def test_uncomparable_names_are_unverifiable_not_wrong(label, decorated, why):
    verdict, reason = vc.compare_label(label, decorated)
    assert verdict == vc.UNVERIFIABLE
    assert why in reason


def test_type_name_parser_token_order_and_backrefs():
    assert vc.parse_type_descriptor_name(".?AVB@A@@") == [("id", "A"), ("id", "B")]
    tokens = vc.parse_type_descriptor_name(
        ".?AV?$Outer@VBundle@Mods@bnet@@VHttpResponseInfo@3@@bnet@@")
    assert [t for k, t in tokens if k == "id"] == [
        "bnet", "Outer", "bnet", "Mods", "Bundle", "bnet", "HttpResponseInfo"]
    with pytest.raises(vc.UnsupportedName):
        vc.parse_type_descriptor_name(".?AVX@9@")          # dangling back-reference
    with pytest.raises(vc.UnsupportedName):
        vc.parse_type_descriptor_name(".PEAVX@@")          # not a class descriptor


# ---------------------------------------------------------------------------
# COL walk on a synthetic image
# ---------------------------------------------------------------------------

def test_read_vtable_col_validates_the_x64_locator():
    b = ImageBuilder()
    good = b.vtable_for(".?AVActor@@", offset=0x28)
    bad_signature = b.vtable_for(".?AVActor@@", signature=0)
    bad_self = b.vtable_for(".?AVActor@@", self_rva=0x1234)
    not_a_class = b.vtable_for(".P6AXXZ")
    garbage = b.garbage_vtable()
    image = b.image()

    info = vc.read_vtable_col(image, good)
    assert (info.decorated_name, info.subobject_offset) == (".?AVActor@@", 0x28)
    for rva in (bad_signature, bad_self, not_a_class, garbage, 0x90000):
        with pytest.raises(vc.ColError):
            vc.read_vtable_col(image, rva)


def test_only_the_rtti_confirmed_name_survives_on_a_shared_rva():
    b = ImageBuilder()
    shared = b.vtable_for(".?AVActorValueOwner@@")
    local = b.vtable_for(".?AVTraverser@?1??RegisterPrefix@BSResource@@YAXPEBD0PEAVLocation@2@@Z@")
    both = b.vtable_for(".?AVLocal@?1??f@@YAXXZ@")
    garbage = b.garbage_vtable()
    b_dup = b.vtable_for(".?AVDup@@")
    result = vc.check_vtable_labels([
        ("VTABLE_ActorValueOwner", shared, None),
        ("VTABLE_BGSInventoryList__InventoryWeightFunctor", shared, None),
        ("VTABLE_BSResource__RegisterPrefix__2__Traverser", local, None),
        # same ID listed twice in one upstream array: X and X_2 on one address
        ("VTABLE_Dup", b_dup, "Dup"),
        ("VTABLE_Dup_2", b_dup, "Dup"),
        ("VTABLE_bnet__AccountInfoRequest", garbage, None),
        ("VTABLE_Whatever", both, None),
    ], b.image())

    assert {v.name for v in result.kept} == {
        "VTABLE_ActorValueOwner",
        "VTABLE_BSResource__RegisterPrefix__2__Traverser",   # unverifiable: kept
        "VTABLE_Dup",
        "VTABLE_Whatever",                                    # unverifiable: kept
    }
    verdicts = {v.name: v.verdict for v in result.dropped}
    assert verdicts == {
        "VTABLE_BGSInventoryList__InventoryWeightFunctor": vc.MISMATCH,
        "VTABLE_Dup_2": vc.DUPLICATE,
        "VTABLE_bnet__AccountInfoRequest": vc.NO_COL,
    }
    counts = result.counts()
    assert (counts["kept_confirmed"], counts["kept_unverifiable"],
            counts["dropped"]) == (2, 2, 3)
    assert "2 kept (unverifiable)" in result.summary()


def test_unverifiable_sibling_of_a_confirmed_name_and_strict_mode():
    b = ImageBuilder()
    rva = b.vtable_for(".?AV?$FxResponseArgs@$0P@@@")
    rows = [("VTABLE_FxResponseArgs_15_", rva, "FxResponseArgs_15_"),
            ("VTABLE_FxResponseArgs_12_", rva, "FxResponseArgs_12_")]
    result = vc.check_vtable_labels(rows, b.image())
    assert [v.name for v in result.kept] == ["VTABLE_FxResponseArgs_15_"]

    alone = vc.check_vtable_labels(rows[1:], b.image())
    assert [v.name for v in alone.kept] == ["VTABLE_FxResponseArgs_12_"]
    strict = vc.check_vtable_labels(rows[1:], b.image(), strict=True)
    assert strict.kept == []


def test_symbols_lose_only_the_refuted_target_offset(tmp_path):
    b = ImageBuilder()
    rva = b.vtable_for(".?AVActorValueOwner@@")
    symbols = [
        {"n": "VTABLE_ActorValueOwner", "t": "label", "id": 100021, "240": rva,
         "a": 0x111, "sections": {"240": ".rdata"}, "target_sha256": {"240": "x"}},
        {"n": "VTABLE_BGSInventoryList__InventoryWeightFunctor", "t": "label",
         "id": 100021, "240": rva, "a": 0x111,
         "sections": {"240": ".rdata"}, "target_sha256": {"240": "x"}},
        {"n": "Actor::Update", "t": "func", "240": rva},      # never touched
    ]
    result = vc.validate_symbol_vtable_labels(symbols, "240", b.image())
    assert symbols[0]["240"] == rva
    assert "240" not in symbols[1] and symbols[1]["a"] == 0x111
    assert symbols[1]["rejected_offsets"] == {"240": "vtable_mismatch"}
    assert symbols[1]["sections"] == {} and symbols[1]["target_sha256"] == {}
    assert symbols[2]["240"] == rva

    report = tmp_path / "refs" / "vtable_labels_dropped_240.csv"
    vc.write_dropped_csv(str(report), result,
                         {(s["n"], rva): s.get("id", "") for s in symbols})
    rows = list(csv.DictReader(report.open(encoding="utf-8")))
    assert [(r["label"], r["id"], r["verdict"], r["rtti_name"]) for r in rows] == [
        ("VTABLE_BGSInventoryList__InventoryWeightFunctor", "100021", "mismatch",
         ".?AVActorValueOwner@@")]


def test_rtti_labels_must_be_the_class_type_descriptor():
    b = ImageBuilder()
    actor = b.type_descriptor(".?AVActor@@")
    other = b.type_descriptor(".?AVTESForm@@")
    result = vc.check_rtti_labels([
        ("RTTI_Actor", actor, None),
        ("RTTI_PlayerCharacter", other, None),
        ("RTTI_Nowhere", 0x90000, None),
    ], b.image(), strict=True)
    assert [v.name for v in result.kept] == ["RTTI_Actor"]


# ---------------------------------------------------------------------------
# through a real (minimal) PE file, as the generators call it
# ---------------------------------------------------------------------------

def _write_pe(path, rdata):
    """Smallest PE32+ image ``pe_layout.PELayout`` accepts: one .rdata section."""
    raw_offset = 0x400
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<Q", optional, 24, IMAGE_BASE)
    struct.pack_into("<I", optional, 56, 0x100000)
    section = struct.pack("<8sIIIIIIHHI", b".rdata", len(rdata), RDATA, len(rdata),
                          raw_offset, 0, 0, 0, 0, 0x40000040)
    blob = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + section
    blob += b"\0" * (raw_offset - len(blob)) + bytes(rdata)
    path.write_bytes(blob)


def test_generator_entry_point_checks_each_staged_layout(tmp_path):
    pe_layout = _load("pe_layout_under_test", HERE.parent / "commonlibsf" / "pe_layout.py")
    b = ImageBuilder()
    rva = b.vtable_for(".?AVActorValueOwner@@")
    exe = tmp_path / "Fallout4.exe"
    _write_pe(exe, b.data)
    layout = pe_layout.PELayout.read(str(exe))

    symbols = [
        {"n": "VTABLE_ActorValueOwner", "t": "label", "id": 7, "240": rva, "v": rva},
        {"n": "VTABLE_Wrong", "t": "label", "id": 7, "240": rva, "v": rva, "og": rva},
    ]
    lines = []
    results = vc.validate_vtable_labels_for_layouts(
        symbols, {"240": layout, "og": None}, {"VTABLE_Wrong": "Wrong"},
        report_dir=str(tmp_path / "refs"), log=lines.append)

    assert set(results) == {"240"}
    assert "240" in symbols[0] and "240" not in symbols[1]
    # targets without a staged executable are neither checked nor touched
    assert symbols[1]["og"] == rva and symbols[1]["v"] == rva
    assert (tmp_path / "refs" / "vtable_labels_dropped_240.csv").is_file()
    assert any("1 kept (RTTI-confirmed)" in line and "1 dropped" in line for line in lines)


def test_f4_vr_labels_must_be_confirmed_by_the_staged_vr_exe(tmp_path, monkeypatch):
    """Legacy IDs (< 1.6M) may resolve through vr_db -- but a VR VTABLE label
    survives only when Fallout4VR.exe's own RTTI names that class (strict),
    while a desktop target keeps what merely cannot be compared."""
    pe_layout = _load("pe_layout_under_test", HERE.parent / "commonlibsf" / "pe_layout.py")
    address_library = _load("f4_address_library_vt_test", HERE / "address_library.py")
    gen = _load("f4_parser_vt_test", HERE / "parse_commonlib_types.py")
    monkeypatch.setattr(gen, "SCRIPT_DIR", str(tmp_path / "commonlibf4"))
    monkeypatch.setattr(gen, "PROJECT_DIR", str(tmp_path))
    reports = tmp_path / "build" / "evidence" / "vtable_labels" / "commonlibf4"

    b = ImageBuilder()
    actor = b.vtable_for(".?AVActor@@")
    form = b.vtable_for(".?AVTESForm@@")
    local = b.vtable_for(".?AVLocal@?1??f@@YAXXZ@")
    exe = tmp_path / "Fallout4VR.exe"
    _write_pe(exe, b.data)
    layout = pe_layout.PELayout.read(str(exe))

    lib = address_library.F4AddressLibrary()
    lib.vr_db = {1: actor, 2: form, 3: local}
    lib.db_240 = dict(lib.vr_db)
    labels = [
        {"name": "VTABLE_Actor", "id": 1, "vtable_class": "Actor"},
        {"name": "VTABLE_PlayerCharacter", "id": 2, "vtable_class": "PlayerCharacter"},
        {"name": "VTABLE_f__2__Local", "id": 3, "vtable_class": "f__2__Local"},
    ]
    layouts = {"v": layout, "240": layout}
    symbols, classes = gen.build_primary_symbols([], labels, lib, layouts)
    assert all(s["v"] == s["240"] for s in symbols)       # legacy ids reach vr_db
    gen.validate_vtable_labels(symbols, layouts, classes)

    by_name = {s["n"]: s for s in symbols}
    assert by_name["VTABLE_Actor"]["v"] == actor
    assert "v" not in by_name["VTABLE_PlayerCharacter"]    # RTTI says TESForm
    assert "240" not in by_name["VTABLE_PlayerCharacter"]
    assert "v" not in by_name["VTABLE_f__2__Local"]        # VR: unconfirmed -> out
    assert by_name["VTABLE_f__2__Local"]["240"] == local   # desktop: kept, counted
    assert by_name["VTABLE_f__2__Local"]["rejected_offsets"] == {"v": "vtable_unverifiable"}
    for key in ("v", "240"):
        assert (reports / "vtable_labels_dropped_{}.csv".format(key)).is_file()


# ---------------------------------------------------------------------------
# fail-closed comparison, RTTI-only targets, per-row drops, per-target IDs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label, decorated, expected", [
    # a trailing number is not filler: Actor2 is another class
    ("Actor2", ".?AVActor@@", vc.MISMATCH),
    # a primitive template argument must be the RTTI one, in order
    ("BSTArray_int_", ".?AV?$BSTArray@M@@", vc.UNVERIFIABLE),
    ("BSTArray_float_", ".?AV?$BSTArray@M@@", vc.MATCH),
    ("Pair_float_int_", ".?AV?$Pair@MH@@", vc.MATCH),
    ("Pair_int_float_", ".?AV?$Pair@MH@@", vc.UNVERIFIABLE),
    ("BSTArray_unsignedint_", ".?AV?$BSTArray@H@@", vc.UNVERIFIABLE),
    # a template constant must be spelled too
    ("FxResponseArgs_", ".?AV?$FxResponseArgs@$0P@@@", vc.UNVERIFIABLE),
])
def test_numbers_and_primitives_are_required_not_filler(label, decorated, expected):
    assert vc.compare_label(label, decorated)[0] == expected


def test_the_same_label_twice_at_one_rva_keeps_one(tmp_path):
    b = ImageBuilder()
    rva = b.vtable_for(".?AVDup@@")
    result = vc.check_vtable_labels(
        [("VTABLE_Dup", rva, "Dup"), ("VTABLE_Dup", rva, "Dup")], b.image())
    assert [v.verdict for v in result.verdicts] == [vc.MATCH, vc.DUPLICATE]
    assert [v.verdict for v in result.kept] == [vc.MATCH]
    assert not result.is_dropped("VTABLE_Dup", rva)

    symbols = [{"n": "VTABLE_Dup", "t": "label", "240": rva},
               {"n": "VTABLE_Dup", "t": "label", "240": rva}]
    vc.validate_symbol_vtable_labels(symbols, "240", b.image())
    assert symbols[0]["240"] == rva
    assert symbols[1]["rejected_offsets"] == {"240": "vtable_duplicate"}


def test_rtti_labels_are_checked_without_any_vtable_label(tmp_path):
    pe_layout = _load("pe_layout_under_test", HERE.parent / "commonlibsf" / "pe_layout.py")
    b = ImageBuilder()
    actor = b.type_descriptor(".?AVActor@@")
    exe = tmp_path / "Fallout4VR.exe"
    _write_pe(exe, b.data)
    layout = pe_layout.PELayout.read(str(exe))
    symbols = [{"n": "RTTI_Actor", "t": "label", "v": actor},
               {"n": "RTTI_Bogus", "t": "label", "v": 0x90000}]
    results = vc.validate_vtable_labels_for_layouts(
        symbols, {"v": layout}, strict_keys=("v",), rtti_keys=("v",), log=lambda _l: None)
    assert "v:rtti" in results
    assert symbols[0]["v"] == actor
    assert "v" not in symbols[1]


def test_nirtti_labels_are_confirmed_only_by_a_file_backed_name():
    b = ImageBuilder()
    name = b._append(b"NiNode\0")
    good = b._append(struct.pack("<QQ", IMAGE_BASE + name, 0))
    other = b._append(struct.pack("<QQ", IMAGE_BASE + b._append(b"BSFadeNode\0"), 0))
    runtime = b._append(b"\0" * 16)            # dynamic initializer: zero in image
    rows = [("NiRTTI_NiNode", good, None), ("NiRTTI_NiCamera", other, None),
            ("NiRTTI_BSTriShape", runtime, None)]
    lenient = vc.check_nirtti_labels(rows, b.image())
    assert [v.verdict for v in lenient.verdicts] == [
        vc.MATCH, vc.MISMATCH, vc.UNVERIFIABLE]
    assert [v.name for v in lenient.kept] == ["NiRTTI_NiNode", "NiRTTI_BSTriShape"]
    strict = vc.check_nirtti_labels(rows, b.image(), strict=True)
    assert [v.name for v in strict.kept] == ["NiRTTI_NiNode"]


def test_dropped_csv_ids_come_from_the_targets_own_namespace(tmp_path):
    pe_layout = _load("pe_layout_under_test", HERE.parent / "commonlibsf" / "pe_layout.py")
    b = ImageBuilder()
    rva = b.vtable_for(".?AVActorValueOwner@@")
    exe = tmp_path / "SkyrimSE.exe"
    _write_pe(exe, b.data)
    layout = pe_layout.PELayout.read(str(exe))
    symbols = [{"n": "VTABLE_Wrong", "t": "label", "si": 269454, "ai": 215718,
                "s": rva, "17104": rva}]
    vc.validate_vtable_labels_for_layouts(
        symbols, {"s": layout, "17104": layout}, {"VTABLE_Wrong": "Wrong"},
        report_dir=str(tmp_path), log=lambda _l: None,
        id_fields={"s": ("si",), "17104": ("ai",)})
    ids = {key: [r["id"] for r in csv.DictReader(
        (tmp_path / "vtable_labels_dropped_{}.csv".format(key)).open(encoding="utf-8"))]
        for key in ("s", "17104")}
    assert ids == {"s": ["269454"], "17104": ["215718"]}


def test_f4_vr_nirtti_labels_are_checked_like_rtti_labels(tmp_path, monkeypatch):
    """``startswith('RTTI_')`` skipped every ``NiRTTI_`` label, so its
    statistical VR offset shipped unchecked."""
    pe_layout = _load("pe_layout_under_test", HERE.parent / "commonlibsf" / "pe_layout.py")
    gen = _load("f4_parser_nirtti_test", HERE / "parse_commonlib_types.py")
    monkeypatch.setattr(gen, "SCRIPT_DIR", str(tmp_path / "commonlibf4"))
    monkeypatch.setattr(gen, "PROJECT_DIR", str(tmp_path))
    reports = tmp_path / "build" / "evidence" / "vtable_labels" / "commonlibf4"
    b = ImageBuilder()
    named = b._append(struct.pack("<QQ", IMAGE_BASE + b._append(b"NiNode\0"), 0))
    runtime = b._append(b"\0" * 16)
    exe = tmp_path / "Fallout4VR.exe"
    _write_pe(exe, b.data)
    layout = pe_layout.PELayout.read(str(exe))
    symbols = [{"n": "NiRTTI_NiNode", "t": "label", "v": named, "240": named},
               {"n": "NiRTTI_BSTriShape", "t": "label", "v": runtime, "240": runtime}]
    gen.validate_vtable_labels(symbols, {"v": layout, "240": layout})
    assert symbols[0]["v"] == named
    assert "v" not in symbols[1]                          # zero: unverifiable
    assert symbols[1]["rejected_offsets"] == {"v": "nirtti_unverifiable"}
    assert symbols[1]["240"] == runtime                   # desktop: not strict
    assert (reports / "vtable_labels_dropped_v_nirtti.csv").is_file()
