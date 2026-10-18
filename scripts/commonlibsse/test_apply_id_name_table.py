import importlib.util
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _module():
    saved = {n: sys.modules.pop(n) for n in ("address_library",) if n in sys.modules}
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_apply_id_name_table", HERE / "apply_id_name_table.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
        sys.modules.pop("address_library", None)
        sys.modules.update(saved)
    return module


def _row(kind, name, ae="", se=""):
    return {"kind": kind, "name": name, "ae_id": str(ae), "se_id": str(se)}


def test_only_the_targets_namespace_column_is_used_and_bad_rows_refused():
    mod = _module()
    rows = [
        _row("func", "A::F", ae=10, se=20),
        _row("func", "A::G", se=21),                      # SE-only: absent for AE
        _row("func", "Copied::Ctor", ae=68663, se=68663),  # SE id copied into AE column
        _row("func", "Wrong::Pair", ae=99, se=30),         # CommonLib says se 30 -> ae 31
        _row("func", "Dup1", se=40), _row("func", "Dup2", se=40),
        _row("data", "VTABLE_X", se=50), _row("data", "VTABLE_X_0", se=50),
    ]
    clib = {30: 31}
    ae_rows, ae_refused = mod.select_rows(rows, "ae_id", clib)
    assert [r[1] for r in ae_rows] == ["A::F"]
    assert ae_refused["se_id-equals-ae_id"] == 1
    assert ae_refused["contradicts-commonlib-pair"] == 1
    se_rows, se_refused = mod.select_rows(rows, "se_id", clib)
    assert {r[1] for r in se_rows} == {"A::F", "A::G", "Wrong::Pair", "VTABLE_X", "VTABLE_X_0"}
    assert se_refused["func-id-claims-several-names"] == 2      # Dup1/Dup2 on one SE id
    assert se_refused["se_id-equals-ae_id"] == 1


def test_setting_and_ini_and_nirtti_evidence_read_the_key_strings():
    mod = _module()
    base = 0x140000000
    data = bytearray(0x400)
    def put_ptr(off, target):
        struct.pack_into("<Q", data, off, base + 0x1000 + target)
    strings = {0x200: b"fJumpHeightMin\0", 0x240: b"bFoo:General\0", 0x280: b"NiNode\0"}
    for off, s in strings.items():
        data[off:off + len(s)] = s
    put_ptr(0x010 + 0x10, 0x200)    # gs_ object at +0x010
    put_ptr(0x040 + 0x10, 0x240)    # ini_ object at +0x040
    put_ptr(0x080, 0x280)           # NiRTTI object at +0x080
    image = mod.vlc.SectionImage(base, 0x2000, [(0x1000, bytes(data))])
    assert mod.data_evidence("gs_fJumpHeightMin", 0x1010, image) == "ok"
    assert mod.data_evidence("gs_fOther", 0x1010, image) == "setting-key-mismatch"
    assert mod.data_evidence("ini_bFoo_General", 0x1040, image) == "ok"
    assert mod.data_evidence("ini_bFoo_Display", 0x1040, image) == "ini-key-mismatch"
    assert mod.data_evidence("NiRTTI_NiNode", 0x1080, image) == "ok"
    assert mod.data_evidence("NiRTTI_NiAVObject", 0x1080, image) == "nirtti-name-mismatch"
    assert mod.data_evidence("g_SomeGlobal", 0x1010, image) == "unverifiable"


def test_runtime_initialised_nirtti_is_unverifiable_not_a_mismatch():
    mod = _module()
    image = mod.vlc.SectionImage(0x140000000, 0x2000, [(0x1000, bytes(0x100))])
    assert mod.data_evidence("NiRTTI_NiNode", 0x1010, image) == "unverifiable"
    assert mod.data_evidence("NiRTTI_NiNode", 0x1F00, image) == "unverifiable"   # BSS


def test_slot_placeholders_are_recognised():
    mod = _module()
    for name in ("Func1", "Func12_v8", "Unk_A3"):
        assert mod.SLOT_PLACEHOLDER_RE.match(name)
    for name in ("dtor", "Handle", "Function1", "Func"):
        assert not mod.SLOT_PLACEHOLDER_RE.match(name)


def test_name_action_judges_the_leaf_of_literal_global_names():
    act = _module().name_action
    # ``Class::Func2`` stored as one literal Global name by an older pass.
    assert act("Foo::Func2", "Foo::Handle", False, False) == "upgrade-placeholder"
    assert act("Foo::Func2", "Foo::Handle", False, True) == "placeholder-user-defined"
    assert act("Foo::Func2", "Bar::Handle", False, False) == "differs-kept"   # other class
    assert act("Foo::Func2", "Foo::Func3", False, False) == "differs-kept"    # slot vs slot
    assert act("Derived::sub_14053E1B0", "Base::Restart", False, False) == "rename"
    assert act("Derived::sub_14053E1B0", "Base::Restart", False, True) == "placeholder-user-defined"
    assert act("FUN_140001000", "Foo::Bar", True, False) == "rename"
    assert act("Character::Kill", "Actor::Kill", False, True) == "agrees-other-namespace"
    assert act("Actor::KillImpl", "Actor::Kill", False, False) == "differs-kept"
    assert act("Actor::Kill", "Actor::Kill", False, True) == "already-same"
    # Owner opt-in upgrades USER_DEFINED placeholders, never real names.
    assert act("Foo::Func2", "Foo::Handle", False, True, True) == "upgrade-placeholder"
    assert act("Derived::sub_14053E1B0", "Base::Restart", False, True, True) == "rename"
    assert act("Actor::KillImpl", "Actor::Kill", False, True, True) == "differs-kept"
    assert act("Foo::Func2", "Bar::Handle", False, True, True) == "differs-kept"


def test_pdata_index_knows_starts_and_every_unwind_range():
    mod = _module()
    rows = [{"begin_rva": 0x1000, "end_rva": 0x1040, "start": True},
            {"begin_rva": 0x1040, "end_rva": 0x1080, "start": False},   # chained fragment
            {"begin_rva": 0x2000, "end_rva": 0x2010, "start": True}]
    index = mod.PdataIndex(rows, lambda row: row["start"])
    assert 0x1000 in index and 0x2000 in index and 0x1040 not in index
    assert index.overlaps(0x1050, 0x1051)            # inside the fragment
    assert index.overlaps(0x1FF0, 0x2001)            # runs into the next range
    assert not index.overlaps(0x1080, 0x1090)        # leaf gap
    assert not index.overlaps(0x0F00, 0x1000)        # ends right before a range
    assert not mod.PdataIndex().starts
