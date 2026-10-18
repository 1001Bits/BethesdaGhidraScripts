"""apply_enrich / conflict_report must survive the generator's real record shape."""
import ast
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))

import gen_tuples  # noqa: E402
import test_import_gen_fixes as emitter  # noqa: E402  (real generate_script)


def _emitted(tmp_path):
    """STRUCTS/ENUMS/VTABLES exactly as ghidra_import_gen writes them."""
    category = "/CommonLibTest/RE"
    source = emitter._generate(
        tmp_path,
        enums=[emitter._enum("RE::Color", category, [("kRed", 0), ("kBlue", 1)])],
        structs=[
            emitter._struct("RE::Actor", category,
                            fields=[("vtbl", "void*", 0, 8), ("hp", "float", 8, 4)],
                            size=16, has_vtable=True),
            emitter._struct("RE::Variant", category,
                            fields=[("i", "int", 0, 4), ("f", "float", 0, 4)],
                            size=4, kind="union"),
        ],
        vtables={"RE::Actor": {
            "name": "Actor_vtbl", "class_full_name": "RE::Actor", "size": 8,
            "category": category, "slots": [(0, "Update", "void", [])],
            "vtable_kind": "primary", "subobject_offset": 0}})
    return {name: ast.literal_eval(gen_tuples.extract_list(source, name))
            for name in ("STRUCTS", "ENUMS", "VTABLES")}


def test_real_emitter_records_normalise_to_the_shape_the_consumers_index(tmp_path):
    namespace = _emitted(tmp_path)
    # The shape that crashed apply_enrich on its first struct:
    assert {len(record) for record in namespace["STRUCTS"]} == {8}
    assert {len(record) for record in namespace["ENUMS"]} == {5}
    assert {len(record) for record in namespace["VTABLES"]} == {7}
    with pytest.raises(ValueError):
        name, size, category, fields, bases, has_vtable = namespace["STRUCTS"][0]

    skipped = gen_tuples.normalize_namespace(namespace)

    assert skipped == 1                                   # the union
    (actor,) = namespace["STRUCTS"]
    name, size, category, fields, bases, has_vtable = actor  # apply_enrich:974
    assert (name, size, category, has_vtable) == (
        "Actor", 16, "/CommonLibTest/RE", True)
    assert actor[1] == 16 and actor[2] == category           # apply_plan: st[1], st[2]
    assert [field[0] for field in fields] == ["vtbl", "hp"]
    ((ename, esize, ecat, evals),) = namespace["ENUMS"]      # apply_enrich:271
    assert (ename, esize, evals) == ("Color", 4, [("kRed", 0), ("kBlue", 1)])
    ((vname, class_full_name, vtbl_size, vcat, slots),) = namespace["VTABLES"]
    assert (vname, class_full_name, vtbl_size) == ("Actor_vtbl", "RE::Actor", 8)
    assert [tuple(slot)[:2] for slot in slots] == [(0, "Update")]


def test_legacy_records_pass_through_and_unknown_arity_is_an_error():
    legacy = ("Actor", 16, "/C/RE", [], [], False)
    assert gen_tuples.legacy_struct(legacy) == legacy
    assert gen_tuples.legacy_enum(("E", 4, "/C", [])) == ("E", 4, "/C", [])
    assert gen_tuples.legacy_vtable(("V", "RE::A", 8, "/C", [])) == (
        "V", "RE::A", 8, "/C", [])
    for convert in (gen_tuples.legacy_struct, gen_tuples.legacy_enum,
                    gen_tuples.legacy_vtable):
        with pytest.raises(ValueError, match="unsupported"):
            convert(("only", "three", "fields"))


def test_consumers_load_through_the_normaliser():
    """conflict_report imports Ghidra at module level and is exec'd by
    apply_enrich, so assert on its source: no raw load may bypass gen_tuples.
    apply_enrich itself is executed end-to-end below."""
    report = (HERE / "conflict_report.py").read_text(encoding="utf-8")
    assert "legacy_structs(eval(structs_src))" in report


# --------------------------------------------- apply_enrich, executed for real
BASE = 0x140000000
TEXT, RDATA = 0x1000, 0x8000
UPDATE, WALK, MID = 0x1100, 0x1200, 0x1208      # MID: not a .pdata start
VTABLE = RDATA + 0x10


def _manifest(sha="a" * 64):
    return {
        "schema": 1, "sha256": sha, "file_size": 0x4000,
        "pointer_size": 8, "image_base": BASE, "image_size": 0x10000,
        "sections": [
            {"name": ".text", "rva": TEXT, "virtual_size": 0x4000,
             "raw_size": 0x4000, "executable": True},
            {"name": ".rdata", "rva": RDATA, "virtual_size": 0x1000,
             "raw_size": 0x1000, "executable": False},
        ],
        "anchors": [{"rva": TEXT, "bytes": "90" * 16}],
        "function_starts": [UPDATE, WALK],
    }


def _clvr_importer(tmp_path):
    from ghidra_import_gen import build_vtable_structs
    category = "/CommonLibTest/RE"
    actor = emitter._struct(
        "RE::Actor", category, fields=[("vtbl", "void*", 0, 8)], size=8,
        has_vtable=True, vfuncs=[("Update", 0)],
        vmethods={"Update": ("void", [["delta", "f32"]])})
    vtables = build_vtable_structs({"RE::Actor": actor})
    symbols = [
        {"n": "VTABLE_Actor", "t": "label", "v": VTABLE},
        {"n": "Actor::Walk", "t": "func", "v": WALK},
        {"n": "Actor::Mid", "t": "func", "v": MID},
        {"n": "Actor::InData", "t": "func", "v": RDATA + 0x40},
    ]
    emitter._generate(tmp_path, structs=[actor], vtables=vtables,
                      symbols=symbols, version="svr", manifest=_manifest())
    return tmp_path / "Import.py"


@pytest.fixture
def enrich(tmp_path):
    """apply_enrich loaded against fake_ghidra and a generated CLVR importer."""
    import importlib.util
    import fake_ghidra as fg
    previous = fg.install()
    try:
        spec = importlib.util.spec_from_file_location(
            "apply_enrich_under_test", HERE / "apply_enrich.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.IMPORT_PATH = str(_clvr_importer(tmp_path))

        def bind(program):
            def create_function(address, name):
                function = fg.Function(program, address,
                                       "FUN_{:08x}".format(address.getOffset()))
                program.functions[address.getOffset()] = function
                return function
            # run_symbols rebuilds created[] from the live types first.
            program.dtm.getAllDataTypes = lambda: list(program.dtm.types.values())
            module.currentProgram = program
            module.monitor = fg._Monitor()
            module.createFunction = create_function
            return program

        yield module, fg, bind
    finally:
        fg.uninstall(previous)


def test_symbols_phase_completes_through_the_importer_gates(enrich):
    module, fg, bind = enrich
    program = bind(fg.Program(_manifest()))
    program.memory.qwords[BASE + VTABLE] = BASE + UPDATE

    module.run_symbols()      # raised ValueError (5-field VTABLES) before

    assert program.committed("CommonLibVR symbol/vtable improve") == [True]
    assert program.function_at(WALK).getName() == "Actor::Walk"
    # _import_vtable_names ran with an armed target and named the vfunc.
    assert program.function_at(UPDATE).getName() == "Actor::Update"
    # Creation goes through _ensure_function: never mid-body or in data.
    assert BASE + MID not in program.functions
    assert BASE + RDATA + 0x40 not in program.functions


def test_normalised_copies_never_reach_the_importer_globals(enrich):
    module, fg, bind = enrich
    bind(fg.Program(_manifest()))
    view = module._load_generated_ns()
    assert {len(vt) for vt in view["VTABLES"]} == {5}
    assert {len(st) for st in view["STRUCTS"]} == {6}
    importer_globals = view.maps[-1]
    assert {len(vt) for vt in importer_globals["VTABLES"]} == {7}
    assert {len(st) for st in importer_globals["STRUCTS"]} == {8}
    assert importer_globals["_ACTIVE_TARGET"]["sha256"] == "a" * 64


def test_symbols_phase_refuses_a_different_executable(enrich):
    module, fg, bind = enrich
    program = bind(fg.Program(_manifest(sha="b" * 64)))
    with pytest.raises(RuntimeError, match="SHA-256"):
        module.run_symbols()
    assert program.transactions == []
    assert program.functions == {}
