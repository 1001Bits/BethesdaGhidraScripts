"""Drivers must prefer no answer over a wrong one."""
import inspect

import console_harvest_sf
import ctor_apply
import ctor_mine
import globals_harvest
import settings_harvest


# ------------------------------------------------------------------ P3
def test_constructor_with_inlined_base_is_attributed_to_the_last_vtable():
    # ctor: base vtable first, own vtable last.  "First store" gave the BASE.
    assert ctor_mine.pick_constructed_class(
        ["TESForm", "Actor"], virtual=False) == "Actor"
    assert ctor_mine.pick_constructed_class(
        ["BaseFormComponent", "TESForm", "Actor"], virtual=False) == "Actor"


def test_destructor_shape_keeps_its_own_first_vtable():
    # A function that sits in a vtable is never a constructor; a destructor
    # writes its own vtable first and the bases afterwards.
    assert ctor_mine.pick_constructed_class(
        ["Actor", "TESForm"], virtual=True) == "Actor"


def test_single_or_repeated_vtable_is_unambiguous():
    assert ctor_mine.pick_constructed_class(["Actor"], virtual=True) == "Actor"
    assert ctor_mine.pick_constructed_class(
        ["Actor", "Actor"], virtual=False) == "Actor"
    assert ctor_mine.pick_constructed_class([], virtual=False) is None


# ------------------------------------------------------------------ P5
class _Type:
    def __init__(self, name, path=None):
        self._name, self._path = name, path or "/" + name

    def getName(self):
        return self._name

    def getPathName(self):
        return self._path


class _Component:
    def __init__(self, offset, type_name, field_name):
        self._offset, self._type, self._field = offset, _Type(type_name), field_name

    def getOffset(self):
        return self._offset

    def getDataType(self):
        return self._type

    def getFieldName(self):
        return self._field


def test_typed_member_named_unk_or_pad_is_not_free():
    assert not ctor_apply.is_placeholder_component(_Component(0x10, "float", "unk10"), 0x10)
    assert not ctor_apply.is_placeholder_component(_Component(0x1C, "uint", "pad1C"), 0x1C)
    assert not ctor_apply.is_placeholder_component(
        _Component(0x20, "MyUndefinedThing", "unk20"), 0x20)


def test_undefined_typed_member_is_a_placeholder_only_at_its_own_offset():
    assert ctor_apply.is_placeholder_component(_Component(0x10, "undefined4", "unk10"), 0x10)
    assert ctor_apply.is_placeholder_component(_Component(0x10, "undefined1[8]", ""), 0x10)
    # No component (packed padding / past the end) is not free either.
    assert not ctor_apply.is_placeholder_component(None, 0x10)
    # Inside a larger component: replacing would split it.
    assert not ctor_apply.is_placeholder_component(_Component(0x10, "undefined8", ""), 0x14)


def test_type_index_is_built_once_and_refuses_colliding_leaf_names():
    walked = []

    def all_types():
        walked.append(1)
        return [_Type("Foo", "/RE/Foo"), _Type("Foo", "/Other/Foo"),
                _Type("Bar", "/RE/Bar")]

    index = ctor_apply.index_types(all_types())
    assert ctor_apply.resolve_indexed(index, "Bar").getPathName() == "/RE/Bar"
    assert ctor_apply.resolve_indexed(index, " /RE/Foo ").getPathName() == "/RE/Foo"
    assert ctor_apply.resolve_indexed(index, "Foo") is None        # ambiguous
    assert ctor_apply.resolve_indexed(index, "Missing") is None
    assert walked == [1]
    # The per-row full DTM walk is gone from the driver.
    source = inspect.getsource(ctor_apply.run)
    assert source.count("getAllDataTypes()") == 1


# ------------------------------------------------------------------ V9
def test_cstr_decodes_java_signed_bytes_and_rejects_binary():
    assert console_harvest_sf.decode_cstr([0x54, 0x47, 0x4D, 0, 0x41], 5) == "TGM"
    assert console_harvest_sf.decode_cstr([-1, 0x41], 2) is None    # 0xFF as Java byte
    assert console_harvest_sf.decode_cstr([0, 0x41], 2) is None
    assert console_harvest_sf.decode_cstr([0x41, 0x42], 1) == "A"


def test_cstr_reads_into_a_java_array_not_a_python_bytearray():
    source = inspect.getsource(console_harvest_sf.run)
    assert "bytearray(" not in source
    assert "JArray(jpype.JByte)" in source


# ------------------------------------------------------- V10 / P8 / P4
def test_no_identity_comparison_against_the_global_namespace():
    import ast
    source = inspect.getsource(globals_harvest.run)
    identity = [
        node.lineno for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Compare)
        and any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops)
        and any(isinstance(side, ast.Name) and side.id == "gns"
                for side in [node.left, *node.comparators])]
    # JPype returns a fresh wrapper per call, so `is`/`is not` never matches.
    assert identity == [] and "isGlobal()" in source


def test_sampling_is_ordered_by_entry_address():
    harvest = inspect.getsource(globals_harvest.run)
    assert "list(refs_by_g[g])[:SAMPLES]" not in harvest
    assert "sorted(refs_by_g[g], key=_entry_offset)[:SAMPLES]" in harvest
    mine = inspect.getsource(ctor_mine.run)
    assert "cand_list = list(cand_funcs)" not in mine
    assert "sorted(cand_funcs" in mine


def test_csv_writers_name_their_encoding():
    import havok_mine
    import registration_harvest
    for module in (ctor_mine, globals_harvest, havok_mine, registration_harvest):
        source = inspect.getsource(module)
        for line in source.splitlines():
            if "open(" in line and ("'w'" in line or '"w"' in line):
                assert "encoding=" in line, (module.__name__, line.strip())


def test_settings_harvest_names_only_default_symbols_and_reports_errors():
    source = inspect.getsource(settings_harvest.run)
    assert "startswith('DAT_')" not in source
    assert "SourceType.DEFAULT" in source
    assert "getInstructionContaining" in source          # per-byte conflict loop
    assert "except Exception:\n                pass" not in source
    assert "errors.append(" in source
