import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _module():
    saved = {name: sys.modules.pop(name) for name in ("address_library",)
             if name in sys.modules}
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_port_ae_family_by_id", HERE / "port_ae_family_by_id.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
        sys.modules.pop("address_library", None)
        sys.modules.update(saved)
    return module


def test_masked_bytes_must_agree_outside_wildcards():
    port = _module()
    sig = (bytes([0x48, 0x8B, 0, 0, 0xC3]), bytes([1, 1, 0, 0, 1]))
    same_but_reloc = (bytes([0x48, 0x8B, 0x11, 0x22, 0xC3]), bytes([1, 1, 1, 1, 1]))
    different = (bytes([0x48, 0x89, 0x11, 0x22, 0xC3]), bytes([1, 1, 1, 1, 1]))
    assert port.bytes_agree(sig, same_but_reloc)
    assert not port.bytes_agree(sig, different)
    assert not port.bytes_agree(None, sig)
    assert not port.bytes_agree(sig, (b"\x48", b"\x01"))


def test_slot_placeholders_and_only_ae_pairs_are_refused():
    port = _module()
    for name in ("Actor::Func12", "BSFoo::Func3_v8", "Actor::Unk_A3"):
        assert port.SLOT_PLACEHOLDER_RE.search(name)
    for name in ("Actor::Update", "Func", "Actor::Function12"):
        assert not port.SLOT_PLACEHOLDER_RE.search(name)
    assert port._shared_namespace("ae", "17104")
    assert port._shared_namespace("16640", "17104")
    assert not port._shared_namespace("se", "ae")
    assert set(port.DBS) == {"ae", "16640", "17104", "se", "vr"}
    assert port._shared_namespace("se", "vr")
    assert not port._shared_namespace("vr", "ae")


def test_ae_addresses_in_ported_names_become_se_addresses():
    sys.path.insert(0, str(HERE.parent / "creationkit"))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_bytesig_port_ae_to_se", HERE / "bytesig_port_ae_to_se.py")
        port = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(port)
    finally:
        sys.path.remove(str(HERE.parent / "creationkit"))
    assert port.se_local_name("sub_1400FBA60", 0x10200) == "sub_140010200"
    assert port.se_local_name("FUN_140681c60", 0x10200) == "sub_140010200"
    assert port.se_local_name("ReadFromStream_14053EB00", 0x10) == "ReadFromStream_140000010"
    assert port.se_local_name("SetMagnitude", 0x10) == "SetMagnitude"
    assert port.se_local_name("sub", 0x10) == "sub"
    import re
    for name in ("X::Func12", "X::Func12_140837520", "X::Unk_A3"):
        assert re.search(port.SLOT_PLACEHOLDER_RE, name)
    assert not re.search(port.SLOT_PLACEHOLDER_RE, "X::ReadFromStream_14053EB00")


def test_embedded_source_addresses_are_retargeted():
    port = _module()
    assert port.retarget_local_name("sub_1408E7530", 0x140010200) == "sub_140010200"
    assert port.retarget_local_name("Unwind@1415c4354", 0x1416345F4) == "Unwind@1416345f4"
    assert port.retarget_local_name("ClearTarget", 0x140010200) == "ClearTarget"


def test_missing_function_is_never_created_inside_an_unwind_range():
    port = _module()
    ranges = [(0x1000, 0x1080), (0x2000, 0x2040)]
    starts = [begin for begin, _end in ranges]
    assert port._inside_unwind_range(ranges, starts, 0x1010)
    assert not port._inside_unwind_range(ranges, starts, 0x1000)   # its own start
    assert not port._inside_unwind_range(ranges, starts, 0x1080)   # just past it
    assert not port._inside_unwind_range(ranges, starts, 0x1500)   # leaf/funclet gap
    assert port.MIN_CREATE_BYTES >= 16 and port.MIN_FUNCLET_BYTES >= 8


def test_unwind_funclet_names_get_the_se_address():
    sys.path.insert(0, str(HERE.parent / "creationkit"))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_bytesig_port_ae_to_se_unwind", HERE / "bytesig_port_ae_to_se.py")
        port = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(port)
    finally:
        sys.path.remove(str(HERE.parent / "creationkit"))
    assert port.se_local_name("Unwind@1415c4354", 0x10200) == "Unwind@140010200"
    assert port.se_local_name("Unwind@1415C4354", 0x1A200) == "Unwind@14001A200"
    assert port.se_local_name("Foo_Bar_14053eb00", 0x1A200) == "Foo_Bar_14001a200"
    assert "build" in port.DEFAULT_EVIDENCE.parts and "refs" not in port.DEFAULT_EVIDENCE.parts


class _Program:
    def __init__(self, sha, name="p.exe"):
        self.sha, self.name = sha, name

    def getExecutableSHA256(self):
        return self.sha

    def getName(self):
        return self.name


def test_a_program_must_be_the_pinned_build_it_is_used_as():
    import pytest
    port = _module()
    sha_17104 = port.BUILD_SHA256["17104"]
    assert port.require_build(_Program(sha_17104.upper()), "17104", "target") == sha_17104
    # --target-build 16640 --target-program ...1_7_104.exe is refused
    with pytest.raises(SystemExit, match="not the pinned 16640"):
        port.require_build(_Program(sha_17104), "16640", "target")
    assert set(port.BUILD_SHA256) == set(port.DBS)


def test_build_pins_agree_with_the_pdb_port_targets():
    port = _module()
    sys.path.insert(0, str(HERE.parent / "commonlibf4"))
    sys.path.insert(0, str(HERE.parent / "creationkit"))
    try:
        spec = importlib.util.spec_from_file_location(
            "f4_bytesig_port_pdb_to_targets_pins",
            HERE.parent / "commonlibf4" / "bytesig_port_pdb_to_targets.py")
        targets = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(targets)
    finally:
        sys.path.remove(str(HERE.parent / "commonlibf4"))
        sys.path.remove(str(HERE.parent / "creationkit"))
    for build, key in (("se", "se"), ("vr", "svr"), ("ae", "ae1170"),
                       ("16640", "16640"), ("17104", "17104")):
        assert port.BUILD_SHA256[build] == targets.TARGETS[key][1], build


def test_pinned_target_pe_refuses_another_build(monkeypatch):
    import pytest
    port = _module()                      # puts scripts/core on sys.path
    import target_pe
    monkeypatch.setattr(target_pe, "select_target_pe", lambda program, candidates: (
        "SkyrimSE.exe", {"sha256": port.BUILD_SHA256["17104"]}))
    import binary_identity
    monkeypatch.setattr(binary_identity, "verify_ghidra_program",
                        lambda program, manifests: manifests[0])
    assert port.pinned_target_pe(object(), "17104") == "SkyrimSE.exe"
    with pytest.raises(SystemExit, match="not the pinned 16640"):
        port.pinned_target_pe(object(), "16640", "SkyrimSE.exe")


def test_evidence_is_never_overwritten_and_records_results(tmp_path):
    import csv
    import pytest
    from datetime import datetime, timezone
    port = _module()
    now = datetime(2026, 10, 18, 9, 30, 0, tzinfo=timezone.utc)
    first = port.evidence_path("ae", "17104", "apply", directory=tmp_path, now=now)
    assert first.name == "id_port_ae_to_17104.apply.20261018T093000Z.csv"
    rows = [("A::f", 0x10, 5, 0x20, "apply", "FUN_140000020", "f", ("A",), None),
            ("B::g", 0x30, 6, 0x40, "create", "", "g", ("B",), None),
            ("C::h", 0x50, None, None, "no-unique-id", "")]
    port.write_evidence(first, rows, "apply",
                        {0: "renamed", 1: "absorbed-by-earlier-creation"})
    with pytest.raises(FileExistsError):
        port.write_evidence(first, rows, "apply", {})
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        port.evidence_path("ae", "17104", "apply", explicit=str(first))
    assert port.evidence_path("ae", "17104", "apply", directory=tmp_path,
                              now=now) != first
    with open(first, newline="", encoding="utf-8") as handle:
        got = {row["name"]: (row["decision"], row["mode"], row["result"])
               for row in csv.DictReader(handle)}
    assert got == {"A::f": ("apply", "apply", "renamed"),
                   "B::g": ("create", "apply", "absorbed-by-earlier-creation"),
                   "C::h": ("no-unique-id", "apply", "not-applied")}


def test_apply_rows_reports_actual_outcomes(monkeypatch):
    import types
    port = _module()

    class Addr:
        def __init__(self, offset):
            self.offset = offset

    class Symbol:
        def __init__(self, function):
            self.function = function

        def setNameAndNamespace(self, local, namespace, source):
            if local == "boom":
                raise ValueError("duplicate")
            self.function.name = local

    class Function:
        def __init__(self):
            self.name = None

        def getSymbol(self):
            return Symbol(self)

    class Program:
        def __init__(self):
            self.functions, self.instructions = {}, {0x300}
            self.inside = {0x200}

        def getSymbolTable(self):
            return self

        def getFunctionManager(self):
            return self

        def getListing(self):
            return self

        def getGlobalNamespace(self):
            return "global"

        def getNamespace(self, part, parent):
            return part

        def getFunctionContaining(self, address):
            return "f" if address.offset in self.inside else None

        def getInstructionAt(self, address):
            return "insn" if address.offset in self.instructions else None

        def getFunctionAt(self, address):
            return self.functions.get(address.offset)

    class DisassembleCommand:
        def __init__(self, address, *_):
            pass

        def applyTo(self, *_):
            return False

    class CreateFunctionCmd:
        def __init__(self, address):
            self.address = address

        def applyTo(self, program, _monitor):
            program.functions[self.address.offset] = Function()
            return True

    class SourceType:
        ANALYSIS = "ANALYSIS"

    for name, attributes in {
            "ghidra": {}, "ghidra.app": {}, "ghidra.app.cmd": {},
            "ghidra.app.cmd.disassemble": {"DisassembleCommand": DisassembleCommand},
            "ghidra.app.cmd.function": {"CreateFunctionCmd": CreateFunctionCmd},
            "ghidra.program": {}, "ghidra.program.model": {},
            "ghidra.program.model.symbol": {"SourceType": SourceType}}.items():
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)

    rows = [("A::f", 0, 1, 0x100, "apply", "", "f", ("A",), Function()),
            ("B::g", 0, 2, 0x200, "create", "", "g", ("B",), Addr(0x200)),
            ("C::h", 0, 3, 0x300, "create", "", "h", ("C",), Addr(0x300)),
            ("D::i", 0, 4, 0x400, "create", "", "i", ("D",), Addr(0x400)),
            ("E::j", 0, 5, 0x500, "apply", "", "boom", ("E",), Function())]
    results = {}
    done, failed, _errors, created = port.apply_rows(Program(), rows, results=results)
    assert results == {0: "renamed", 1: "absorbed-by-earlier-creation",
                       2: "created+renamed", 3: "no-instruction",
                       4: "rename-failed: duplicate"}
    assert (done, failed, created) == (2, 2, 1)
