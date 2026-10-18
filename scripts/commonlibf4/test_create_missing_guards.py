"""--create-missing of the IDA-name appliers (no Ghidra needed).

``CreateFunctionCmd(addr)`` alone returns True INSIDE an existing function and
splits it, and on undefined bytes makes a 1-byte function with no instruction.
The appliers must refuse a containing function, disassemble first, require an
instruction, and -- when the verified target PE is known -- a .pdata start.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


csv_applier = _load("apply_ida_csv_names_create_test", "apply_ida_csv_names.py")


class Addr:
    def __init__(self, offset):
        self.offset = offset

    def getOffset(self):
        return self.offset


class Block:
    def __init__(self, execute=True, initialized=True):
        self.execute, self.initialized = execute, initialized

    def isExecute(self):
        return self.execute

    def isInitialized(self):
        return self.initialized


class Program:
    """Functions are {entry: size}; ``decodable`` offsets disassemble."""

    def __init__(self, functions=(), decodable=(), instructions=(),
                 block=Block()):
        self.functions = dict(functions)
        self.decodable = set(decodable)
        self.instructions = set(instructions)
        self.block = block
        self.created = []

    # Program
    def getMemory(self):
        return self

    def getFunctionManager(self):
        return self

    def getListing(self):
        return self

    def getImageBase(self):
        return Addr(0x140000000)

    # Memory / Listing / FunctionManager
    def getBlock(self, _addr):
        return self.block

    def getInstructionAt(self, addr):
        return "insn" if addr.getOffset() in self.instructions else None

    def getFunctionContaining(self, addr):
        for entry, size in self.functions.items():
            if entry <= addr.getOffset() < entry + size:
                return ("function", entry)
        return None

    def getFunctionAt(self, addr):
        return ("function", addr.getOffset()) \
            if addr.getOffset() in self.functions else None


class DisassembleCommand:
    def __init__(self, addr, _restrict, _follow):
        self.addr = addr

    def applyTo(self, program, _monitor):
        if self.addr.getOffset() in program.decodable:
            program.instructions.add(self.addr.getOffset())
            return True
        return False


class CreateFunctionCmd:
    """Like Ghidra: no containment check -- that is the caller's job."""

    def __init__(self, addr):
        self.addr = addr

    def applyTo(self, program, _monitor):
        program.created.append(self.addr.getOffset())
        program.functions[self.addr.getOffset()] = 1
        return True


@pytest.fixture
def fake_commands(monkeypatch):
    names = {
        "ghidra": {}, "ghidra.app": {}, "ghidra.app.cmd": {},
        "ghidra.app.cmd.disassemble": {"DisassembleCommand": DisassembleCommand},
        "ghidra.app.cmd.function": {"CreateFunctionCmd": CreateFunctionCmd},
    }
    for name, attributes in names.items():
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)


BASE = 0x140000000


def test_never_created_inside_an_existing_function(fake_commands):
    program = Program(functions={BASE + 0x1000: 0x40}, instructions={BASE + 0x1010})
    function, outcome = csv_applier.create_missing_function(
        program, Addr(BASE + 0x1010), None)
    assert (function, outcome) == (None, "inside-function")
    assert program.created == []                      # nothing split
    assert program.functions == {BASE + 0x1000: 0x40}


def test_undefined_bytes_without_an_instruction_are_refused(fake_commands):
    program = Program()                               # nothing decodes
    function, outcome = csv_applier.create_missing_function(
        program, Addr(BASE + 0x2000), None)
    assert (function, outcome) == (None, "no-instruction")
    assert program.created == []


def test_disassembles_first_then_creates(fake_commands):
    program = Program(decodable={BASE + 0x3000})
    function, outcome = csv_applier.create_missing_function(
        program, Addr(BASE + 0x3000), None)
    assert outcome == "created" and function == ("function", BASE + 0x3000)
    assert program.created == [BASE + 0x3000]


def test_pdata_start_is_required_when_the_pe_is_known(fake_commands):
    program = Program(instructions={BASE + 0x3000, BASE + 0x4000})
    starts = frozenset({0x4000})
    assert csv_applier.create_missing_function(
        program, Addr(BASE + 0x3000), None, starts) == (None, "not-pdata-start")
    function, outcome = csv_applier.create_missing_function(
        program, Addr(BASE + 0x4000), None, starts)
    assert outcome == "created"
    assert program.created == [BASE + 0x4000]


def test_non_executable_memory_is_refused(fake_commands):
    program = Program(block=Block(execute=False), decodable={BASE + 0x10})
    assert csv_applier.create_refusal(program, Addr(BASE + 0x10)) == "not-executable"
    assert csv_applier.create_refusal(Program(block=None), Addr(BASE)) == "not-executable"


def test_function_starts_come_from_the_bound_executable_only(monkeypatch, capsys):
    import binary_identity
    import target_pe

    verified = []
    monkeypatch.setattr(binary_identity, "verify_ghidra_program",
                        lambda program, manifests: verified.append(manifests))
    monkeypatch.setattr(target_pe, "select_target_pe", lambda program, candidates: (
        "x.exe", {"sha256": "a" * 64, "function_starts": [0x1000, 0x2000]}))
    starts = csv_applier.verified_function_starts(object(), "A" * 64)
    assert starts == {0x1000, 0x2000} and len(verified) == 1
    with pytest.raises(RuntimeError, match="not the --target-sha256"):
        csv_applier.verified_function_starts(object(), "b" * 64)

    def gone(program, candidates):
        raise target_pe.TargetPEError("the executable is gone")
    monkeypatch.setattr(target_pe, "select_target_pe", gone)
    assert csv_applier.verified_function_starts(object(), "a" * 64) is None
    assert "structural checks" in capsys.readouterr().out
    with pytest.raises(target_pe.TargetPEError):          # an explicit PE must work
        csv_applier.verified_function_starts(object(), "a" * 64, "given.exe")


def test_both_appliers_and_the_id_port_use_the_guarded_path():
    for name, direct in (("apply_ida_csv_names.py", 1), ("apply_og_names.py", 0)):
        source = (HERE / name).read_text(encoding="utf-8")
        assert "create_missing_function(" in source, name
        # the only CreateFunctionCmd call is the one inside the guarded helper
        assert source.count("CreateFunctionCmd(addr).applyTo") == direct, name
        assert "verified_function_starts(" in source, name
    port = (HERE / "port_names_by_id.py").read_text(encoding="utf-8")
    assert '"--create-missing", "--target-pe", args.target_exe' in port
