"""remove_wrong_importer_symbols without Ghidra: secondary-vtable collateral,
every walked slot reported, never-overwritten ledgers, bound incident CSVs."""
import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def _module():
    spec = importlib.util.spec_from_file_location(
        "sse_remove_wrong_importer_symbols", HERE / "remove_wrong_importer_symbols.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remover = _module()


class SourceType:
    IMPORTED, ANALYSIS, USER_DEFINED, DEFAULT = "IMPORTED", "ANALYSIS", "USER_DEFINED", "DEFAULT"


class SymbolType:
    LABEL, FUNCTION = "LABEL", "FUNCTION"


class CommentType:
    EOL, PLATE = "EOL", "PLATE"


@pytest.fixture
def fake_ghidra(monkeypatch):
    names = {"ghidra": {}, "ghidra.program": {}, "ghidra.program.model": {},
             "ghidra.program.model.symbol": {"SourceType": SourceType,
                                             "SymbolType": SymbolType},
             "ghidra.program.model.listing": {"CommentType": CommentType}}
    for name, attributes in names.items():
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)


class Addr:
    def __init__(self, offset):
        self.offset = offset

    def getOffset(self):
        return self.offset

    def add(self, delta):
        return Addr(self.offset + delta)

    def getNewAddress(self, offset):
        return Addr(offset)

    def __eq__(self, other):
        return isinstance(other, Addr) and other.offset == self.offset

    def __hash__(self):
        return hash(self.offset)


class Block:
    def __init__(self, start, size, execute):
        self.start, self.size, self.execute = start, size, execute

    def contains(self, offset):
        return self.start <= offset < self.start + self.size

    def isExecute(self):
        return self.execute

    def getEnd(self):
        return Addr(self.start + self.size - 1)


class Symbol:
    def __init__(self, name, address, source, kind=SymbolType.LABEL):
        self.name, self.address, self.source, self.kind = name, address, source, kind

    def getName(self):
        return self.name

    def getAddress(self):
        return Addr(self.address)

    def getSource(self):
        return self.source

    def getSymbolType(self):
        return self.kind


class Function:
    def __init__(self, name, qualified=None, source=SourceType.ANALYSIS):
        self.name, self.qualified, self.source = name, qualified or name, source

    def getName(self, qualified=False):
        return self.qualified if qualified else self.name

    def getSymbol(self):
        return Symbol(self.name, 0, self.source, SymbolType.FUNCTION)


BASE = 0x140000000


class Program:
    def __init__(self, pointers, functions, comments, labels):
        self.pointers, self.functions = pointers, functions
        self.comments, self.labels = comments, labels
        self.blocks = [Block(BASE + 0x1000, 0x100, False),    # .rdata vtables
                       Block(BASE + 0x5000, 0x1000, True)]    # .text

    def getImageBase(self):
        return Addr(BASE)

    def getMemory(self):
        return self

    def getListing(self):
        return self

    def getSymbolTable(self):
        return self

    def getFunctionManager(self):
        return self

    def getBlock(self, address):
        return next((b for b in self.blocks if b.contains(address.getOffset())), None)

    def getLong(self, address):
        return self.pointers.get(address.getOffset(), 0)

    def getComment(self, kind, address):
        return self.comments.get((kind, address.getOffset()))

    def getSymbolIterator(self, _pattern, _forward):
        return [s for s in self.labels if s.getName().startswith("VTABLE_")]

    def getSymbols(self, address):
        return [s for s in self.labels if s.address == address.getOffset()]

    def getFunctionAt(self, address):
        return self.functions.get(address.getOffset())


def test_secondary_vtable_slots_are_named_like_the_importer():
    assert remover.walk_owner("VTABLE_Actor") == ("Actor", "")
    assert remover.walk_owner("VTABLE_Actor_2") == ("Actor", "_v2")
    assert remover.slot_name("VTABLE_Actor_3", 7) == "Actor::Func7_v3"
    assert remover.slot_name("VTABLE_BSTEventSink_12", 1) == "BSTEventSink::Func1_v12"


def test_secondary_walk_matches_literal_and_namespaced_names(fake_ghidra):
    label = Symbol("VTABLE_Foo_2", BASE + 0x1000, SourceType.IMPORTED)
    pointers = {BASE + 0x1000: BASE + 0x5000, BASE + 0x1008: BASE + 0x5100,
                BASE + 0x1010: BASE + 0x5200, BASE + 0x1018: BASE + 0x5300}
    functions = {
        BASE + 0x5000: Function("Foo::Func1_v2"),                   # literal Global
        BASE + 0x5100: Function("Func2_v2", "Foo::Func2_v2"),      # real namespace
        BASE + 0x5200: Function("Other::Thing"),                   # not walk-named
    }                                                              # 0x5300: none
    comments = {(CommentType.EOL, BASE + 0x5000): "ID 1\nVTABLE Foo::Func1_v2",
                (CommentType.PLATE, BASE + 0x5100): "VTABLE Foo::Func2_v2"}
    program = Program(pointers, functions, comments, [label])
    rows = [{"name": "VTABLE_Foo_2", "kind": "label", "wrong_rva": "0x1000",
             "rva": 0x1000}]
    decisions = remover.plan(program, rows)
    summary = [(row["name"], action) for row, action, _d, _t in decisions]
    assert summary == [
        ("VTABLE_Foo_2", "delete-label"),
        ("Foo::Func1_v2", "reset-function-name"),
        ("Foo::Func2_v2", "reset-function-name"),
        ("Foo::Func3_v2", "name-mismatch"),        # every walked slot reported
        ("Foo::Func4_v2", "absent"),
    ]


def test_ledgers_are_timestamped_and_never_overwritten(tmp_path):
    now = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
    first = remover.ledger_path("x/incident.csv", "applied", tmp_path, now)
    assert first.name == "incident.applied.20261018T120000Z.csv"
    decisions = [({"name": "A", "kind": "label", "wrong_rva": "0x10"},
                  "delete-label", "IMPORTED label", None)]
    remover.write_ledger(first, decisions, "applied", ["deleted"])
    second = remover.ledger_path("x/incident.csv", "applied", tmp_path, now)
    assert second != first and not second.exists()
    with pytest.raises(FileExistsError):
        remover.write_ledger(first, decisions, "applied", ["deleted"])
    text = first.read_text(encoding="utf-8").splitlines()
    assert text[0] == "name,kind,rva,mode,action,result,detail"
    assert text[1] == "A,label,0x10,applied,delete-label,deleted,IMPORTED label"


def test_apply_requires_a_bound_incident_csv(tmp_path, capsys):
    incident = tmp_path / "incident.csv"
    incident.write_text("name,kind,wrong_rva\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="bind_evidence"):
        remover.incident_binding(incident, require=True)
    assert remover.incident_binding(incident, require=False) is None
    assert "--apply will refuse" in capsys.readouterr().out


def test_bound_sha_not_the_program_path_selects_the_build(monkeypatch):
    import target_pe
    checked = []
    monkeypatch.setattr(remover, "validate_evidence",
                        lambda *args, **kwargs: checked.append("evidence"))
    monkeypatch.setattr(remover, "verify_ghidra_program",
                        lambda program, manifests: checked.append("program"))
    monkeypatch.setattr(target_pe, "select_target_pe",
                        lambda program, candidates: ("p.exe", {"sha256": "b" * 64}))
    binding = {"kind": "importer_wrong_symbols", "target_sha256": "A" * 64}
    with pytest.raises(SystemExit, match="not the incident"):
        remover.verify_bound_program(object(), "c.csv", binding)
    monkeypatch.setattr(target_pe, "select_target_pe",
                        lambda program, candidates: ("p.exe", {"sha256": "a" * 64}))
    checked.clear()
    remover.verify_bound_program(object(), "c.csv", binding, "p.exe")
    assert checked == ["evidence", "program"]
