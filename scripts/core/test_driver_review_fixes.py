"""Driver/launcher fixes from the 2026-10 review: each test pins one finding."""
import csv
import os
import sys
import types

import pytest

import console_harvest_sf
import ctor_apply
import evidence_identity
import review_queue
import target_pe
import vtable_name_reconciler as reconciler

SHA = "a" * 64
IMAGE_BASE = 0x140000000


# ------------------------------------------------------------------ fakes
class _Space:
    def getAddress(self, offset):
        return _Addr(offset)

    def equals(self, other):
        return other is self


SPACE = _Space()


class _Addr:
    def __init__(self, offset):
        self._offset = int(offset)

    def getOffset(self):
        return self._offset

    def add(self, delta):
        return _Addr(self._offset + int(delta))

    def compareTo(self, other):
        return (self._offset > other.getOffset()) - (
            self._offset < other.getOffset())

    def getAddressSpace(self):
        return SPACE

    def isMemoryAddress(self):
        return True

    def __eq__(self, other):
        return isinstance(other, _Addr) and other._offset == self._offset

    def __hash__(self):
        return hash(self._offset)

    def __repr__(self):
        return "0x%X" % self._offset


class _JavaClass:
    def __init__(self, name):
        self._name = name

    def getSimpleName(self):
        return self._name


class _DT:
    def __init__(self, name, length, java_class="IntegerDataType"):
        self._name, self._length, self._class = name, length, java_class

    def getName(self):
        return self._name

    def getPathName(self):
        return "/" + self._name

    def getLength(self):
        return self._length

    def getClass(self):
        return _JavaClass(self._class)


class _Source:
    """SourceType stand-in (named so the gate's USER_DEFINED rule ignores it)."""
    DEFAULT = "DEFAULT"
    ANALYSIS = "ANALYSIS"
    IMPORTED = "IMPORTED"
    USER_DEFINED = "USER_DEFINED"


class _Iter:
    def __init__(self, items):
        self._items = list(items)

    def hasNext(self):
        return bool(self._items)

    def next(self):
        return self._items.pop(0)


class _ProgramBase:
    """Identity + transaction surface every driver touches."""

    def __init__(self, name="game.exe"):
        self.name = name
        self.transactions = []

    def getName(self):
        return self.name

    def getExecutableSHA256(self):
        return SHA

    def getImageBase(self):
        return _Addr(IMAGE_BASE)

    def getDefaultPointerSize(self):
        return 8

    def getCurrentTransactionInfo(self):
        return None

    def startTransaction(self, label):
        self.transactions.append([label, None])
        return len(self.transactions) - 1

    def endTransaction(self, transaction_id, commit):
        self.transactions[transaction_id][1] = commit
        return commit


def _stub_modules(monkeypatch, **modules):
    """Install fake ``ghidra.*`` modules for one test."""
    for dotted, attributes in modules.items():
        parts = dotted.split(".")
        for index in range(1, len(parts)):
            parent = ".".join(parts[:index])
            if parent not in sys.modules or not isinstance(
                    sys.modules[parent], types.ModuleType):
                monkeypatch.setitem(sys.modules, parent,
                                    types.ModuleType(parent))
        module = types.ModuleType(dotted)
        for key, value in attributes.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, dotted, module)


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _set_decisions(path, field, values):
    """What a reviewer does: fill the decision column of the decisions CSV."""
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields, rows = reader.fieldnames, list(reader)
    for row in rows:
        row[field] = values(row) or ""
    _write_csv(path, fields, rows)


# ------------------------------------------- 1: ctor_apply covering field
class _Comp:
    def __init__(self, offset, length, type_name, name=None):
        self._offset, self._length = offset, length
        self._type, self._name = _DT(type_name, length), name

    def getOffset(self):
        return self._offset

    def getLength(self):
        return self._length

    def getDataType(self):
        return self._type

    def getFieldName(self):
        return self._name


class _Struct(_DT):
    """Ghidra semantics: getComponentAt is None inside a field;
    getComponentContaining returns the covering field or an undefined
    filler for a gap of a non-packed structure."""

    def __init__(self, name, length, components):
        super().__init__(name, length, "StructureDB")
        self._components = components
        self.replaced = []

    def getDefinedComponents(self):
        return list(self._components)

    def getComponentContaining(self, offset):
        for component in self._components:
            start = component.getOffset()
            if start <= offset < start + component.getLength():
                return component
        if 0 <= offset < self.getLength():
            return _Comp(offset, 1, "undefined")
        return None

    def getComponentAt(self, offset):
        component = self.getComponentContaining(offset)
        return component if component.getOffset() == offset else None

    def replaceAtOffset(self, offset, data_type, length, name, comment):
        self.replaced.append((offset, data_type.getName(), length, name))


def test_offset_inside_a_typed_field_is_never_free():
    member = _Comp(0, 16, "Inner", "member")
    # getComponentAt(8) is None here -- the old code read that as "free".
    assert ctor_apply.is_placeholder_component(None, 8) is False
    assert ctor_apply.is_placeholder_component(member, 8) is False


def _ctor_program(struct):
    program = _ProgramBase()

    class _DTM:
        def getAllDataTypes(self):
            return [struct, _DT("int", 4)]

    program.getDataTypeManager = lambda: _DTM()
    return program


def test_ctor_apply_keeps_a_covering_field_and_drops_numeric_labels(
        tmp_path, monkeypatch):
    struct = _Struct("Actor", 0x20, [_Comp(0, 16, "Inner", "member"),
                                     _Comp(16, 4, "int", "tail")])
    evidence = tmp_path / "ctor_fields.csv"
    decisions = tmp_path / "ctor_decisions.csv"
    fields = ["class", "offset", "type", "name", "slot_state", "votes",
              "confidence", "constructors", "decision"]
    rows = [("0x8", "inside"), ("0x10", "tail2"), ("0x14", "2")]
    _write_csv(evidence, fields, [
        {"class": "Actor", "offset": off, "type": "int", "name": name,
         "slot_state": "unknown", "votes": "2", "confidence": "high",
         "constructors": "a | b"} for off, name in rows])
    evidence_identity.bind_for_hash(evidence, "ctor_fields", SHA, "game.exe")
    review_queue.merge_review_queue(evidence, decisions, review_queue.CTORS)
    monkeypatch.setenv("BGS_CTOR_CSV", str(evidence))
    monkeypatch.setenv("BGS_CTOR_DECISIONS_CSV", str(decisions))
    monkeypatch.setattr(ctor_apply, "APPLY", True)
    monkeypatch.setattr(ctor_apply, "currentProgram", _ctor_program(struct),
                        raising=False)

    ctor_apply.run()

    # +0x8 is inside the typed 16-byte member and +0x10 is the typed tail;
    # only the gap at +0x14 is filled, and ``2`` is not a field name.
    assert struct.replaced == [(0x14, "int", 4, None)]
    assert ctor_apply.field_label_or_none(" speed ") == "speed"
    assert ctor_apply.field_label_or_none("2") is None


# ------------------------------------------- 2: no skip loss
def test_missing_decisions_file_is_a_refusal_not_approve_everything(tmp_path):
    evidence = tmp_path / "globals_evidence.csv"
    _write_csv(evidence, ["global_addr", "inferred_type", "confidence"],
               [{"global_addr": "0x140001000", "inferred_type": "Foo",
                 "confidence": "high"}])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", SHA, "game.exe", image_base=IMAGE_BASE,
        pointer_size=8, address_coordinate="VA")
    with pytest.raises(review_queue.ReviewQueueError,
                       match="no globals decisions CSV"):
        review_queue.load_reviewed_rows(
            evidence, tmp_path / "absent.csv", _ProgramBase(),
            review_queue.GLOBALS)


# ------------------------------------------- 3: reviewed inline singleton
class _Block:
    def __init__(self, start, size, execute=False, write=True):
        self._start, self._size = start, size
        self._execute, self._write = execute, write

    def isInitialized(self):
        return True

    def isExecute(self):
        return self._execute

    def isWrite(self):
        return self._write

    def contains(self, address):
        return self._start <= address.getOffset() < self._start + self._size


class _Memory:
    def __init__(self, blocks, longs=None):
        self._blocks, self._longs = blocks, dict(longs or {})

    def getBlock(self, address):
        for block in self._blocks:
            if block.contains(address):
                return block
        return None

    def contains(self, address):
        return self.getBlock(address) is not None

    def getLong(self, address):
        return self._longs[address.getOffset()]


class _Pointer(_DT):
    def __init__(self, target):
        super().__init__(target.getName() + " *", 8, "PointerDB")


class _Symbol:
    def __init__(self, offset, source):
        self._address, self._source = _Addr(offset), source

    def getAddress(self):
        return self._address

    def getSource(self):
        return self._source


def test_reviewed_inline_singleton_gets_the_struct_not_a_pointer(
        tmp_path, monkeypatch):
    data = 0x140100000
    foo = _DT("Foo", 0x20, "StructureDB")
    bar = _DT("Bar", 0x20, "StructureDB")
    _stub_modules(monkeypatch, **{"ghidra.program.model.symbol":
                                  {"SourceType": _Source}})
    monkeypatch.setattr(target_pe, "driver_target_manifest", lambda _p: {
        "image_base": IMAGE_BASE, "image_size": 0x200000,
        "sections": [{"rva": 0x100000, "virtual_size": 0x10000,
                      "raw_size": 0x10000, "executable": False}]})

    created, cleared, labels = [], [], []

    class _Listing:
        def getInstructionContaining(self, _address):
            return None

        def getDefinedDataContaining(self, _address):
            return None

        def clearCodeUnits(self, start, end, _keep):
            cleared.append((start.getOffset(), end.getOffset()))

        def createData(self, address, data_type):
            created.append((address.getOffset(), data_type.getName()))
            return object()

    class _SymbolTable:
        symbols = [_Symbol(data + 0x308, _Source.USER_DEFINED)]

        def getPrimarySymbol(self, _address):
            return None

        def getSymbolIterator(self, start, _forward):
            return _Iter(s for s in self.symbols
                         if s.getAddress().getOffset() >= start.getOffset())

        def createLabel(self, address, name, _source):
            labels.append((address.getOffset(), name))

    class _DTM:
        def getAllDataTypes(self):
            return [foo, bar]

        def getPointer(self, target, _size):
            return _Pointer(target)

    program = _ProgramBase()
    program.getDataTypeManager = lambda: _DTM()
    program.getListing = lambda: _Listing()
    program.getSymbolTable = lambda: _SymbolTable()
    program.getAddressFactory = lambda: types.SimpleNamespace(
        getDefaultAddressSpace=lambda: SPACE)
    program.getMemory = lambda: _Memory([_Block(data, 0x10000)])

    evidence = tmp_path / "globals_evidence.csv"
    decisions = tmp_path / "globals_decisions.csv"
    fields = ["global_addr", "current_symbol", "inferred_type", "is_pointer",
              "confidence", "decision_type"]
    _write_csv(evidence, fields, [
        {"global_addr": "0x%X" % (data + off), "inferred_type": cls,
         "is_pointer": ptr, "confidence": "high"}
        for off, cls, ptr in ((0x0, "Foo", "0"), (0x100, "Foo", "0"),
                              (0x200, "Bar", "1"), (0x300, "Foo", "0"))])
    evidence_identity.bind_for_hash(
        evidence, "globals_evidence", SHA, "game.exe", image_base=IMAGE_BASE,
        pointer_size=8, address_coordinate="VA")
    review_queue.merge_review_queue(evidence, decisions, review_queue.GLOBALS)
    reviewed = {"0x%X" % data, "0x%X" % (data + 0x300)}
    _set_decisions(decisions, "decision_type",
                   lambda row: "Foo" if row["global_addr"] in reviewed else "")
    monkeypatch.setenv("BGS_GLOBALS_CSV", str(evidence))
    monkeypatch.setenv("BGS_GLOBALS_APPLY_CSV", str(decisions))

    import globals_apply
    monkeypatch.setattr(globals_apply, "APPLY", True)
    monkeypatch.setattr(globals_apply, "currentProgram", program, raising=False)
    globals_apply.run()

    # Reviewed inline -> the struct itself over its full size; unreviewed
    # inline -> untouched; pointer slot -> Class *; an inline struct that
    # would swallow a named global (+0x308) -> skipped.
    assert created == [(data, "Foo"), (data + 0x200, "Bar *")]
    assert cleared == [(data, data + 0x1F), (data + 0x200, data + 0x207)]
    assert labels == [(data, "g_Foo"), (data + 0x200, "g_Bar")]
    assert globals_apply.inline_struct_width(foo) == 0x20


# ------------------------------------------- 5: reconciler expectations
def _vt(full, slots):
    return ("vt", full, 8 * len(slots), "/RE", slots)


def test_reconciler_keys_by_full_name_and_drops_ambiguous_short_names():
    tables = [
        _vt("RE::A::Entry", [(0, "Load")]),
        _vt("RE::B::Entry", [(0, "Save")]),
        _vt("RE::BSTHashMap<RE::Foo::Bar, int>", [(0, "Find")]),
        _vt("RE::Bar", [(0, "Run")]),
        _vt("RE::Same", [(0, "X")]),
        _vt("RE::Same", [(0, "X")]),
        _vt("RE::Twice", [(0, "X")]),
        _vt("RE::Twice", [(0, "Y")]),
    ]
    expectations, ambiguous = reconciler.build_expectations(tables)
    assert ambiguous["Entry"] == ["RE::A::Entry", "RE::B::Entry"]
    assert ambiguous["Twice"] == ["RE::Twice"]
    assert "RE::A::Entry" not in expectations
    assert "RE::Twice" not in expectations
    # The template argument's ``Bar`` no longer collides with RE::Bar.
    assert expectations["RE::Bar"] == ("Bar", {0: "Run"})
    assert expectations["RE::BSTHashMap<RE::Foo::Bar, int>"][0] == \
        "BSTHashMap<RE::Foo::Bar, int>"
    assert expectations["RE::Same"] == ("Same", {0: "X"})
    assert reconciler.split_qualified("A::B<C::D>::E(F::G)") == \
        ["A", "B<C::D>", "E(F::G)"]


# ------------------------------------------- 7: atomic namespace + name
def test_vtable_pipeline_rename_is_one_atomic_symbol_update(monkeypatch):
    import run_vtable_pipeline as pipeline

    class _NS:
        def __init__(self, name, parent=None):
            self.name, self.parent = name, parent

    global_ns = _NS("<global>")

    class _FuncSymbol:
        def __init__(self, fail):
            self.fail = fail
            self.name, self.namespace = None, global_ns

        def getSource(self):
            return _Source.DEFAULT

        def setNameAndNamespace(self, name, namespace, _source):
            if self.fail:
                raise RuntimeError("DuplicateNameException")
            self.name, self.namespace = name, namespace

    class _Func:
        def __init__(self, entry, fail):
            self.entry, self.symbol = entry, _FuncSymbol(fail)

        def getSymbol(self):
            return self.symbol

        def getName(self):
            return self.symbol.name or "FUN_%x" % self.entry

        def setParentNamespace(self, _ns):
            raise AssertionError("two-step rename")

        def setName(self, _name, _source):
            raise AssertionError("two-step rename")

    funcs = {0x140001000: _Func(0x140001000, fail=True),
             0x140001100: _Func(0x140001100, fail=False)}

    class _SymbolTable:
        def getNamespace(self, _name, _parent):
            return None

        def createNameSpace(self, parent, name, _source):
            return _NS(name, parent)

    program = _ProgramBase()
    program.getFunctionManager = lambda: types.SimpleNamespace(
        getFunctionAt=lambda address: funcs.get(address.getOffset()))
    program.getSymbolTable = lambda: _SymbolTable()
    program.getListing = lambda: types.SimpleNamespace(
        getCodeUnitAt=lambda _a: None)
    program.getGlobalNamespace = lambda: global_ns
    program.getAddressFactory = lambda: types.SimpleNamespace(
        getDefaultAddressSpace=lambda: SPACE)
    program.getMemory = lambda: _Memory(
        [_Block(0x140001000, 0x1000, execute=True)])
    _stub_modules(monkeypatch, **{
        "ghidra.program.model.symbol": {"SourceType": _Source},
        "ghidra.app.cmd.function": {"CreateFunctionCmd": object},
        "ghidra.app.cmd.disassemble": {"DisassembleCommand": object}})
    monkeypatch.setattr(pipeline, "resolve_backing_manifest",
                        lambda _program, backing_manifest=None: {})
    monkeypatch.setattr(pipeline, "_manifest_section_for_va",
                        lambda *_a, **_k: {"executable": True})

    stats = pipeline.apply_naming(
        program, [(0x140001000, "Foo::Bar"), (0x140001100, "Foo::Baz")],
        monitor=None)

    failed, renamed = funcs[0x140001000].symbol, funcs[0x140001100].symbol
    assert (failed.name, failed.namespace) == (None, global_ns)
    assert renamed.name == "Baz" and renamed.namespace.name == "Foo"
    assert stats["renamed"] == 1 and stats["errors"] == 1


# ------------------------------------------- 8: console handler sources
class _Handler:
    def __init__(self, name, source):
        self._name, self._source = name, source

    def getName(self):
        return self._name

    def getSymbol(self):
        return types.SimpleNamespace(getSource=lambda: self._source)


@pytest.mark.parametrize("name,source,expected", [
    ("thunk_FUN_1400", _Source.DEFAULT, True),
    ("FUN_1400", _Source.ANALYSIS, True),
    ("thunk_MyHandler", _Source.USER_DEFINED, False),
    ("sub_1400", _Source.IMPORTED, False),
    ("Handler", _Source.DEFAULT, False),
])
def test_console_sf_renames_only_machine_placeholders(name, source, expected):
    assert console_harvest_sf.is_renamable_handler(
        _Handler(name, source), _Source) is expected


# ------------------------------------------- 9: settings decides first
def test_settings_pass_that_fails_every_write_is_rolled_back(monkeypatch):
    import settings_harvest

    class _Type:
        pass

    _stub_modules(monkeypatch, **{
        "ghidra.program.model.symbol": {"SourceType": _Source},
        "ghidra.program.model.data": {
            name: _Type for name in (
                "FloatDataType", "IntegerDataType", "UnsignedIntegerDataType",
                "BooleanDataType", "CharDataType", "ByteDataType",
                "PointerDataType")}})
    key_va, base = 0x140002000, 0x140003000

    class _Data:
        def getDataType(self):
            return _DT("string", 15)

        def getValue(self):
            return "fJumpHeightMin"

        def getAddress(self):
            return _Addr(key_va)

    class _Ref:
        def getFromAddress(self):
            return _Addr(base + 0x10)

        def getReferenceType(self):
            return types.SimpleNamespace(isData=lambda: True)

    def _fail(*_args):
        raise RuntimeError("write refused")

    program = _ProgramBase()
    program.getListing = lambda: types.SimpleNamespace(
        getDefinedData=lambda _forward: _Iter([_Data()]),
        getInstructionContaining=lambda _a: None,
        getDefinedDataContaining=lambda _a: None,
        clearCodeUnits=lambda *_a: None, createData=_fail)
    program.getReferenceManager = lambda: types.SimpleNamespace(
        getReferencesTo=lambda _a: [_Ref()])
    program.getFunctionManager = lambda: types.SimpleNamespace(
        getFunctionContaining=lambda _a: None)
    program.getMemory = lambda: _Memory(
        [_Block(0x140001000, 0x1000, execute=True),
         _Block(0x140002000, 0x10000)],
        {base: 0x140004000, 0x140004000: 0x140001000})
    program.getSymbolTable = lambda: types.SimpleNamespace(
        getPrimarySymbol=lambda _a: _Symbol(base, _Source.DEFAULT),
        createLabel=_fail)
    program.getAddressFactory = lambda: types.SimpleNamespace(
        getDefaultAddressSpace=lambda: SPACE)
    monkeypatch.setattr(settings_harvest, "APPLY", True)
    monkeypatch.setattr(settings_harvest, "currentProgram", program,
                        raising=False)

    with pytest.raises(RuntimeError, match="every write failed"):
        settings_harvest.run()
    # Decided before the transaction ended: rolled back, never committed.
    assert program.transactions == [["settings-harvest", False]]


# ------------------------------------------- 12: miner health + atomic CSV
class _Result:
    def decompileCompleted(self):
        return False

    def getErrorMessage(self):
        return "boom"


def _decompiler(opens):
    class _Decomp:
        disposed = []

        def openProgram(self, _program):
            return opens

        def getLastMessage(self):
            return "Unable to start decompiler process"

        def decompileFunction(self, _function, _timeout, _monitor):
            return _Result()

        def dispose(self):
            _Decomp.disposed.append(True)

    return _Decomp


class _Function:
    def __init__(self, entry):
        self._entry = _Addr(entry)

    def getName(self):
        return "FUN_%x" % self._entry.getOffset()

    def getEntryPoint(self):
        return self._entry


def _miner_stubs(monkeypatch, opens):
    class _PcodeOp:
        CALL = COPY = CAST = PTRSUB = INT_ADD = PTRADD = MULTIEQUAL = 0
        LOAD = INDIRECT = 0

    _stub_modules(monkeypatch, **{
        "ghidra.app.decompiler": {"DecompInterface": _decompiler(opens)},
        "ghidra.program.model.pcode": {"PcodeOp": _PcodeOp},
        "ghidra.program.model.symbol": {"SourceType": _Source,
                                        "SymbolType": _Source}})
    monkeypatch.setattr(target_pe, "driver_target_manifest", lambda _p: {
        "image_base": IMAGE_BASE, "image_size": 0x200000, "sections": []})


def _miner_program():
    program = _ProgramBase()
    functions = [_Function(0x140001000 + 0x10 * i) for i in range(3)]
    program.getFunctionManager = lambda: types.SimpleNamespace(
        getFunctions=lambda _forward: iter(functions),
        getFunctionContaining=lambda _a: functions[0])
    program.getMemory = lambda: _Memory(
        [_Block(0x140001000, 0x1000, execute=True)])
    program.getAddressFactory = lambda: types.SimpleNamespace(
        getDefaultAddressSpace=lambda: SPACE)
    program.getListing = lambda: object()
    program.getGlobalNamespace = lambda: object()
    vtable = types.SimpleNamespace(getName=lambda: "VTABLE_Actor",
                                   getAddress=lambda: _Addr(0x140001800))
    program.getSymbolTable = lambda: types.SimpleNamespace(
        getAllSymbols=lambda _dynamic: _Iter([vtable]))
    ref = types.SimpleNamespace(getFromAddress=lambda: _Addr(0x140001004))
    program.getReferenceManager = lambda: types.SimpleNamespace(
        getReferencesTo=lambda _a: [ref])

    unk = types.SimpleNamespace(getFieldName=lambda: "unk08",
                                getDataType=lambda: _DT("undefined8", 8),
                                getOffset=lambda: 8)
    actor = _DT("Actor", 0x10, "StructureDB")
    actor.getNumComponents = lambda: 1
    actor.getComponent = lambda _i: unk
    actor.getCategoryPath = lambda: "/RE"
    program.getDataTypeManager = lambda: types.SimpleNamespace(
        getAllDataTypes=lambda: [actor])
    return program


@pytest.mark.parametrize("module_name,env", [
    ("ctor_mine", "BGS_CTOR_CSV"),
    ("globals_harvest", "BGS_GLOBALS_CSV"),
    ("registration_harvest", "BGS_REGISTRY_CSV"),
])
@pytest.mark.parametrize("opens", [False, True])
def test_a_broken_decompiler_never_replaces_good_evidence(
        module_name, env, opens, tmp_path, monkeypatch):
    import importlib
    module = importlib.import_module(module_name)
    if module_name == "globals_harvest":
        monkeypatch.setattr(module, "SCOPE", "all")
    _miner_stubs(monkeypatch, opens)
    previous = tmp_path / "evidence.csv"
    previous.write_text("last,good\n1,2\n", encoding="utf-8")
    monkeypatch.setenv(env, str(previous))
    monkeypatch.setattr(module, "currentProgram", _miner_program(),
                        raising=False)
    monkeypatch.setattr(module, "monitor", None, raising=False)

    # Not started: openProgram returned False.  Started: every decompile
    # failed.  Either way: raise (no sentinel), keep the previous CSV.
    with pytest.raises(review_queue.MinerHealthError,
                       match="did not start" if not opens else "decompiles failed"):
        module.run()
    assert previous.read_text(encoding="utf-8") == "last,good\n1,2\n"
    assert sorted(os.listdir(tmp_path)) == ["evidence.csv"]


def test_decompile_health_thresholds():
    review_queue.require_decompile_health("m", 0, 0)            # nothing to do
    review_queue.require_decompile_health("m", 100, 50)         # half: tolerated
    review_queue.require_decompile_health("m", 5, 4)            # small sample
    with pytest.raises(review_queue.MinerHealthError):
        review_queue.require_decompile_health("m", 5, 5)        # total
    with pytest.raises(review_queue.MinerHealthError):
        review_queue.require_decompile_health("m", 100, 51)     # very high


def test_interrupted_csv_write_keeps_the_previous_file(tmp_path):
    target = tmp_path / "evidence.csv"
    target.write_text("previous\n", encoding="utf-8")

    def rows():
        yield ["a", "b"]
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        review_queue.write_csv_atomically(target, ["x", "y"], rows())
    assert target.read_text(encoding="utf-8") == "previous\n"
    assert sorted(os.listdir(tmp_path)) == ["evidence.csv"]
    review_queue.write_csv_atomically(target, ["x", "y"], [[1, 2]])
    assert target.read_text(encoding="utf-8").splitlines() == ["x,y", "1,2"]
