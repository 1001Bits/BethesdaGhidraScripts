"""reciprocal_bytesig_port without Ghidra: prototype copies never create
``.conflict`` types and are recorded; apply ledgers are new timestamped files;
apply provenance is keyed per configuration."""
from __future__ import annotations

import csv
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import reciprocal_bytesig_port as port  # noqa: E402


# --------------------------------------------------------------- fake types
class DT:
    def __init__(self, category, name, key=None):
        self.category, self.name, self.key = category, name, key or name

    def getCategoryPath(self):
        return self.category

    def getName(self):
        return self.name

    def getPathName(self):
        return self.category.rstrip("/") + "/" + self.name

    def isEquivalent(self, other):
        return type(other) is type(self) and other.key == self.key


class Builtin(DT):
    def __init__(self, name):
        super().__init__("/", name)


class Struct(DT):
    def __init__(self, category, name, members=(), key=None):
        super().__init__(category, name, key)
        self.members = list(members)

    def getDefinedComponents(self):
        return [types.SimpleNamespace(getDataType=lambda dt=dt: dt)
                for dt in self.members]


class Ptr(DT):
    def __init__(self, target):
        super().__init__(target.getCategoryPath(), target.getName() + " *")
        self.target = target

    def getDataType(self):
        return self.target


class Never:
    """A kind no fake type is an instance of."""


KINDS = {"array": Never, "bitfield": Never, "builtin": Builtin,
         "composite": Struct, "function": Never, "pointer": Ptr,
         "typedef": Never}


class Signature:
    def __init__(self, return_type, *arguments):
        self.return_type, self.arguments = return_type, arguments

    def getReturnType(self):
        return self.return_type

    def getArguments(self):
        return [types.SimpleNamespace(getDataType=lambda dt=dt: dt)
                for dt in self.arguments]


class DTM:
    def __init__(self, *existing):
        self.types = {(dt.getCategoryPath(), dt.getName()): dt for dt in existing}

    def getDataType(self, category, name):
        return self.types.get((category, name))


class SourceType:
    DEFAULT, ANALYSIS, IMPORTED, USER_DEFINED = (
        "DEFAULT", "ANALYSIS", "IMPORTED", "USER_DEFINED")


class SourceFunction:
    def __init__(self, signature):
        self.signature = signature

    def getSignatureSource(self):
        return SourceType.IMPORTED

    def hasUnknownCallingConventionName(self):
        return False

    def getSignature(self, _formal):
        return self.signature


class SourceProgram:
    def __init__(self, function):
        self.function = function

    def getImageBase(self):
        return types.SimpleNamespace(add=lambda rva: rva)

    def getFunctionManager(self):
        return types.SimpleNamespace(getFunctionAt=lambda _addr: self.function)


class TargetFunction:
    def __init__(self, dtm, source=SourceType.ANALYSIS, custom=False):
        self.dtm, self.source, self.custom = dtm, source, custom
        self.signature = Signature(Builtin("undefined8"))
        self.prototype = "undefined8 __fastcall FUN_140001000(void)"

    def getPrototypeString(self, _formal, _convention):
        return self.prototype

    def getSignatureSource(self):
        return self.source

    def hasCustomVariableStorage(self):
        return self.custom

    def getEntryPoint(self):
        return 0x1000

    def getProgram(self):
        return types.SimpleNamespace(getDataTypeManager=lambda: self.dtm)

    def getSignature(self, _formal):
        return self.signature


@pytest.fixture
def apply_cmd(monkeypatch):
    calls = []
    behaviour = {"resolve": lambda signature: signature}

    class ApplyFunctionSignatureCmd:
        def __init__(self, entry, signature, source):
            self.signature = signature

        def applyTo(self, program):
            calls.append(self.signature)
            target = behaviour["function"]
            target.signature = behaviour["resolve"](self.signature)
            target.prototype = "int __fastcall Target(Foo * p)"
            return True

    for name, attributes in {
            "ghidra": {}, "ghidra.app": {}, "ghidra.app.cmd": {},
            "ghidra.app.cmd.function": {
                "ApplyFunctionSignatureCmd": ApplyFunctionSignatureCmd},
            "ghidra.program": {}, "ghidra.program.model": {},
            "ghidra.program.model.symbol": {"SourceType": SourceType}}.items():
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)
    return calls, behaviour


FOO = Struct("/X", "Foo", [Builtin("int"), Builtin("int")], key="Foo{a,b}")
BAR = Struct("/X", "Bar", [FOO], key="Bar{Foo}")


def _copy(target, signature, behaviour, record):
    behaviour["function"] = target
    return port._copy_prototype(SourceProgram(SourceFunction(signature)), 0x10,
                                target, record=record, kinds=KINDS)


def test_a_different_same_path_type_refuses_the_prototype(apply_cmd):
    calls, behaviour = apply_cmd
    signature = Signature(Builtin("int"), Ptr(BAR))        # Foo only as a member
    for existing in (Struct("/X", "Foo", key="Foo{z,w}"),  # different layout
                     Struct("/X", "Foo", key="")):         # empty placeholder
        record = {}
        target = TargetFunction(DTM(existing))
        assert _copy(target, signature, behaviour, record) == "refused_type_conflict"
        assert record["type_conflicts"] == ["/X/Foo"]
        assert record["prototype_before"] == "undefined8 __fastcall FUN_140001000(void)"
        assert record["prototype_source_before"] == "ANALYSIS"
    assert calls == []                                     # nothing applied


def test_missing_types_are_added_and_recorded(apply_cmd):
    calls, behaviour = apply_cmd
    record = {}
    target = TargetFunction(DTM(Struct("/X", "Foo", [], key="Foo{a,b}")))
    signature = Signature(Builtin("int"), Ptr(BAR))
    assert _copy(target, signature, behaviour, record) == "prototype_applied"
    assert record["types_added"] == ["/X/Bar"]             # Foo already equal
    assert record["prototype_after"] == "int __fastcall Target(Foo * p)"
    assert len(calls) == 1


def test_custom_storage_and_user_prototypes_are_kept(apply_cmd):
    _calls, behaviour = apply_cmd
    signature = Signature(Builtin("int"))
    assert _copy(TargetFunction(DTM(), custom=True), signature, behaviour,
                 {}) == "kept_target_custom_storage"
    analyst = TargetFunction(DTM())
    analyst.source = SourceType.USER_DEFINED
    assert _copy(analyst, signature, behaviour, {}) == "kept_target_prototype"


def test_a_renamed_resolution_never_survives(apply_cmd):
    _calls, behaviour = apply_cmd
    behaviour["resolve"] = lambda signature: Signature(
        Builtin("int"), Ptr(Struct("/X", "Foo.conflict", key="Foo{a,b}")))
    with pytest.raises(RuntimeError, match="Foo.conflict"):
        _copy(TargetFunction(DTM()), Signature(Builtin("int"), Ptr(FOO)),
              behaviour, {})


# ------------------------------------------------------- ledgers + provenance
def _proposal(name="RE::TESForm::Lookup", target_rva=0x900):
    parts = tuple(name.split("::"))
    return port.Proposal(
        source_tag="a", source_sha256="a" * 64, source_program_path="/a.exe",
        source_name_type="IMPORTED", source_rva=0x100, target_rva=target_rva,
        qualified_name=name, local_name=parts[-1], namespace=parts[:-1],
        match_kind="exact", signature_bytes=32)


MANIFEST = {"sha256": port.TARGET_SHA256, "program_path": "/CreationKit.exe",
            "program_name": "CreationKit.exe", "image_base": 0x140000000,
            "identity_kind": "ghidra_program_executable_sha256", "sections": []}


def test_apply_ledger_records_mode_and_the_replaced_prototype(tmp_path):
    rows, decisions, accepted = port.resolve_proposals([_proposal()])
    pair = accepted[0]
    ledger = tmp_path / "ledger.csv"
    record = {"outcome": "prototype_applied", "prototype_source_before": "ANALYSIS",
              "prototype_before": "undefined8 FUN_140000900(void)",
              "prototype_after": "bool Lookup(int id)", "types_added": ["/X/A"]}
    port._write_evidence(ledger, rows, decisions, {pair: "applied"},
                         {pair: "FUN_140000900"}, MANIFEST, [], [], "apply",
                         prototype_records={pair: record}, exclusive=True)
    with ledger.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["mode"] == "apply" and row["decision"] == "applied"
    assert row["target_prototype_before"] == "undefined8 FUN_140000900(void)"
    assert row["target_prototype_source_before"] == "ANALYSIS"
    assert row["prototype_types_added"] == "/X/A"
    with pytest.raises(FileExistsError):
        port._write_evidence(ledger, rows, decisions, {pair: "applied"}, {},
                             MANIFEST, [], [], "apply", exclusive=True)


def test_ledger_paths_never_collide(tmp_path):
    now = datetime(2026, 10, 18, 8, 0, 0, tzinfo=timezone.utc)
    first = port._ledger_path(Path("refs/x.csv"), "apply", tmp_path, now)
    assert first == tmp_path / "x.apply.20261018T080000Z.csv"
    first.write_text("", encoding="utf-8")
    assert port._ledger_path(Path("refs/x.csv"), "apply", tmp_path, now) == \
        tmp_path / "x.apply.20261018T080000Z-2.csv"


def test_run_apply_never_reuses_the_dry_run_evidence_path(tmp_path, monkeypatch):
    proposal = _proposal()
    pair = (proposal.qualified_name, proposal.target_rva)
    monkeypatch.setattr(port, "_assert_target_identity", lambda *a, **k: MANIFEST)
    monkeypatch.setattr(port, "_assert_analysis_idle", lambda program: None)
    monkeypatch.setattr(port, "_function_boundaries", lambda program: ({}, set()))
    monkeypatch.setattr(port, "_load_text_block",
                        lambda program: (0x140000000, 0x1000, b""))
    monkeypatch.setattr(port, "_match_source", lambda *a, **k: (
        [proposal], {"name_extraction": {}, "exact": {}, "masked": {}},
        {"sha256": "a" * 64, "program_path": "/a.exe"}))
    monkeypatch.setattr(port, "_target_mapping_decisions", lambda program, pairs: (
        {pair: "would_apply"}, {pair: "FUN_140000900"}))
    monkeypatch.setattr(port, "_apply_mappings", lambda *a, **k: {pair: "applied"})
    provenance = []
    monkeypatch.setattr(port, "_record_apply_provenance",
                        lambda program, path, *a: provenance.append(path))
    target = types.SimpleNamespace(save=lambda *a: None)
    evidence = tmp_path / "dry.csv"
    common = dict(target_program=target, target_path="/CreationKit.exe",
                  source_specs=[("a", "/a.exe")],
                  open_source=lambda path: (object(), lambda: None),
                  evidence_path=evidence, monitor=object(), ledger_dir=tmp_path / "ledgers")

    port._run(apply=False, save=False, **common)
    dry = evidence.read_bytes()
    first = port._run(apply=True, save=True, **common)
    second = port._run(apply=True, save=True, **common)
    assert evidence.read_bytes() == dry                    # dry-run file untouched
    ledgers = sorted(p.name for p in (tmp_path / "ledgers").glob("*.csv"))
    assert len(ledgers) == 4                               # 2 x (preflight + apply)
    assert first["evidence_path"] != second["evidence_path"]
    assert [Path(p) for p in provenance] == [Path(first["evidence_path"]),
                                             Path(second["evidence_path"])]
    assert ".apply." in Path(first["evidence_path"]).name


def test_provenance_options_are_keyed_per_configuration(monkeypatch):
    other = port.PortConfig(**{**{f.name: getattr(port.SKYRIM_CONFIG, f.name)
                                  for f in port.dataclasses.fields(port.PortConfig)},
                               "default_evidence": Path("build/evidence/x.y.csv"),
                               "provenance_key": ""})
    assert port.SKYRIM_CONFIG.provenance_key == "skyrim_to_creationkit_1_6_1378_1"
    assert other.provenance_key == "x_y"                   # '.' is an option separator
    written = {}

    class Options:
        def setString(self, name, value):
            written[name] = value

        def setLong(self, name, value):
            written[name] = value

    class Program:
        PROGRAM_INFO = "Program Information"

        def getOptions(self, _name):
            return Options()

        def getCurrentTransactionInfo(self):
            return None

        def startTransaction(self, _label):
            return 1

        def endTransaction(self, _tx, commit):
            return commit

    for name, attributes in {"ghidra": {}, "ghidra.program": {},
                             "ghidra.program.model": {},
                             "ghidra.program.model.listing": {"Program": Program}}.items():
        module = types.ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(port, "_sha256_file", lambda path: "e" * 64)
    for config in (port.SKYRIM_CONFIG, other):
        port._record_apply_provenance(Program(), Path("ledger.csv"),
                                      {("a", 1): "applied"}, [("a", 1)], config)
    assert written[
        "BGS Reciprocal Bytesig [skyrim_to_creationkit_1_6_1378_1] Applied Count"] == 1
    assert written["BGS Reciprocal Bytesig [x_y] Evidence Path"] == "ledger.csv"
    assert not any(name.startswith("BGS Reciprocal Bytesig Target") for name in written)


def test_pdb_port_copies_prototypes_by_default_only_to_fallout4():
    sys.path.insert(0, str(HERE.parent / "commonlibf4"))
    try:
        import bytesig_port_pdb_to_targets as pdb_port
    finally:
        sys.path.remove(str(HERE.parent / "commonlibf4"))
    sha = "c" * 64
    for target in ("og", "ng", "ae", "221", "240", "vr"):
        assert pdb_port.config_for(target, sha).copy_prototypes, target
    for target in ("se", "ae1170", "16640", "17104", "svr", "sf"):
        assert not pdb_port.config_for(target, sha).copy_prototypes, target
    assert pdb_port.config_for("se", sha, True).copy_prototypes
    assert not pdb_port.config_for("og", sha, False).copy_prototypes
    evidence = pdb_port.config_for("se", sha).default_evidence
    assert evidence.parent.name == "evidence" and "refs" not in evidence.parts
