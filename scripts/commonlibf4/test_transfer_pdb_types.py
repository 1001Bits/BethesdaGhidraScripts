"""transfer_pdb_types without Ghidra: built-ins at the root are skipped, the
whole dependency graph moves under the prefix, and added/kept is counted from
what the target held before the transfer (never by JPype identity)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
_spec = importlib.util.spec_from_file_location(
    "transfer_pdb_types_under_test", HERE / "transfer_pdb_types.py")
transfer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transfer)


class CategoryPath:
    def __init__(self, path):
        self.path = "/" + path.strip("/")

    def getPathElements(self):
        return [part for part in self.path.split("/") if part]

    def isAncestorOrSelf(self, other):
        return (self.path == "/" or other.path == self.path
                or other.path.startswith(self.path + "/"))

    def __eq__(self, other):
        return isinstance(other, CategoryPath) and other.path == self.path

    def __hash__(self):
        return hash(self.path)


class DT:
    def __init__(self, category, name, staging=None):
        self.category, self.name = CategoryPath(category), name

    def getCategoryPath(self):
        return self.category

    def getName(self):
        return self.name

    def getPathName(self):
        return self.category.path.rstrip("/") + "/" + self.name


class Builtin(DT):
    pass


class Pointer(DT):
    pass


class Array(DT):
    pass


KINDS = {"builtin": Builtin, "pointer": Pointer, "array": Array}


def test_root_builtins_and_derived_types_are_not_transferred():
    assert not transfer.is_transferable(Builtin("/", "int"), KINDS)     # lives at /
    assert not transfer.is_transferable(Pointer("/P", "S *"), KINDS)
    assert not transfer.is_transferable(Array("/P", "S[4]"), KINDS)
    assert not transfer.is_transferable(DT("/BuiltInTypes/x", "T"), KINDS)
    assert transfer.is_transferable(DT("/", "HANDLE"), KINDS)            # root typedef
    assert transfer.is_transferable(DT("/P", "S"), KINDS)


class Category:
    def __init__(self, manager, path):
        self.manager, self.path = manager, path

    def getName(self):
        return self.path.getPathElements()[-1]

    def getCategory(self, name):
        wanted = CategoryPath(self.path.path.rstrip("/") + "/" + name)
        return Category(self.manager, wanted) if wanted in self.manager.categories() else None

    def getCategories(self):
        depth = len(self.path.getPathElements()) + 1
        return [Category(self.manager, c) for c in self.manager.categories()
                if len(c.getPathElements()) == depth and self.path.isAncestorOrSelf(c)]

    def getDataTypes(self):
        return [dt for dt in self.manager.types if dt.category == self.path]

    def moveCategory(self, category, _monitor):
        old = category.path.path
        new = self.path.path.rstrip("/") + "/" + category.getName()
        for dt in self.manager.types:          # references follow the types
            if dt.category.path == old or dt.category.path.startswith(old + "/"):
                dt.category = CategoryPath(new + dt.category.path[len(old):])

    def moveDataType(self, dt, _handler):
        dt.category = self.path


class Staging:
    def __init__(self):
        self.types, self.created, self.tx = [], [], []

    def categories(self):
        out = set(self.created)
        for dt in self.types:
            elements = dt.category.getPathElements()
            for depth in range(1, len(elements) + 1):
                out.add(CategoryPath("/".join(elements[:depth])))
        return out

    def startTransaction(self, _label):
        self.tx.append("open")
        return 1

    def endTransaction(self, _tx, commit):
        self.tx.append(commit)

    def addDataType(self, dt, _handler):
        copy = type(dt)(dt.category.path, dt.name)
        self.types.append(copy)
        return copy

    def getRootCategory(self):
        return Category(self, CategoryPath("/"))

    def createCategory(self, path):
        self.created.append(path)
        return Category(self, path)

    def getAllDataTypes(self):
        return list(self.types)


def test_the_whole_graph_is_staged_under_the_prefix():
    staging = Staging()
    source = [DT("/P", "T"), DT("/P/sub", "S"), DT("/", "HANDLE"), Builtin("/", "int")]
    staged = transfer.stage_under_prefix(
        source, staging, CategoryPath("/PDB_1_10_155"), None, "DEFAULT", KINDS)
    assert sorted(dt.getPathName() for dt in staged) == [
        "/PDB_1_10_155/HANDLE", "/PDB_1_10_155/P/T", "/PDB_1_10_155/P/sub/S"]
    assert staging.tx == ["open", True]
    # the built-in stays where Ghidra keeps it and is not offered to the target
    assert [dt.getPathName() for dt in staging.types if isinstance(dt, Builtin)] == ["/int"]


def test_a_source_category_named_like_the_prefix_is_refused():
    staging = Staging()
    with pytest.raises(SystemExit, match="choose another"):
        transfer.stage_under_prefix([DT("/PDB_1_10_155", "T")], staging,
                                    CategoryPath("/PDB_1_10_155"), None, "DEFAULT", KINDS)
    assert staging.tx == ["open", False]


class Target:
    def __init__(self, *paths):
        self.paths, self.added = set(paths), []

    def getDataType(self, category, name):
        path = category.path.rstrip("/") + "/" + name
        return object() if path in self.paths else None

    def addDataType(self, dt, _handler):
        self.added.append(dt.getPathName())
        self.paths.add(dt.getPathName())   # dependencies may be added implicitly
        return dt


def test_added_and_kept_come_from_the_pre_transfer_snapshot():
    staged = [DT("/PDB/P", "S"), DT("/PDB/P", "T"), DT("/PDB", "HANDLE")]
    target = Target("/PDB/P/T")
    assert transfer.transfer(staged, target, "KEEP") == (2, 1)
    assert target.added == ["/PDB/P/S", "/PDB/P/T", "/PDB/HANDLE"]


def test_apply_path_no_longer_builds_empty_category_paths():
    source = (HERE / "transfer_pdb_types.py").read_text(encoding="utf-8")
    assert "getDataTypeManager() is dtm" not in source
    assert '"BuiltIn" in type(dt).__name__' not in source
    assert "stage_under_prefix(" in source and "StandAloneDataTypeManager(" in source
