#!/usr/bin/env python3
"""Unit tests for clvr_ghidra_util using light fakes of the Ghidra DataType API.

Run: python -m pytest test_clvr_ghidra_util.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clvr_ghidra_util as gu  # noqa: E402


class FakeDT:
    def __init__(self, name, length=8, category='/types.h', cls='StructureDB'):
        self._name, self._len, self._cat, self._cls = name, length, category, cls

    def getName(self):
        return self._name

    def getLength(self):
        return self._len

    def getCategoryPath(self):
        return self._cat

    def getClass(self):
        return type('C', (), {'getSimpleName': staticmethod(lambda: self._cls)})


class FakeComp:
    def __init__(self, name, typename, length):
        self._n, self._t, self._l = name, typename, length

    def getFieldName(self):
        return self._n

    def getLength(self):
        return self._l

    def getDataType(self):
        return FakeDT(self._t, self._l)


class FakeStruct:
    def __init__(self, length, comps):
        self._len, self._comps = length, comps

    def getLength(self):
        return self._len

    def getNumComponents(self):
        return len(self._comps)

    def getComponent(self, i):
        return self._comps[i]


class FakeDTM:
    def __init__(self, dts):
        self._dts = dts

    def getAllDataTypes(self):
        return self._dts

    def getPointer(self, dt, _sz):
        return ('PTR', dt)


def test_struct_metrics_counts_only_protected_bytes():
    s = FakeStruct(0x20, [
        FakeComp('vtbl', 'TESForm__VFTable *', 8),   # protected
        FakeComp('unk08', 'undefined8', 8),          # unk -> not protected
        FakeComp('pad10', 'uint32', 4),              # pad -> not protected
        FakeComp('count', 'uint32', 4),              # protected
    ])
    assert gu.struct_metrics(s) == (0x20, 12)        # 8 + 4 protected bytes


def test_build_by_name_prefers_typesh():
    pdb = FakeDT('Crime', category='/SkyrimSE.pdb')
    th = FakeDT('Crime', category='/types.h')
    by = gu.build_by_name(FakeDTM([pdb, th]))
    assert by['Crime'] is th                         # /types.h wins regardless of order


def test_resolve_type_strips_and_reapplies_pointer():
    actor = FakeDT('Actor')
    dtm = FakeDTM([actor])
    by = {'Actor': actor}
    assert gu.resolve_type(dtm, by, 'Actor') is actor
    # `Actor *64` -> strip width then one pointer
    assert gu.resolve_type(dtm, by, 'Actor *64') == ('PTR', actor)
    assert gu.resolve_type(dtm, by, 'Missing *') is None


def test_types_structs_filters_typesh_structuredb():
    a = FakeDT('A', category='/types.h', cls='StructureDB')
    b = FakeDT('B', category='/SkyrimSE.pdb', cls='StructureDB')
    c = FakeDT('C', category='/types.h', cls='EnumDB')
    got = [d.getName() for d in gu.types_structs(FakeDTM([a, b, c]))]
    assert got == ['A']


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
