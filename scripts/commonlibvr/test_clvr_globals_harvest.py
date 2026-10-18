"""CLVR globals harvester votes only for real Structure param-0 types."""
import ast
import os
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HARVESTER = os.path.join(HERE, 'globals_harvest.py')


def _load_without_driver_call():
    """Exec the Ghidra driver minus its trailing top-level ``run()``."""
    with open(HARVESTER, encoding='utf-8') as fh:
        tree = ast.parse(fh.read(), HARVESTER)
    last = tree.body[-1]
    assert (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call) and
            getattr(last.value.func, 'id', None) == 'run')
    tree.body.pop()
    namespace = {'__name__': 'clvr_globals_harvest_under_test', '__file__': HARVESTER}
    exec(compile(tree, HARVESTER, 'exec'), namespace)
    return namespace


class Structure:
    def __init__(self, name):
        self._name = name

    def getName(self):
        return self._name


class Pointer:
    def __init__(self, target, name=None):
        self._target = target
        self._name = name or target.getName() + ' *'

    def getDataType(self):
        return self._target

    def getName(self):
        return self._name


class Builtin:
    def __init__(self, name):
        self._name = name

    def getName(self):
        return self._name


class _Param:
    def __init__(self, data_type):
        self._dt = data_type

    def getDataType(self):
        return self._dt


class _Func:
    def __init__(self, *types_):
        self._params = [_Param(t) for t in types_]

    def getParameters(self):
        return self._params


@pytest.fixture
def harvester(monkeypatch):
    data = types.ModuleType('ghidra.program.model.data')
    data.Pointer, data.Structure = Pointer, Structure
    for name in ('ghidra', 'ghidra.program', 'ghidra.program.model'):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, 'ghidra.program.model.data', data)
    core_dir = os.path.join(os.path.dirname(HERE), 'core')
    monkeypatch.setattr(sys, 'path', [p for p in sys.path
                                      if os.path.normcase(p) != os.path.normcase(core_dir)])
    loaded = set(sys.modules)
    namespace = _load_without_driver_call()
    # Loading core's helper must not leave core/ shadowing sibling module names.
    assert os.path.normcase(core_dir) not in [os.path.normcase(p) for p in sys.path]
    yield namespace
    for name in set(sys.modules) - loaded:   # e.g. core's globals_plan
        sys.modules.pop(name, None)


def test_param0_class_comes_from_core_structure_check(harvester):
    fn = harvester['_param0_class_name']
    assert fn.__code__.co_filename.replace('\\', '/').endswith('core/globals_harvest.py')
    assert 'gu' not in harvester


@pytest.mark.parametrize('param_type,expected', [
    (Pointer(Structure('PlayerCharacter')), 'PlayerCharacter'),
    (Pointer(Pointer(Structure('TESDataHandler'))), 'TESDataHandler'),
    (Structure('BSTimer'), 'BSTimer'),
    # The old name-stripping helper returned these as "classes".
    (Builtin('longlong'), None),
    (Pointer(Builtin('code'), 'code *'), None),
    (Pointer(Builtin('undefined8'), 'undefined8 *64'), None),
])
def test_builtins_do_not_vote_as_classes(harvester, param_type, expected):
    assert harvester['_param0_class_name'](_Func(param_type)) == expected


def test_no_parameters_has_no_class(harvester):
    assert not harvester['_param0_class_name'](_Func())
