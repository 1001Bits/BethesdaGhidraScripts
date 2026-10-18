"""run_bsim_query must canonicalise Ghidra's /C:/... executable path."""
from __future__ import annotations

import contextlib
import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SHA = 'cd' * 32


def _load():
    spec = importlib.util.spec_from_file_location(
        'sf_run_bsim_query_under_test', HERE / 'run_bsim_query.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _DomainFile:
    def getName(self):
        return 'Starfield.exe'

    def getPathname(self):
        return '/Starfield.exe'


class _Folder:
    def getFiles(self):
        return [_DomainFile()]

    def getFolders(self):
        return []


class _Project:
    def getProjectData(self):
        return types.SimpleNamespace(getRootFolder=lambda: _Folder())


class _Program:
    def __init__(self, recorded):
        self.recorded = recorded
        self.saved = False

    def getExecutablePath(self):
        return self.recorded

    def getExecutableSHA256(self):
        return SHA

    def startTransaction(self, label):
        return 1

    def save(self, message, monitor):
        self.saved = True

    def release(self, consumer):
        pass


@pytest.mark.skipif(os.name != 'nt', reason='/C:/ drive form is Windows-only')
def test_ghidra_drive_path_is_canonicalised_before_identity_check(monkeypatch, tmp_path):
    module = _load()
    import binary_identity

    exe = tmp_path / 'Starfield.exe'
    exe.write_bytes(b'MZ')
    program = _Program('/' + str(exe).replace('\\', '/'))   # Ghidra's rendering
    inspected, verified, scripts = [], [], []

    monkeypatch.setitem(sys.modules, 'pyghidra', types.SimpleNamespace(
        start=lambda install_dir=None: None,
        ghidra_script=lambda *a, **k: scripts.append(k['script_args']) or ('', '')))
    for name in ('ghidra', 'ghidra.util', 'java'):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, 'ghidra.util.task', types.SimpleNamespace(
        ConsoleTaskMonitor=object))
    monkeypatch.setitem(sys.modules, 'java.lang', types.SimpleNamespace(Object=object))
    sys.modules['java'].lang = sys.modules['java.lang']

    monkeypatch.setattr(module, 'open_user_project',
                        lambda *a: contextlib.nullcontext(_Project()))
    monkeypatch.setattr(module, 'open_program', lambda *a, **k: program)
    monkeypatch.setattr(binary_identity, 'inspect_pe',
                        lambda path: inspected.append(path) or {'sha256': SHA})
    monkeypatch.setattr(module, 'verify_ghidra_program',
                        lambda prog, manifests: verified.append(manifests))
    monkeypatch.setattr(module, 'end_outer_transaction', lambda *a: None)
    monkeypatch.setattr(module, 'require_script_success', lambda *a: None)
    monkeypatch.setattr(sys, 'argv', ['run_bsim_query.py', 'Starfield.exe', '0.85'])
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)   # main() setdefaults it

    module.main()

    assert inspected == [str(exe)]
    assert verified == [[{'sha256': SHA}]]
    assert scripts[0][-1] == '--target-sha256=' + SHA
    assert program.saved
