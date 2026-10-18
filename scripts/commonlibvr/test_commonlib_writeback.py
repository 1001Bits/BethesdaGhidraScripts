"""commonlib_writeback: read generated SYMBOLS without exec, pick runtime explicitly."""
import csv
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'core'))
import fake_ghidra  # noqa: E402

AE_SHA = 'a' * 64
AE_17104_SHA = 'b' * 64
SYMBOLS = [
    {'n': 'PlayerCharacter::GetSingleton', 't': 'func', 's': 0x100, 'a': 0x200,
     'v': 0x300, 'si': 11, 'ai': 22},
    {'n': "Foo::`vftable'", 't': 'label', 'a': 0x400},
    {'n': 'Café::Bar', 't': 'func', 's': 0x500, 'a': 0x600, 'ai': 33},
]


def _load(monkeypatch, import_path, out_csv):
    monkeypatch.setenv('CLVR_IMPORT', str(import_path))
    monkeypatch.setenv('CLVR_WRITEBACK_CSV', str(out_csv))
    monkeypatch.delenv('CLVR_WRITEBACK_RUNTIME', raising=False)
    sys.modules.pop('clvr_config', None)
    spec = importlib.util.spec_from_file_location(
        'clvr_commonlib_writeback_under_test',
        os.path.join(HERE, 'commonlib_writeback.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # __main__ guard: must not run()
    sys.modules.pop('clvr_config', None)
    return module


def _write_import(path, version='ae', targets=(AE_SHA,)):
    # Same line shapes as scripts/core/ghidra_import_gen.py emits.
    manifests = [{'sha256': sha, 'file_name': 'SkyrimSE.exe'} for sha in targets]
    lines = [
        'VERSION = {}'.format(repr(version)),
        "VERSION_KEYS = {'ae': ('a', 'ai'), 'se': ('s', 'si'), 'svr': ('v', 'si')}",
        'import json as _json_target',
        'TARGET_MANIFESTS = _json_target.loads(' +
        repr(json.dumps(manifests, separators=(',', ':'))) + ')',
        'import json as _json_sym',
        'SYMBOLS = _json_sym.loads(' +
        repr(json.dumps(SYMBOLS, separators=(',', ':'))) + ')',
        "FALLBACK_SYMBOLS = _json.loads('[]')",
    ]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return path


def test_generated_symbols_line_is_decoded_without_exec(monkeypatch, tmp_path):
    imp = _write_import(tmp_path / 'CommonLibImport_CLVR_AE.py')
    module = _load(monkeypatch, imp, tmp_path / 'out.csv')
    assert module._load_symbols(str(imp)) == SYMBOLS
    loaded = module._load_import(str(imp))
    assert loaded['VERSION'] == 'ae'
    assert loaded['TARGET_MANIFESTS'][0]['sha256'] == AE_SHA


def test_runtime_comes_from_bound_import_or_explicit_argument(monkeypatch, tmp_path):
    module = _load(monkeypatch, _write_import(tmp_path / 'i.py'), tmp_path / 'o.csv')
    targets = [{'sha256': AE_SHA}]
    assert module.resolve_runtime('ae', targets, AE_SHA.upper()) == ('ae', 'a')
    assert module.resolve_runtime('ae', targets, AE_SHA, 'ae') == ('ae', 'a')
    # Explicit runtime for a program the import is not bound to.
    assert module.resolve_runtime('svr', [], AE_17104_SHA, 'se') == ('se', 's')


@pytest.mark.parametrize('version,targets,sha,requested', [
    # 1.7.104 / GOG used to match "'ae' in name" and read 1.6.1170 offsets.
    ('ae', [{'sha256': AE_SHA}], AE_17104_SHA, None),
    ('ae', [{'sha256': AE_SHA}], None, None),
    ('ae', [{'sha256': AE_SHA}], AE_17104_SHA, '17104'),
    ('ae', [{'sha256': AE_SHA}], AE_17104_SHA, 'gog'),
    ('ae', [{'sha256': AE_SHA}], AE_SHA, 'se'),   # contradicts the bound target
    ('16640', [{'sha256': AE_SHA}], AE_SHA, None),
    ('ae', [], AE_SHA, None),                      # unbound import
])
def test_unknown_or_unproven_runtimes_fail_closed(monkeypatch, tmp_path, version,
                                                  targets, sha, requested):
    module = _load(monkeypatch, _write_import(tmp_path / 'i.py'), tmp_path / 'o.csv')
    with pytest.raises(ValueError):
        module.resolve_runtime(version, targets, sha, requested)


class _Program(fake_ghidra.Program):
    def __init__(self, sha, name):
        super().__init__({'image_base': 0x140000000, 'sections': [],
                          'pointer_size': 8, 'sha256': sha})
        self._name = name

    def getName(self):
        return self._name


@pytest.fixture
def ghidra():
    previous = fake_ghidra.install()
    yield
    fake_ghidra.uninstall(previous)


def test_run_reads_offsets_for_the_bound_runtime(monkeypatch, tmp_path, ghidra):
    out = tmp_path / 'out.csv'
    module = _load(monkeypatch, _write_import(tmp_path / 'i.py'), out)
    program = _Program(AE_SHA, 'SkyrimSE.exe')
    named = program.add_function(0x200, 'RealName')
    named.signature_source = fake_ghidra.SourceType.USER_DEFINED
    program.add_function(0x600)  # still FUN_
    program.add_function(0x100, 'SE_offset_must_not_be_read')
    monkeypatch.setattr(module, 'currentProgram', program, raising=False)
    module.run()
    with open(out, newline='', encoding='utf-8') as fh:
        rows = list(csv.reader(fh))
    assert rows[1:] == [
        ['MISSING_IN_GHIDRA', 'Café::Bar', 'FUN_140000600', '0x140000600', '', '33'],
        ['NAME_DELTA', 'PlayerCharacter::GetSingleton', 'RealName', '0x140000200', '11', '22'],
    ]


def test_run_refuses_an_ae_named_program_of_another_build(monkeypatch, tmp_path, ghidra):
    out = tmp_path / 'out.csv'
    module = _load(monkeypatch, _write_import(tmp_path / 'i.py'), out)
    monkeypatch.setattr(module, 'currentProgram',
                        _Program(AE_17104_SHA, 'SkyrimAE_1_7_104.exe'), raising=False)
    with pytest.raises(ValueError):
        module.run()
    assert not out.exists()
