import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generated_symbols as gs  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location('t_' + name, os.path.join(HERE, name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reads_the_generators_json_loads_form(tmp_path):
    symbols = [{'n': 'RE::Actor::Kill', 't': 'func', 's': 0x10}]
    path = tmp_path / 'CommonLibImport_X.py'
    path.write_text("VERSION = 'svr'\nSYMBOLS = _json_sym.loads(%r)\n" % json.dumps(symbols),
                    encoding='utf-8')
    assert gs.load_symbols(str(path)) == symbols
    assert gs.assignment_value("VERSION = 'svr'\n") == 'svr'


def test_writeback_aggregate_uses_the_same_reader(tmp_path):
    path = tmp_path / 'CommonLibImport_X.py'
    path.write_text("SYMBOLS = _json_sym.loads('[]')\n", encoding='utf-8')
    assert _load('writeback_aggregate')._load_symbols(str(path)) == []


def test_version_track_maps_only_exact_builds():
    key = _load('version_track').destination_key
    assert key('SkyrimVR_1_4_15.exe') == 'v'
    assert key('SkyrimAE_1_6_1170.exe') == 'a'
    for name in ('SkyrimAE_1_7_104.exe', 'SkyrimAE_1_6_640.exe', 'SkyrimAE_GOG Edition.exe',
                 'SkyrimSE_1_5_97.exe'):
        assert key(name) is None
