"""starfield.rename uses the pre-1.16 ID numbering; it must not name 1.16 code."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent.parent
SHA = 'ab' * 32


def _load_parser():
    spec = importlib.util.spec_from_file_location(
        'sf_parse_commonlib_types_rename_pool', SCRIPT_DIR / 'parse_commonlib_types.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Layout:
    sha256 = SHA

    @staticmethod
    def classify_rva(rva):
        return 'func', '.text'


class _Lib:
    def __init__(self, db):
        self.sf_db = db


def _tree(tmp_path, rename_text, corpus_text):
    (tmp_path / 'extern' / 'AddressLibraryDatabase').mkdir(parents=True)
    (tmp_path / 'extern' / 'AddressLibraryDatabase' / 'starfield.rename').write_text(
        rename_text, encoding='utf-8')
    (tmp_path / 'scripts' / 'refs').mkdir(parents=True)
    corpus = tmp_path / 'scripts' / 'refs' / 'sf116_named_from_combined_final.csv'
    corpus.write_text(corpus_text, encoding='utf-8')
    return hashlib.sha256(corpus.read_bytes()).hexdigest()


def _bind(monkeypatch, module, tmp_path, corpus_sha):
    monkeypatch.setattr(module, 'PROJECT_DIR', str(tmp_path))
    monkeypatch.setattr(module, 'SCRIPT_DIR', str(tmp_path / 'scripts'))
    monkeypatch.setattr(module, 'CORPUS_ARTIFACT_SHA256', corpus_sha)
    monkeypatch.setattr(module, 'CORPUS_SOURCE_SHA256', SHA)


RENAME = '1\n33961 MemoryManager::GetSingleton_*\n33962 MemoryManager::Allocate_*\n'
CORPUS = ('target_va,name\n'
          '0x14029F7B0,MemoryManager::GetSingleton\n'      # echo of 33961
          '0x14029F7E0,MemoryManager::Allocate_1\n'        # collision-suffixed echo
          '0x1402B7E60,MemoryManager::GetSingleton\n'      # independent evidence
          '0x140300000,SomethingElse::Func\n')
DB_236 = {33961: 0x29F7B0, 33962: 0x29F7E0}


@pytest.mark.parametrize('version', [(1, 16, 236, 0), (1, 16, 244, 0)])
def test_rename_pool_is_not_emitted_for_116(monkeypatch, tmp_path, version):
    module = _load_parser()
    _bind(monkeypatch, module, tmp_path, _tree(tmp_path, RENAME, 'target_va,name\n'))
    out = module._build_fallback_symbols(
        _Lib({33961: 0x29F450, 33962: 0x29F480}), version, _Layout(), verbose=False)
    assert not [s for s in out if s['src'] == 'starfield.rename']


def test_corpus_rows_echoing_rename_names_at_old_id_rvas_are_dropped(monkeypatch, tmp_path):
    module = _load_parser()
    _bind(monkeypatch, module, tmp_path, _tree(tmp_path, RENAME, CORPUS))
    out = module._build_fallback_symbols(
        _Lib(DB_236), (1, 16, 236, 0), _Layout(), verbose=False)
    assert sorted((s['n'], s['sf']) for s in out) == [
        ('MemoryManager::GetSingleton', 0x2B7E60),
        ('SomethingElse::Func', 0x300000),
    ]
    assert {s['src'] for s in out} == {'sf116_corpus'}


def test_rename_pool_needs_an_explicitly_verified_id_space(monkeypatch, tmp_path):
    module = _load_parser()
    _bind(monkeypatch, module, tmp_path, _tree(tmp_path, RENAME, 'target_va,name\n'))
    monkeypatch.setattr(module, 'RENAME_VERIFIED_SF_VERSIONS',
                        frozenset({(1, 99, 0, 0)}))
    out = module._build_fallback_symbols(
        _Lib({33961: 0x1000}), (1, 99, 0, 0), _Layout(), verbose=False)
    assert [(s['n'], s['sf'], s['src']) for s in out] == [
        ('MemoryManager::GetSingleton', 0x1000, 'starfield.rename')]


def test_shipped_rename_ids_disagree_with_commonlibsf():
    rename_path = REPO_DIR / 'extern' / 'AddressLibraryDatabase' / 'starfield.rename'
    ids_h = REPO_DIR / 'extern' / 'CommonLibSF' / 'include' / 'RE'
    if not rename_path.is_file() or not (ids_h / 'IDs.h').is_file():
        pytest.skip('starfield.rename / CommonLibSF IDs.h not present')
    module = _load_parser()
    from ids_parser import parse_ids_h

    class _Identity(dict):
        def get(self, key, default=None):
            return key

    class _IdLib:
        sf_db = _Identity()

    commonlib = {}
    for entry in parse_ids_h(str(ids_h), _IdLib()):
        name = '{}::{}'.format(entry['class_'], entry['name']) if entry['class_'] else entry['name']
        commonlib.setdefault(name, set()).add(entry['sf_off'])
    shared = [(rid, name) for rid, name in module._read_rename_rows(str(rename_path))
              if name in commonlib]
    assert shared
    # Re-enable the pool only after a verified old->new ID remap exists.
    if not any(rid in commonlib[name] for rid, name in shared):
        assert not module.RENAME_VERIFIED_SF_VERSIONS
