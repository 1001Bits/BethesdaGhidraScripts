"""Skyrim byte-sig port hints resolve this repo's exes/skyrim/<ver>/ layout."""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def _load():
    spec = importlib.util.spec_from_file_location(
        'sse_bytesig_port_combined_under_test', HERE / 'bytesig_port_combined.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _File:
    def __init__(self, name):
        self._name = name

    def getName(self):
        return self._name


class _Folder:
    def __init__(self, name, files=(), folders=()):
        self._name, self._files, self._folders = name, list(files), list(folders)

    def getName(self):
        return self._name

    def getFiles(self):
        return [_File(n) for n in self._files]

    def getFolders(self):
        return self._folders


def _tree(layout):
    """{'/skyrim/se': ['SkyrimSE.exe'], ...} -> root folder."""
    root = _Folder('')
    for path, files in layout.items():
        folder = root
        for part in path.strip('/').split('/'):
            child = next((f for f in folder.getFolders() if f.getName() == part), None)
            if child is None:
                child = _Folder(part)
                folder._folders.append(child)
            folder = child
        folder._files.extend(files)
    return root


# run_headless imports exes/<game>/<ver>/ into /<game>/<ver>/.
REPO_LAYOUT = {
    '/skyrim/se': ['SkyrimSE.exe'],
    '/skyrim/ae': ['SkyrimSE.exe'],
    '/skyrim/16640': ['SkyrimSE.exe'],
    '/skyrim/17104': ['SkyrimSE.exe.unpacked.exe'],
    '/skyrim/vr': ['SkyrimVR.exe'],
}


@pytest.mark.parametrize('version,expected', [
    ('se', '/skyrim/se/SkyrimSE.exe'),
    ('ae', '/skyrim/ae/SkyrimSE.exe'),
    ('16640', '/skyrim/16640/SkyrimSE.exe'),
    ('17104', '/skyrim/17104/SkyrimSE.exe.unpacked.exe'),
    ('vr', '/skyrim/vr/SkyrimVR.exe'),
])
def test_repo_layout_selects_each_build_without_explicit_path(version, expected):
    module = _load()
    match = module._find_program(_tree(REPO_LAYOUT), module.VERSIONS[version][1])
    assert match is not None and match[0] == expected


@pytest.mark.parametrize('version,expected', [
    ('se', '/Skyrim/SkyrimSE_1_5_97.exe'),
    ('17104', '/Skyrim/SkyrimAE_1_7_104.exe'),
    ('vr', '/Skyrim/SkyrimVR_1_4_15.exe'),
])
def test_version_tagged_names_still_resolve(version, expected):
    module = _load()
    combined = {'/Skyrim': ['SkyrimSE_1_5_97.exe', 'SkyrimAE_1_6_1170.exe',
                            'SkyrimAE_1_7_104.exe', 'SkyrimVR_1_4_15.exe']}
    match = module._find_program(_tree(combined), module.VERSIONS[version][1])
    assert match is not None and match[0] == expected
