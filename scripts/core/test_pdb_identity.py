import struct
import uuid
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import pdb_identity
import pdb_symbols


def _codeview_pe(path, guid, age):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0,
                     0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 6 * 8, 0x2000, 28)
    section = struct.pack("<8sIIIIIIHHI", b".rdata\0\0", 0x300, 0x2000,
                          0x300, 0x400, 0, 0, 0, 0, 0x40000040)
    data[opt + 0xF0:opt + 0xF0 + 40] = section
    record = b"RSDS" + guid.bytes_le + struct.pack("<I", age) + b"test.pdb\0"
    struct.pack_into("<IIHHIIII", data, 0x400, 0, 0, 0, 0, 2,
                     len(record), 0x2100, 0x500)
    data[0x500:0x500 + len(record)] = record
    path.write_bytes(data)


def test_read_pe_codeview(tmp_path):
    guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
    path = tmp_path / "sample.exe"
    _codeview_pe(path, guid, 7)
    identity = pdb_identity.read_pe_codeview(str(path))
    assert identity == {"guid": str(guid).upper(), "age": 7,
                        "pdb_path": "test.pdb"}


def test_omap_mapping_and_deleted_ranges():
    rows = pdb_identity.parse_omap(struct.pack(
        "<IIIIII", 0x1000, 0x2000, 0x1100, 0, 0x1200, 0x3000))
    assert pdb_identity.map_from_source(0x1005, rows) == 0x2005
    assert pdb_identity.map_from_source(0x1150, rows) is None
    assert pdb_identity.map_from_source(0x1208, rows) == 0x3008
    assert pdb_identity.map_from_source(0x900, rows) is None


def test_parse_omap_rejects_unsorted():
    with pytest.raises(pdb_identity.PDBIdentityError, match="increasing"):
        pdb_identity.parse_omap(struct.pack("<IIII", 0x2000, 1, 0x1000, 2))


def test_validate_pdb_rejects_wrong_age(tmp_path, monkeypatch):
    guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
    path = tmp_path / "sample.exe"
    _codeview_pe(path, guid, 7)
    monkeypatch.setattr(pdb_identity, "read_pdb_identity",
                        lambda *_args, **_kwargs: {
                            "guid": str(guid).upper(), "age": 8})
    with pytest.raises(pdb_identity.PDBIdentityError, match="mismatch"):
        pdb_identity.validate_pdb_for_pe(str(path), "unused.pdb")


def test_symbol_cleaning_preserves_double_underscore_identifiers():
    assert pdb_symbols._clean_name("__security_cookie") == "__security_cookie"


def test_pdb_overload_identity_is_retained_and_never_name_only_merged():
    selected = pdb_symbols._select_public_symbols({
        0x1000: [('RE::Actor::Update', '?Update@Actor@RE@@QEAAXH@Z')],
        0x2000: [('RE::Actor::Update', '?Update@Actor@RE@@QEAAXM@Z')],
        0x3000: [('RE::Actor::Draw', '?Draw@Actor@RE@@QEAAXXZ')],
    })
    assert selected[0x1000].decorated_name == '?Update@Actor@RE@@QEAAXH@Z'
    assert not selected[0x1000].name_unique
    assert not selected[0x2000].merge_safe
    assert pdb_symbols.unique_public_merge_target(
        selected[0x1000], [{'n': 'RE::Actor::Update'}]) is None
    assert pdb_symbols.unique_public_merge_target(
        selected[0x3000], [{'n': 'RE::Actor::Draw'}]) == {
            'n': 'RE::Actor::Draw'}
    assert pdb_symbols.unique_public_merge_target(
        selected[0x3000], [{'n': 'one'}, {'n': 'two'}]) is None


def test_pdb_same_rva_aliases_are_not_merge_safe():
    selected = pdb_symbols._select_public_symbols({
        0x1000: [
            ('RE::Actor::Update', '?Update@Actor@RE@@QEAAXH@Z'),
            ('RE::Actor::Update', '?Update@Actor@RE@@QEAAXM@Z'),
        ],
    })
    assert selected[0x1000].name_unique
    assert not selected[0x1000].identity_unique
    assert set(selected[0x1000].aliases) == {
        '?Update@Actor@RE@@QEAAXH@Z', '?Update@Actor@RE@@QEAAXM@Z'}


def test_pdb_symbol_loader_uses_native_msf_publics(tmp_path, monkeypatch):
    pdb_path = tmp_path / "sample.pdb"
    pe_path = tmp_path / "sample.exe"
    pdb_path.write_bytes(b"fixture")
    pe_path.write_bytes(b"fixture")
    publics = (
        SimpleNamespace(rva=0x1010, name="?Run@@YAXXZ", flags=0x2,
                        executable=True),
        SimpleNamespace(rva=0x1020, name="data", flags=0,
                        executable=True),
        SimpleNamespace(rva=0x2010, name="NotCode", flags=0x2,
                        executable=False),
    )
    monkeypatch.setattr(
        pdb_symbols, "validate_pdb_for_pe",
        lambda *_args, **_kwargs: {"guid": "A" * 32, "age": 1})
    monkeypatch.setattr(
        pdb_symbols, "read_pdb_publics",
        lambda *_args, **_kwargs: SimpleNamespace(publics=publics))
    monkeypatch.setattr(
        pdb_symbols, "inspect_pe",
        lambda *_args, **_kwargs: {"sections": [{
            "rva": 0x1000, "virtual_size": 0x100, "raw_size": 0x100,
            "executable": True,
        }]})
    monkeypatch.setattr(pdb_symbols, "undecorate", lambda _name: "Run")

    selected = pdb_symbols.load_pdb_names(
        str(pdb_path), str(pe_path), require_identity=True)
    assert list(selected) == [0x1010]
    assert selected[0x1010].name == "Run"
    assert selected[0x1010].decorated_name == "?Run@@YAXXZ"


def _fake_llvm_install(root):
    platform_key = "test_platform"
    asset = "llvm-test.tar.xz"
    archive_sha = "a" * 64
    lock = {
        "schema": 1,
        "llvm": {
            "version": "20.1.8",
            "release_tag": "llvmorg-20.1.8",
            platform_key + "_asset": asset,
            platform_key + "_sha256": archive_sha,
        },
    }
    (root / "toolchain.lock.json").write_text(
        json.dumps(lock), encoding="utf-8")
    llvm = root / "tools" / "llvm"
    for label, relative in pdb_identity._llvm_binary_relpaths().items():
        path = llvm / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((label + " verified").encode("ascii"))
    pdb_identity.write_llvm_install_receipt(
        llvm, root / "toolchain.lock.json", platform_key, asset, archive_sha)
    return llvm


def test_repo_pdbutil_requires_verified_binary_receipt(tmp_path, monkeypatch):
    llvm = _fake_llvm_install(tmp_path)
    monkeypatch.setattr(pdb_identity, "_repo_root", lambda: tmp_path)
    expected = llvm / Path(
        pdb_identity._llvm_binary_relpaths()["llvm-pdbutil"])
    assert Path(pdb_identity._find_pdbutil()).resolve() == expected.resolve()

    expected.write_bytes(b"tampered")
    with pytest.raises(pdb_identity.PDBIdentityError, match="differs"):
        pdb_identity._find_pdbutil()


def test_pdbutil_ignores_path_and_requires_research_opt_in_for_override(
        tmp_path, monkeypatch):
    empty_repo = tmp_path / "repo"
    empty_repo.mkdir()
    path_tool = tmp_path / "llvm-pdbutil.exe"
    path_tool.write_bytes(b"unverified")
    monkeypatch.setattr(pdb_identity, "_repo_root", lambda: empty_repo)
    monkeypatch.setenv("LLVM_PDBUTIL", str(path_tool))
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(pdb_identity.PDBIdentityError, match="toolchain.lock"):
        pdb_identity._find_pdbutil()
    with pytest.raises(pdb_identity.PDBIdentityError, match="research"):
        pdb_identity._find_pdbutil(str(path_tool))
    monkeypatch.setenv(
        pdb_identity.UNPINNED_PDBUTIL_RESEARCH_OPT_IN, "1")
    with pytest.warns(RuntimeWarning, match="unpinned"):
        assert pdb_identity._find_pdbutil(str(path_tool)) == str(path_tool)
