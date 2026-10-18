"""The shared-ID table must agree with the address libraries themselves."""
import itertools
import sys
from pathlib import Path

import pytest

import port_names_by_id as port

REPO = Path(__file__).resolve().parents[2]


def _equal_gap(a, b, shift=0):
    """Share of address-adjacent ID pairs in ``a`` whose RVA gap recurs in ``b``.

    Builds of one namespace keep most neighbouring functions at identical
    distances (>0.8 measured); unrelated ID spaces score the ``shift=1``
    control rate (<0.45 measured)."""
    ordered = sorted((rva, ident) for ident, rva in a.items()
                     if ident in b and ident + shift in b)
    hits = total = 0
    for (rva0, id0), (rva1, id1) in zip(ordered, ordered[1:]):
        total += 1
        if b[id1 + shift] - b[id0 + shift] == rva1 - rva0:
            hits += 1
    return hits / total if total else 0.0


@pytest.fixture(scope="module", params=sorted(port._GAMES))
def loaded(request):
    game = request.param
    root = REPO / "addresslibrary"
    if not (root / "sse").is_dir() or not (root / "f4").is_dir():
        pytest.skip("address libraries are not staged")
    lib = port._load_library(game)
    dbs = {build: getattr(lib, attr)
           for build, attr in port._GAMES[game]["attr"].items()}
    if any(not db for db in dbs.values()):
        pytest.skip("an address library for {} is missing".format(game))
    return game, dbs


def test_groups_partition_the_known_builds():
    for game, table in port._GAMES.items():
        members = [build for group in table["groups"] for build in group]
        assert len(members) == len(set(members)), game
        assert set(members) == set(table["attr"]), game


def test_every_pair_matches_the_measured_namespace_relation(loaded):
    game, dbs = loaded
    for source, target in itertools.combinations(sorted(dbs), 2):
        score = _equal_gap(dbs[source], dbs[target])
        if port.shared_namespace(game, source, target):
            assert score > 0.75, (game, source, target, score)
        else:
            assert score < 0.45, (game, source, target, score)


def test_skyrim_se_and_ae_are_never_ported_by_id(monkeypatch, capsys):
    assert not port.shared_namespace("skyrim", "se", "ae")
    assert not port.shared_namespace("skyrim", "ae", "se")
    assert not port.shared_namespace("skyrim", "vr", "17104")
    assert port.shared_namespace("skyrim", "16640", "17104")
    monkeypatch.setattr(sys, "argv", [
        "port_names_by_id.py", "dir", "proj", "--game", "skyrim",
        "--source", "ae", "--target", "se", "--from-program", "a",
        "--target-program", "b", "--target-exe", "c"])
    with pytest.raises(SystemExit):
        port.main()
    assert "do not share an address-library ID namespace" in capsys.readouterr().err


def test_a_source_rva_shared_by_several_ids_has_no_id():
    reverse, ambiguous = port._rva_to_id({1: 0x100, 2: 0x200, 3: 0x100, 4: 0x100})
    assert reverse == {0x200: 2}
    assert ambiguous == {0x100}


def test_a_target_claimed_by_two_names_receives_neither():
    src_db = {1: 0x100, 2: 0x200, 3: 0x300, 4: 0x400}
    tgt_db = {1: 0x900, 2: 0x900, 3: 0xA00, 4: 0xA00}
    rows, stats = port.plan_rows(
        [(0x100, "A::f"), (0x200, "B::g"),           # differ -> both dropped
         (0x300, "C::h"), (0x400, "C::h")],          # agree -> kept once
        src_db, tgt_db)
    assert rows == [("C::h", "", "", "A00", "3")]
    assert stats["target-claimed-twice"] == 2


def test_slot_placeholders_and_foreign_addresses_are_not_ported():
    src_db = {1: 0x15c4354, 2: 0x200, 3: 0x300, 4: 0x400}
    tgt_db = {1: 0x16345F4, 2: 0x1200, 3: 0x1300, 4: 0x1400}
    rows, stats = port.plan_rows(
        [(0x15c4354, "Unwind@1415c4354"),             # own address: retargeted
         (0x200, "Actor::Func12"), (0x300, "BSFoo::Unk_A3"),
         (0x400, "Foo::Load_14053EB00")],              # names another address
        src_db, tgt_db)
    assert rows == [("Unwind@1416345f4", "", "", "16345F4", "1")]
    assert stats["not-portable"] == 3
    assert port.port_name("NS::Read_140000300", 0x300, 0x1300) == "NS::Read_140001300"
    assert port.port_name("Actor::Update", 0x300, 0x1300) == "Actor::Update"
    assert port.port_name("BSFoo::Func3_v8", 0x300, 0x1300) is None
