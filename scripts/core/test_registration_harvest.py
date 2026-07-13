import registration_harvest as rh
import pytest

from evidence_identity import EvidenceIdentityError


def _row(site, name, handler, callee=0x1000, name_arg=1, handler_arg=2):
    return {"callee": callee, "callsite": site, "caller": site - 1,
            "name_arg": name_arg, "handler_arg": handler_arg,
            "name": name, "string": site + 1, "handler": handler}


def test_registry_requires_shared_callee_and_one_to_one_mapping():
    rows = [_row(0x2000 + i, "Name%d" % i, 0x3000 + i)
            for i in range(4)]
    accepted = rh.aggregate_observations(rows, min_sites=4)
    assert len(accepted) == 4
    assert {row["confidence"] for row in accepted} == {"medium"}


def test_registry_rejects_ambiguous_handler_identity():
    rows = [_row(0x2000 + i, "Name%d" % i, 0x3000 + i)
            for i in range(4)]
    rows.append(_row(0x2100, "Different", 0x3000))
    accepted = rh.aggregate_observations(rows, min_sites=4)
    assert all(row["handler"] != 0x3000 for row in accepted)


def test_registry_high_confidence_needs_eight_sites():
    rows = [_row(0x2000 + i, "Name%d" % i, 0x3000 + i)
            for i in range(8)]
    accepted = rh.aggregate_observations(rows, min_sites=4)
    assert len(accepted) == 8
    assert {row["confidence"] for row in accepted} == {"high"}


def test_registry_rejects_cross_registry_global_ambiguity():
    rows = [_row(0x2000 + i, "First%d" % i, 0x3000 + i, 0x1000)
            for i in range(4)]
    rows += [_row(0x4000 + i, "Second%d" % i, 0x5000 + i, 0x1800)
             for i in range(4)]
    rows[-1]["handler"] = 0x3000
    accepted = rh.aggregate_observations(rows, min_sites=4)
    assert all(row["handler"] != 0x3000 for row in accepted)


def test_registry_rejects_unstable_argument_positions():
    rows = [_row(0x2000 + i, "Name%d" % i, 0x3000 + i)
            for i in range(4)]
    rows[-1]["name_arg"] = 3
    rows[-1]["handler_arg"] = 4
    assert rh.aggregate_observations(rows, min_sites=4) == []


def test_target_sha_falls_back_to_ghidra_executable_metadata():
    expected = "a" * 64

    class ProgramWithoutBgsManifest:
        def getExecutableSHA256(self):
            return expected.upper()

    assert rh._target_sha(ProgramWithoutBgsManifest()) == expected


def test_target_sha_rejects_program_without_exact_identity():
    class ProgramWithoutIdentity:
        def getExecutableSHA256(self):
            return ""

    with pytest.raises(EvidenceIdentityError, match="no trustworthy"):
        rh._target_sha(ProgramWithoutIdentity())


def test_registration_address_rejects_overlay_and_out_of_image():
    class Space:
        def __init__(self, name):
            self.name = name

        def equals(self, other):
            return self is other

    class Address:
        def __init__(self, space, offset):
            self.space, self.offset = space, offset

        def getAddressSpace(self):
            return self.space

        def getOffset(self):
            return self.offset

    class Memory:
        @staticmethod
        def contains(_address):
            return True

    default = Space("ram")
    overlay = Space("overlay")
    assert rh._is_default_image_address(
        Address(default, 0x140001000), default, Memory(),
        0x140000000, 0x140010000)
    assert not rh._is_default_image_address(
        Address(overlay, 0x140001000), default, Memory(),
        0x140000000, 0x140010000)
    assert not rh._is_default_image_address(
        Address(default, 0x150000000), default, Memory(),
        0x140000000, 0x140010000)


def test_registration_never_overwrites_nondefault_symbol_source():
    class Symbol:
        def __init__(self, source):
            self.source = source

        def getSource(self):
            return self.source

    class Function:
        def __init__(self, name, source):
            self.name, self.source = name, source

        def getName(self):
            return self.name

        def getSymbol(self):
            return Symbol(self.source)

    assert rh._is_overwritable(Function("FUN_140001000", "DEFAULT"), "DEFAULT")
    assert not rh._is_overwritable(
        Function("FUN_140001000", "USER_DEFINED"), "DEFAULT")
    assert not rh._is_overwritable(Function("sub_140001000", "DEFAULT"), "DEFAULT")
