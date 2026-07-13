import pytest

import evidence_identity


def test_binding_round_trip_and_content_guard(tmp_path):
    path = tmp_path / "evidence.csv"
    path.write_text("address,name\n0x10,Foo\n", encoding="utf-8")
    evidence_identity.bind_for_hash(path, "globals", "a" * 64, "game.exe")
    payload = evidence_identity.read_binding(path, "globals", True)
    assert payload["target_sha256"] == "a" * 64
    path.write_text("address,name\n0x20,Bar\n", encoding="utf-8")
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="changed"):
        evidence_identity.read_binding(path, "globals", True)


def test_wrong_kind_is_rejected(tmp_path):
    path = tmp_path / "evidence.csv"
    path.write_text("x\n", encoding="utf-8")
    evidence_identity.bind_for_hash(path, "ctors", "b" * 64)
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="kind"):
        evidence_identity.read_binding(path, "globals")


def test_address_evidence_rejects_rebased_same_sha_program(tmp_path):
    class Address:
        def __init__(self, value):
            self.value = value

        def getOffset(self):
            return self.value

    class Program:
        def __init__(self, base):
            self.base = base

        def getExecutableSHA256(self):
            return "c" * 64

        def getImageBase(self):
            return Address(self.base)

        def getDefaultPointerSize(self):
            return 8

        def getName(self):
            return "game.exe"

    path = tmp_path / "absolute.csv"
    path.write_text("address,name\n0x140001000,Foo\n", encoding="utf-8")
    evidence_identity.bind_evidence(
        path, Program(0x140000000), "globals", address_coordinate="VA")
    evidence_identity.validate_evidence(
        path, Program(0x140000000), "globals", require_content=True)
    with pytest.raises(evidence_identity.EvidenceIdentityError,
                       match="image base"):
        evidence_identity.validate_evidence(
            path, Program(0x150000000), "globals", require_content=True)


def test_rva_evidence_accepts_rebased_same_sha_program(tmp_path):
    class Address:
        def __init__(self, value):
            self.value = value

        def getOffset(self):
            return self.value

    class Program:
        def __init__(self, base):
            self.base = base

        def getExecutableSHA256(self):
            return "d" * 64

        def getImageBase(self):
            return Address(self.base)

        def getDefaultPointerSize(self):
            return 8

        def getName(self):
            return "game.exe"

    path = tmp_path / "relative.csv"
    path.write_text("target_rva,name\n0x1000,Foo\n", encoding="utf-8")
    evidence_identity.bind_evidence(
        path, Program(0x140000000), "functions", address_coordinate="RVA")
    payload = evidence_identity.validate_evidence(
        path, Program(0x150000000), "functions", require_content=True)
    assert payload["address_coordinate"] == "RVA"
