"""Identity gates of the name appliers (no Ghidra needed).

I6  apply_ida_csv_names: the CSV has an OG and an AE address column.  The
    sidecar bound the FILE to one executable but not the COLUMN, so a CSV bound
    to the AE exe run with ``--version og`` stamped OG RVAs onto the AE program
    with every check passing.  Also: setParentNamespace + setName in one
    swallowed ``try`` left ``Namespace::FUN_x`` behind when the rename failed.
I12 apply_og_names never called ``validate_evidence`` on the opened program.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import evidence_identity  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


csv_applier = _load("apply_ida_csv_names_under_test", "apply_ida_csv_names.py")
og_applier = _load("apply_og_names_under_test", "apply_og_names.py")


# --- I6: the address column is part of the binding ---------------------------

def test_version_must_be_the_column_the_sidecar_binds():
    ae_bound = {"kind": "ida_og_ae_names_ae", "address_coordinate": "RVA"}
    assert csv_applier.require_bound_column(ae_bound, "ae") == "ae"
    with pytest.raises(RuntimeError, match="binds the AE address column"):
        csv_applier.require_bound_column(ae_bound, "og")

    og_bound = {"kind": "ida_og_ae_names_og"}
    assert csv_applier.require_bound_column(og_bound, "og") == "og"
    with pytest.raises(RuntimeError, match="binds the OG address column"):
        csv_applier.require_bound_column(og_bound, "ae")


def test_a_kind_that_names_no_column_is_refused():
    for kind in ("ida_og_ae_names", "", None, "og_funcs_json"):
        with pytest.raises(RuntimeError, match="which address column"):
            csv_applier.require_bound_column({"kind": kind}, "ae")


def test_port_names_by_id_output_is_bound_to_its_target_column():
    # port_names_by_id.py writes the target RVA into AE_Addr and binds the kind
    # '<game>_<source>_to_<target>'; OG_Addr is empty in that file.
    for kind in ("f4_og_to_240", "skyrim_se_to_vr", "f4_ae_to_221"):
        assert csv_applier.bound_column(kind) == "ae"
        with pytest.raises(RuntimeError):
            csv_applier.require_bound_column({"kind": kind}, "og")


def test_apply_path_is_wired_to_the_column_check():
    source = (HERE / "apply_ida_csv_names.py").read_text(encoding="utf-8")
    assert "require_bound_column(binding, args.version)" in source
    assert "rename_function(func, namespace_for(ns_parts)" in source
    assert "func.setParentNamespace(" not in source


# --- I6: atomic move + rename ------------------------------------------------

class _Symbol:
    def __init__(self, fail):
        self.fail, self.calls = fail, []

    def setNameAndNamespace(self, name, namespace, source):
        self.calls.append((name, namespace, source))
        if self.fail:
            raise ValueError("duplicate name")


class _Function:
    def __init__(self, fail=False):
        self.symbol = _Symbol(fail)
        self.moved = self.renamed = False

    def getSymbol(self):
        return self.symbol

    def setParentNamespace(self, namespace):      # the old, non-atomic path
        self.moved = True

    def setName(self, name, source):
        self.renamed = True


def test_failed_rename_does_not_leave_the_function_moved():
    func = _Function(fail=True)
    with pytest.raises(ValueError):
        csv_applier.rename_function(func, "NS", "leaf", "IMPORTED")
    assert not func.moved and not func.renamed

    ok = _Function()
    csv_applier.rename_function(ok, "NS", "leaf", "IMPORTED")
    assert ok.symbol.calls == [("leaf", "NS", "IMPORTED")]
    assert not ok.moved and not ok.renamed


# --- I12: apply_og_names validates the evidence against the program ----------

class _Offset:
    def __init__(self, value):
        self.value = value

    def getOffset(self):
        return self.value


class _Program:
    def __init__(self, sha, image_base=0x140000000, pointer_size=8):
        self.sha, self.image_base, self.pointer_size = sha, image_base, pointer_size

    def getExecutableSHA256(self):
        return self.sha

    def getImageBase(self):
        return _Offset(self.image_base)

    def getDefaultPointerSize(self):
        return self.pointer_size

    def getOptions(self, _name):                  # no BGS target manifest
        raise RuntimeError("no options")


def test_og_names_evidence_is_validated_against_the_opened_program(tmp_path):
    funcs = tmp_path / "fallout4_og_funcs.json"
    funcs.write_text(json.dumps({"image_base": 0x140000000, "functions": []}),
                     encoding="utf-8")
    sha = "a" * 64
    binding = evidence_identity.bind_for_hash(
        str(funcs), "og_funcs_json", sha, image_base=0x140000000,
        pointer_size=8, address_coordinate="VA")

    payload = og_applier.require_valid_evidence(str(funcs), _Program(sha), binding)
    assert payload["target_sha256"] == sha

    # The old path compared --target-sha256 strings only: a program rebased
    # away from the VA the names were mined at, or a manifest-bound program
    # whose identity disagrees, was never checked against the sidecar.
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="does not match"):
        og_applier.require_valid_evidence(str(funcs), _Program("b" * 64), binding)
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="image base"):
        og_applier.require_valid_evidence(
            str(funcs), _Program(sha, image_base=0x7FF600000000), binding)
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="kind"):
        og_applier.require_valid_evidence(
            str(funcs), _Program(sha), dict(binding, kind="f4_idc_labels"))
    funcs.write_text("{}", encoding="utf-8")
    with pytest.raises(evidence_identity.EvidenceIdentityError, match="content changed"):
        og_applier.require_valid_evidence(str(funcs), _Program(sha), binding)


def test_og_names_apply_path_calls_the_validation():
    source = (HERE / "apply_og_names.py").read_text(encoding="utf-8")
    assert "require_valid_evidence(args.funcs_json, program, binding)" in source
