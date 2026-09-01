import ast
import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ckpe_evidence.py")
SPEC = importlib.util.spec_from_file_location("ckpe_evidence_tested", MODULE_PATH)
ckpe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ckpe)


def test_parse_plain_and_extended_relb(tmp_path):
    plain = tmp_path / "Plain.relb"
    plain.write_text("Plain Patch\n2\nABC\nDEF\n", encoding="utf-8")
    parsed = ckpe.parse_relb_file(str(plain))
    assert parsed["format"] == "plain"
    assert [row["rva"] for row in parsed["rows"]] == [0xABC, 0xDEF]
    assert all(row["signature"] == "<nope>" for row in parsed["rows"])

    extended = tmp_path / "Extended.relb"
    extended.write_text(
        "Extended Patch\n1\nextended\n100 6 48??90\n200 0 <nope>\n",
        encoding="utf-8",
    )
    parsed = ckpe.parse_relb_file(str(extended))
    assert parsed["format"] == "extended"
    assert parsed["rows"][0]["signature_length_consistent"] is True
    assert parsed["rows"][1]["declared_mask_length"] == 0


def test_mask_offset_prefix_wildcards_and_string():
    memory = {
        0x122: bytes.fromhex("0D1122334441B0"),
        0x300: b"CKPE evidence",
    }

    def reader(rva, size):
        return memory[rva][:size]

    matched = ckpe.match_signature(reader, 0x100, "v0_0D????????41B0-22")
    assert matched == {"kind": "mask", "status": "matched", "anchor_rva": 0x122}
    assert ckpe.match_signature(reader, 0x100, "0E-22")["status"] == "mismatch"
    string_result = ckpe.match_signature(reader, 0x300, 'str_"CKPE evidence"')
    assert string_result["kind"] == "string_anchor"
    assert string_result["status"] == "unsupported"
    assert ckpe.match_signature(reader, 0x100, "<nope>")["status"] == "absent"
    assert ckpe.match_signature(reader, 0x100, "not-a-mask")["status"] == "unsupported"


def test_source_use_mapping_preserves_callsite_role(tmp_path):
    root = tmp_path
    source = root / "CKPE.SkyrimSE" / "Src" / "Patches" / "Patch.cpp"
    source.parent.mkdir(parents=True)
    source.write_text(
        'SetName("Patch Name");\n'
        'Detours::DetourCall(__CKPE_OFFSET(3), &hook);\n'
        'OldFunction = (Type)__CKPE_OFFSET(4);\n',
        encoding="utf-8",
    )
    parsed = ckpe.parse_patch_source(str(source), str(root))
    assert parsed["patch_names"] == ["Patch Name"]
    assert parsed["uses"][3][0]["role"] == "detour_callsite"
    assert parsed["uses"][4][0]["role"] == "bound_address"
    index = ckpe.build_source_index([str(source)], str(root))
    assert ckpe.source_refs_for(index, "Patch Name", 3)[0]["source_line"] == 2


def test_neutral_labels_are_indexed_and_do_not_claim_function_names():
    assert ckpe.safe_label("Altered Form List.relb", 7) == \
        "CKPE_1_6_1378_1_Altered_Form_List_007"


def test_tree_hash_is_checkout_eol_independent(tmp_path):
    root = tmp_path
    path = root / "Patch.cpp"
    path.write_bytes(b"one\r\ntwo\r\n")
    windows_hash = ckpe.canonical_tree_sha256(str(root), [str(path)])
    path.write_bytes(b"one\ntwo\n")
    assert ckpe.canonical_tree_sha256(str(root), [str(path)]) == windows_hash


def test_reports_are_byte_deterministic(tmp_path):
    report = {
        "schema": ckpe.REPORT_SCHEMA,
        "rows": [{
            "database_file": "Patch.relb", "database_line": 4,
            "patch_name": "Patch", "patch_version": 1, "index": 0,
            "rva": 0x100, "va": 0x140000100, "memory_block": ".text",
            "executable": True, "signature": "90", "signature_kind": "mask",
            "signature_anchor_rva": 0x100, "signature_status": "matched",
            "source_refs": [], "label": "CKPE_1_6_1378_1_Patch_000",
            "eligible": True, "action": "would_apply",
        }],
    }
    first_json, first_csv = ckpe.write_reports(report, str(tmp_path / "one"), "report")
    second_json, second_csv = ckpe.write_reports(report, str(tmp_path / "two"), "report")
    assert Path(first_json).read_bytes() == Path(second_json).read_bytes()
    assert Path(first_csv).read_bytes() == Path(second_csv).read_bytes()
    assert json.loads(Path(first_json).read_text(encoding="utf-8"))["schema"] == \
        ckpe.REPORT_SCHEMA


def test_ghidra_driver_has_no_function_or_primary_symbol_mutators():
    driver = Path(__file__).with_name("apply_ckpe_evidence.py")
    tree = ast.parse(driver.read_text(encoding="utf-8"))
    forbidden = {
        "createFunction", "setName", "setNameAndNamespace", "setPrimary",
    }
    called = {
        node.func.attr for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert called.isdisjoint(forbidden)
