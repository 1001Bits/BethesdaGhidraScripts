import ast
import importlib.util
import json
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent
MODULE_PATH = SCRIPT_DIR / "ckpe_evidence.py"
SPEC = importlib.util.spec_from_file_location("ckpe_evidence_fo4_tested", MODULE_PATH)
ckpe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ckpe)


def _lock(name):
    return json.loads((SCRIPT_DIR / "refs" / name).read_text(encoding="utf-8"))


def test_fallout4_lock_pins_exact_editor_and_ckpe_snapshot():
    lock = _lock("ckpe_fo4_1_11_137_0.lock.json")
    assert lock["schema"] == ckpe.LOCK_SCHEMA
    assert lock["target"]["version_string"] == "1.11.137.0"
    assert lock["target"]["file_version"] == [1, 11, 137, 0]
    assert lock["target"]["file_size"] == 69017440
    assert lock["target"]["sha256"] == \
        "222fd0aad949e76721d85c922ae508ada6816ba2f3e1fc11647c7239c24c2e13"
    assert lock["source"]["commit"] == \
        "cfd8533d7522822242d0b0602fe77d17bc929cea"
    assert lock["source"]["database"] == {
        "canonical_tree_sha256":
            "0e42fa72021012e12403f9cbb63e13c6bc85cc5764e487053d27fff5f1aafd54",
        "file_count": 87,
        "path": "Database/FO4/1_11_137_0",
    }
    assert lock["source"]["patch_sources"] == {
        "canonical_tree_sha256":
            "ade689c2f29a281025ac80217c96889d757b94651a4e46319250c1d3abd3fa62",
        "file_count": 76,
        "path": "CKPE.Fallout4/Src/Patches",
    }


def test_fallout4_annotation_namespace_is_distinct_from_skyrim():
    fallout = ckpe.annotation_profile(_lock("ckpe_fo4_1_11_137_0.lock.json"))
    skyrim = ckpe.annotation_profile(_lock("ckpe_sse_1_6_1378_1.lock.json"))
    assert fallout == {
        "family": "FO4",
        "version": "1.11.137.0",
        "display_name": "Fallout 4 Creation Kit",
        "label_prefix": "CKPE_FO4_1_11_137_0",
        "marker_prefix": "[BGS:ckpe:fo4:1.11.137.0:",
        "bookmark_type": "BGS CKPE FO4 1.11.137.0",
        "report_stem": "ckpe_fo4_1_11_137_0",
    }
    assert fallout["label_prefix"] != skyrim["label_prefix"]
    assert fallout["marker_prefix"] != skyrim["marker_prefix"]
    assert ckpe.safe_label("Add Change Ref.relb", 3,
                           fallout["label_prefix"]) == \
        "CKPE_FO4_1_11_137_0_Add_Change_Ref_003"


def test_cross_game_target_manifests_are_not_interchangeable():
    core_path = SCRIPT_DIR.parent / "core" / "binary_identity.py"
    spec = importlib.util.spec_from_file_location("binary_identity_fo4_tested",
                                                  core_path)
    binary_identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(binary_identity)
    fallout = _lock("ckpe_fo4_1_11_137_0.lock.json")["target"]
    skyrim = _lock("ckpe_sse_1_6_1378_1.lock.json")["target"]
    matches, reasons = binary_identity.manifest_matches(fallout, skyrim)
    assert matches is False
    assert any(reason.startswith("sha256:") for reason in reasons)
    assert any(reason.startswith("file_version:") for reason in reasons)


def test_fallout4_legacy_recipes_fail_closed():
    unsupported = [
        '!_0_48895C240857',
        's_find_"DestructionNode"',
        'h_"create func"',
        '48895C240857+37',
        'E8????????_REMOVED',
    ]
    for recipe in unsupported:
        parsed = ckpe.parse_signature(recipe)
        assert parsed["kind"] == "unsupported"
        assert ckpe.match_signature(lambda _rva, size: b"\0" * size,
                                    0x1000, recipe)["status"] == "unsupported"


def test_fallout4_wrapper_and_shared_driver_have_no_function_mutators():
    forbidden = {
        "createFunction", "setName", "setNameAndNamespace", "setPrimary",
    }
    called = set()
    for name in ("apply_ckpe_evidence.py", "apply_fallout4_ckpe_evidence.py"):
        tree = ast.parse((SCRIPT_DIR / name).read_text(encoding="utf-8"))
        called.update(
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        )
    assert called.isdisjoint(forbidden)
