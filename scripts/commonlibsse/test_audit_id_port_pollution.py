import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _module():
    saved = sys.modules.pop("address_library", None)
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location(
            "sse_audit_id_port_pollution", HERE / "audit_id_port_pollution.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
        sys.modules.pop("address_library", None)
        if saved is not None:
            sys.modules["address_library"] = saved
    return module


def test_only_a_name_carried_through_the_same_id_is_a_hit():
    audit = _module()
    source_db = {10: 0x100, 11: 0x200, 12: 0x300, 13: 0x400}
    target_db = {10: 0x900, 11: 0x910, 12: 0x920}
    source_names = {0x100: ("Actor::Update", "IMPORTED"),
                    0x200: ("TESForm::GetName", "IMPORTED"),
                    0x300: ("Foo::Bar", "IMPORTED"),
                    0x400: ("No::TargetId", "IMPORTED")}
    target_names = {0x900: ("Actor::Update", "IMPORTED"),     # ported through id 10
                    0x910: ("Something::Else", "USER_DEFINED"),
                    0x999: ("Foo::Bar", "IMPORTED")}         # right name, other address
    assert audit.find_hits(source_db, target_db, source_names, target_names) == [
        ("Actor::Update", 10, 0x100, 0x900, "IMPORTED")]
