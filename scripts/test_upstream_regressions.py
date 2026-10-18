import importlib.util
from pathlib import Path

import discover_combined


REPO_DIR = Path(__file__).resolve().parent.parent


def _load_bytesig_port_combined():
    path = REPO_DIR / "scripts" / "commonlibf4" / "bytesig_port_combined.py"
    spec = importlib.util.spec_from_file_location("f4_bytesig_port_combined", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_combined_fallout_routes_match_repository_directories():
    module = _load_bytesig_port_combined()
    for version in ("og", "ng", "ae", "vr", "221", "240"):
        assert "/{}/".format(version) in module.VERSIONS[version][1]


def test_discovery_identity_uses_canonical_executable_path(monkeypatch, tmp_path):
    import binary_identity

    class _Program:
        def getExecutableSHA256(self):
            return "a" * 64

    program = _Program()
    recorded = tmp_path / "game.exe"
    recorded.write_bytes(b"MZ")
    manifest = {"sha256": "a" * 64}
    calls = []
    # The canonical normaliser (``/C:/...`` -> ``C:\...``) still decides the
    # recorded path; selection now lives in core/target_pe.py (--target-pe).
    monkeypatch.setattr(
        binary_identity, "_program_executable_path",
        lambda value: calls.append(("path", value)) or str(recorded))
    monkeypatch.setattr(
        binary_identity, "inspect_pe",
        lambda path: calls.append(("inspect", path)) or manifest)
    monkeypatch.setattr(
        discover_combined, "verify_ghidra_program",
        lambda value, expected: calls.append(("verify", value, expected)))

    assert discover_combined._verified_program_manifest(program) == (
        str(recorded), manifest)
    assert calls == [
        ("path", program),
        ("inspect", str(recorded)),
        ("verify", program, [manifest]),
    ]


def test_identity_bound_text_artifacts_disable_line_ending_conversion():
    attributes = (REPO_DIR / ".gitattributes").read_text(encoding="ascii")
    protected = (
        "f4_221_pdb_publics.txt",
        "f4_240_pdb_publics.txt",
        "bytesig_ported_221.csv",
        "bytesig_ported_og.csv",
    )
    for name in protected:
        line = next(row for row in attributes.splitlines() if name in row)
        assert line.endswith(" -text")
