from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent

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
