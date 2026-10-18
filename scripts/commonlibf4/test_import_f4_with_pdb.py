import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PE = REPO / "FO4 PDB" / "Fallout4.exe"
PDB = REPO / "FO4 PDB" / "Fallout4.pdb"
BETA_PDB = REPO / "FO4 PDB" / "Fallout4Beta.pdb"


def _module():
    spec = importlib.util.spec_from_file_location(
        "f4_import_with_pdb", HERE / "import_f4_with_pdb.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(not (PE.is_file() and PDB.is_file() and BETA_PDB.is_file()),
                    reason="FO4 PDB folder is not present")
def test_only_the_matching_pdb_is_accepted():
    mod = _module()
    identity = mod.verify_pdb_matches_pe(PE, PDB)
    assert identity["guid"] == "E0BB0FDB-47DA-48F1-886C-CC6967D72468"
    with pytest.raises(RuntimeError, match="does not belong"):
        mod.verify_pdb_matches_pe(PE, BETA_PDB)
