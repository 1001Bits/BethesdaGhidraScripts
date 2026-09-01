import hashlib
import json
from pathlib import Path

import pdb_publics_f4_221 as corpus
from update_pdb_publics import _read_bound_public_corpus


def test_latest_community_pdb_corpus_is_exact_and_ambiguity_bound():
    artifact = Path(corpus.PUBLICS_TXT)
    identity = json.loads(Path(corpus.IDENTITY_JSON).read_text(encoding="utf-8"))
    assert identity["schema_version"] == 2
    assert identity["source"]["sha256"] == (
        "188876580daa33ae24b21383d9aac939ccc49a265cabf9ee3cf29b3de9eb5e2f")
    assert identity["source"]["size"] == 4_517_888
    assert identity["source"]["author"] == "unknown"
    assert identity["source"]["license"] == "unknown"
    assert identity["source"]["origin"] == (
        "https://cdn.discordapp.com/attachments/541414634117398536/"
        "1533321776493498518/Fallout4_1_11_221_for_debug.pdb")
    assert identity["source"]["retrieved_utc"] == "2026-08-05T04:04:28Z"
    assert "prior strict-subset corpus was attributed to Perchik71" in \
        identity["source"]["attribution_note"]
    assert "raw PDB not bundled" in identity["source"]["redistribution"]
    # The GUID/age must stay pinned to Fallout4.exe 1.11.221's own CodeView
    # record -- a community rebuild that changed them would name a different
    # binary and must never be accepted silently.
    assert identity["pdb"]["guid"] == "22776620-B648-4C12-98F7-D51833DAFFC9"
    assert identity["pdb"]["age"] == 1
    assert identity["pdb"]["type_record_count"] == 0
    assert identity["pdb"]["signature"] == 1_785_642_431
    assert identity["supersedes"] == {
        "kind": "public-symbol-corpus",
        "artifact": "f4_221_pdb_publics.txt",
        "artifact_sha256": (
            "ee6a5a7b99f1f97ffd95997635cc81a150086eaf70d548b6630c27707b3fd77b"),
        "source_pdb_sha256": (
            "461f07a4b04100c34ee12e261d1616a393d33867d8468b9f38404222d7c37858"),
        "publics": 40_227,
        "added_publics": 1_418,
        "removed_publics": 0,
    }
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == \
        identity["artifact_sha256"]
    # The unknown-license source PDB stays external; only the deterministic,
    # exact-target-bound public corpus is checked in.
    repo_dir = Path(corpus.SCRIPT_DIR).parents[1]
    assert not (repo_dir / "Fallout4_1_11_221_for_debug.pdb").exists()

    rows = list(corpus._iter_lines(str(artifact)))
    selected, quarantine = corpus._unambiguous_rows(rows)
    assert len(rows) == identity["counts"]["publics"] == 41_645
    assert len(selected) == identity["counts"]["unambiguous_records"] == 41_425
    assert quarantine == {
        "same_rva_alias_groups": 30,
        "same_name_multi_rva_groups": 88,
        "quarantined_records": 220,
    }


def test_public_selection_is_order_independent_and_reciprocal_unique():
    rows = [(0x1000, "A"), (0x1000, "Alias"),
            (0x2000, "Repeated"), (0x3000, "Repeated"),
            (0x4000, "Safe")]
    forward, stats = corpus._unambiguous_rows(rows)
    reverse, reverse_stats = corpus._unambiguous_rows(list(reversed(rows)))
    assert forward == reverse == [(0x4000, "Safe")]
    assert stats == reverse_stats == {
        "same_rva_alias_groups": 1,
        "same_name_multi_rva_groups": 1,
        "quarantined_records": 4,
    }


def test_predecessor_corpus_loader_validates_bound_artifact():
    pairs, identity = _read_bound_public_corpus(Path(corpus.PUBLICS_TXT))
    assert len(pairs) == identity["counts"]["publics"] == 41_645
    assert identity["artifact_sha256"] == (
        "554caab5ff8a92a49780c6de64feaceb24b29b34ebde49fb120afccc7dcb0710")
