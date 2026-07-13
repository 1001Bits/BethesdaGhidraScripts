import hashlib
import json
from pathlib import Path

import pdb_publics_f4_221 as corpus


def test_latest_community_pdb_corpus_is_exact_and_ambiguity_bound():
    artifact = Path(corpus.PUBLICS_TXT)
    identity = json.loads(Path(corpus.IDENTITY_JSON).read_text(encoding="utf-8"))
    assert identity["schema_version"] == 2
    assert identity["source"]["sha256"] == (
        "e64a17d4a3adb3cbb51848489f0674f320be302ee2e489cdf46810395a4cfb95")
    assert identity["source"]["size"] == 4_186_112
    assert identity["pdb"]["guid"] == "22776620-B648-4C12-98F7-D51833DAFFC9"
    assert identity["pdb"]["age"] == 1
    assert identity["pdb"]["type_record_count"] == 0
    assert identity["supersedes"] == {
        "sha256": "a0b6ae0ac8818bf3984be54645c67db063e0aac431991f93212b603b1998a8db",
        "size": 4_149_248, "publics": 37_714,
        "added_publics": 315, "removed_publics": 0}
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == \
        identity["artifact_sha256"]

    rows = list(corpus._iter_lines(str(artifact)))
    selected, quarantine = corpus._unambiguous_rows(rows)
    assert len(rows) == identity["counts"]["publics"] == 38_029
    assert len(selected) == identity["counts"]["unambiguous_records"] == 37_882
    assert quarantine == {
        "same_rva_alias_groups": 15,
        "same_name_multi_rva_groups": 60,
        "quarantined_records": 147,
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
