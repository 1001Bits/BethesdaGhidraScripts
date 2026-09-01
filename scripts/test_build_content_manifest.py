import hashlib
from pathlib import Path

import pytest

from build_content_manifest import write_manifest


def test_content_manifest_is_complete_sorted_and_repeatable(tmp_path):
    root = tmp_path / "stage"
    (root / "nested").mkdir(parents=True)
    (root / "z.txt").write_bytes(b"z")
    (root / "nested" / "A.txt").write_bytes(b"alpha")
    output = root / "BUNDLE_CONTENTS.sha256"

    assert write_manifest(root, output) == 2
    first = output.read_text(encoding="ascii")
    assert first.splitlines() == [
        "{}  nested/A.txt".format(hashlib.sha256(b"alpha").hexdigest()),
        "{}  z.txt".format(hashlib.sha256(b"z").hexdigest()),
    ]
    assert write_manifest(root, output) == 2
    assert output.read_text(encoding="ascii") == first


def test_content_manifest_rejects_output_outside_stage(tmp_path):
    root = tmp_path / "stage"
    root.mkdir()
    with pytest.raises(ValueError, match="inside"):
        write_manifest(root, tmp_path / "outside.sha256")
