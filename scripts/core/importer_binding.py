"""Static identity validation for generated CommonLib import scripts.

Generated importers contain executable Python, so launchers must not import or
execute one merely to discover its target.  This module extracts the literal
``TARGET_MANIFESTS`` assignment through ``ast`` and rejects legacy/unbound or
dynamic scripts before PyGhidra is allowed to run them.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List

from binary_identity import manifest_matches, verify_ghidra_program
from version_catalog import target_for_importer


class ImporterBindingError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

_WHY_BOUND = (
    "An import script stamps struct layouts, globals and thousands of function\n"
    "names onto hard-coded addresses that are valid for exactly one build of the\n"
    "game. TARGET_MANIFESTS is the fingerprint (SHA-256, sections, code anchors)\n"
    "of the .exe it was generated from, and it is what lets the applier refuse to\n"
    "run against a different build. Without it there is nothing to check, and a\n"
    "mismatched script would quietly mislabel the whole binary."
)


def _regenerate_hint(path: Path) -> str:
    """How to produce a properly bound importer, naming the exact staging dir."""
    target = target_for_importer(path.name)
    if target:
        label, subdir = target
        stage = "exes/{}/  ({})".format(subdir, label)
        pick = 'pick "{}"'.format(label)
    else:
        stage = "exes/<game>/<version>/"
        pick = "pick your version"
    return (
        "To fix, regenerate the importer from your own copy of the game:\n"
        "  1. Copy the exact .exe into {}\n"
        "  2. Run run.bat (or `python run.py`). If the startup checks show Clang\n"
        "     as not installed, choose menu option 1 (Install prerequisites) --\n"
        "     script generation parses the CommonLib headers with it.\n"
        "  3. Choose menu option 4 (Generate import scripts), {}, then\n"
        "     re-run this step.\n"
        "\n"
        "If that .exe no longer exists -- a Steamless-unpacked binary is often a\n"
        "temporary file, and re-unpacking does not reproduce it byte-for-byte --\n"
        "run.py option 9 can recover it from the Ghidra project itself: Ghidra\n"
        "stores the imported bytes, and the recovered file is checked against the\n"
        "SHA-256 the program recorded when it was imported.".format(stage, pick)
    )


def _decode_assignment(value: ast.AST) -> Any:
    try:
        return ast.literal_eval(value)
    except (ValueError, TypeError):
        pass
    if (isinstance(value, ast.Call) and len(value.args) == 1 and
            not value.keywords and isinstance(value.func, ast.Attribute) and
            value.func.attr == "loads" and
            isinstance(value.args[0], ast.Constant) and
            isinstance(value.args[0].value, str)):
        try:
            return json.loads(value.args[0].value)
        except json.JSONDecodeError as exc:
            raise ImporterBindingError(
                "TARGET_MANIFESTS contains invalid JSON") from exc
    raise ImporterBindingError(
        "TARGET_MANIFESTS is not a static literal/JSON assignment")


def _validate_manifest(manifest: Any) -> Dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ImporterBindingError("target manifest is not an object")
    sha = str(manifest.get("sha256") or "")
    if not _SHA256.fullmatch(sha):
        raise ImporterBindingError("target manifest has no exact SHA-256")
    if int(manifest.get("file_size") or 0) <= 0:
        raise ImporterBindingError("target manifest has no file size")
    if int(manifest.get("pointer_size") or 0) not in (4, 8):
        raise ImporterBindingError("target manifest has invalid pointer size")
    if int(manifest.get("image_base") or 0) <= 0 \
            or int(manifest.get("image_size") or 0) <= 0:
        raise ImporterBindingError("target manifest has no image layout")
    if not isinstance(manifest.get("sections"), list) or not manifest["sections"]:
        raise ImporterBindingError("target manifest has no sections")
    if not isinstance(manifest.get("anchors"), list) or not manifest["anchors"]:
        raise ImporterBindingError("target manifest has no memory anchors")
    if (int(manifest["pointer_size"]) == 8 and
            not isinstance(manifest.get("function_starts"), list)):
        raise ImporterBindingError("x64 target manifest has no function-start index")
    return manifest


def extract_target_manifests(script_path: str | Path) -> List[Dict[str, Any]]:
    path = Path(script_path)
    try:
        source = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ImporterBindingError(
            "cannot parse importer {}: {}".format(path, exc)) from exc
    assignments = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and
               target.id == "TARGET_MANIFESTS" for target in targets):
            assignments.append(node.value)
    if not assignments:
        raise ImporterBindingError(
            "{}\ndoes not record which game build it was generated for: it has no\n"
            "TARGET_MANIFESTS. It predates identity binding, or was generated\n"
            "without the target .exe available.\n\n{}\n\n{}".format(
                path, _WHY_BOUND, _regenerate_hint(path)))
    if len(assignments) > 1:
        raise ImporterBindingError(
            "{}\nassigns TARGET_MANIFESTS {} times, so which build it targets is\n"
            "ambiguous. A generated importer declares it exactly once; this file\n"
            "has been hand-edited or concatenated.\n\n{}\n\n{}".format(
                path, len(assignments), _WHY_BOUND, _regenerate_hint(path)))
    decoded = _decode_assignment(assignments[0])
    if not isinstance(decoded, list) or not decoded:
        raise ImporterBindingError("TARGET_MANIFESTS must be a nonempty list")
    manifests = [_validate_manifest(item) for item in decoded]
    hashes = [item["sha256"].lower() for item in manifests]
    if len(hashes) != len(set(hashes)):
        raise ImporterBindingError("TARGET_MANIFESTS contains duplicate identities")
    return manifests


def accepts_manifest(script_path: str | Path,
                     actual: Dict[str, Any]) -> Dict[str, Any]:
    reasons = []
    for expected in extract_target_manifests(script_path):
        matches, why = manifest_matches(expected, actual)
        if matches:
            return expected
        reasons.extend(why)
    raise ImporterBindingError(
        "importer target mismatch: " + "; ".join(reasons[:8]))


def verify_importer_for_program(script_path: str | Path, program):
    manifests = extract_target_manifests(script_path)
    return verify_ghidra_program(program, manifests)
