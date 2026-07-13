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


class ImporterBindingError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


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
    if len(assignments) != 1:
        raise ImporterBindingError(
            "{} must define TARGET_MANIFESTS exactly once (legacy/unbound "
            "importers are unsafe). This importer predates identity binding -- "
            "regenerate it: run `python run.py`, choose Generate scripts for "
            "this game, then retry (the exact target .exe must be staged under "
            "exes/<game>/<version>/).".format(path))
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
