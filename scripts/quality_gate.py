#!/usr/bin/env python3
"""Repository correctness gate: compile, static safety invariants, then tests."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _python_files():
    yield ROOT / "run.py"
    yield from sorted((ROOT / "scripts").rglob("*.py"))


def _call_name(node):
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def static_checks():
    errors = []
    warnings = []
    for path in _python_files():
        relative = path.relative_to(ROOT).as_posix()
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(path))
            compile(source, str(path), "exec")
        except Exception as exc:
            errors.append(f"{relative}: compile/parse failure: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) == "endTransaction":
                if (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                        and node.args[1].value is True):
                    errors.append(
                        f"{relative}:{node.lineno}: unconditional transaction commit")
            if isinstance(node, ast.Call):
                # Comparing a symbol's source with USER_DEFINED is required to
                # preserve analyst work.  Only claiming USER_DEFINED as a
                # direct mutation-call argument is forbidden.
                claims_user_source = any(
                    isinstance(arg, ast.Attribute) and
                    arg.attr == "USER_DEFINED" and
                    isinstance(arg.value, ast.Name) and
                    arg.value.id == "SourceType"
                    for arg in [*node.args,
                                *(kw.value for kw in node.keywords)])
                if claims_user_source:
                    errors.append(
                        f"{relative}:{node.lineno}: heuristic/import code may "
                        "not claim SourceType.USER_DEFINED")
            if (isinstance(node, ast.Call) and _call_name(node) == "generate_script"
                    and relative != "scripts/core/ghidra_import_gen.py"):
                keywords = {keyword.arg for keyword in node.keywords}
                if not ({"target_manifest", "target_binary_path"} & keywords):
                    errors.append(
                        f"{relative}:{node.lineno}: generated importer is not "
                        "bound to an exact target manifest")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.lower().replace("\\", "/")
                critical = ("/ghidraprojects/scripts/" in value or
                            value.startswith("d:/fnv project") or
                            value.startswith("c:/development/tools/bethesdaghidrascripts"))
                if critical and not relative.startswith("scripts/quality_gate.py"):
                    warnings.append(
                        f"{relative}:{getattr(node, 'lineno', '?')}: developer-local path")
    return errors, warnings


def main():
    errors, warnings = static_checks()
    print("Static safety gate: {} error(s), {} warning(s)".format(
        len(errors), len(warnings)))
    for item in errors:
        print("ERROR: " + item)
    for item in warnings:
        print("WARN:  " + item)
    if errors:
        return 1
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
               "scripts"]
    return subprocess.run(command, cwd=str(ROOT), check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
