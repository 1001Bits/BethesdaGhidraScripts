#!/usr/bin/env python3
"""Repository correctness gate: compile, static safety invariants, then tests."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


# Method names that look plausible but do not exist on the Ghidra 12.1.2 class
# they are called on.  PyGhidra only fails at call time, so a driver that is
# rarely executed can carry one for months.  name -> the real spelling.
WRONG_GHIDRA_METHODS = {
    "isWritable": "MemoryBlock.isWrite()",
    "isReadable": "MemoryBlock.isRead()",
    "isExecutable": "MemoryBlock.isExecute()",
}


# ``DomainFile.getDomainObject(consumer, okToUpgrade, okToRecover, monitor)``
# with okToRecover=False makes Ghidra DELETE the crash-recovery snapshot of
# unsaved GUI work.  ``ghidra_project.open_program`` is the one place allowed
# to call it (it refuses while a snapshot exists and opens readers read-only).
OPEN_PROGRAM_HOME = "scripts/core/ghidra_project.py"

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


def _scope_nodes(scope):
    """Every node of one module/function body, not of its nested defs."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def ignored_end_transaction_before_save(tree):
    """Line numbers of ``x.endTransaction(...)`` statements whose result is
    discarded while the same body calls ``.save(...)`` after them.

    ``endTransaction`` returns False when the transaction (or a nested one)
    was rolled back; saving without looking reports -- and for an outer
    transaction persists -- a pass that never committed.  An explicit
    ``endTransaction(tx, False)`` rollback has nothing to check.
    """
    hits = []
    scopes = [tree] + [node for node in ast.walk(tree)
                       if isinstance(node, (ast.FunctionDef,
                                            ast.AsyncFunctionDef))]
    for scope in scopes:
        ignored = []
        saves = []
        for node in _scope_nodes(scope):
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and _call_name(node.value) == "endTransaction"):
                args = node.value.args
                rollback = (len(args) >= 2 and isinstance(args[1], ast.Constant)
                            and args[1].value is False)
                if not rollback:
                    ignored.append(node.lineno)
            elif (isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "save"):
                saves.append(node.lineno)
        hits.extend(line for line in ignored
                    if any(save > line for save in saves))
    return sorted(hits)


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
        for line in ignored_end_transaction_before_save(tree):
            errors.append(
                f"{relative}:{line}: endTransaction() result ignored before "
                "save(); check it (False = rolled back) before saving")
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in WRONG_GHIDRA_METHODS):
                errors.append(
                    f"{relative}:{node.lineno}: {node.func.attr}() is not a "
                    f"Ghidra method; use {WRONG_GHIDRA_METHODS[node.func.attr]}")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "getDomainObject"
                    and relative != OPEN_PROGRAM_HOME):
                errors.append(
                    f"{relative}:{node.lineno}: raw getDomainObject() can delete "
                    "crash-recovery data; use ghidra_project.open_program()")
            if (isinstance(node, ast.Compare) and len(node.ops) == 1
                    and isinstance(node.ops[0], (ast.In, ast.NotIn))
                    and isinstance(node.comparators[0], ast.Call)
                    and isinstance(node.comparators[0].func, ast.Name)
                    and node.comparators[0].func.id == "globals"):
                errors.append(
                    f"{relative}:{node.lineno}: `in globals()` is always False "
                    "under PyGhidra; use pyghidra_result.script_program()")
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
