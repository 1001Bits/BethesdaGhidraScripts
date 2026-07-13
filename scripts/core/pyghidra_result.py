"""Fail-closed handling for :func:`pyghidra.ghidra_script` results.

PyGhidra returns the script's captured stdout/stderr.  A Python exception in
the executed script can therefore arrive as stderr instead of being raised in
the launcher process.  Launchers must check stderr before they save a mutated
program or report success.
"""

from __future__ import annotations


class PyGhidraScriptError(RuntimeError):
    """The launched Ghidra script reported an error on stderr."""


def require_script_success(stderr, label: str = "Ghidra script") -> None:
    rendered = "" if stderr is None else str(stderr)
    if rendered.strip():
        # Preserve enough context to diagnose the script, while keeping an
        # accidentally enormous Java traceback from overwhelming summaries.
        detail = rendered.strip()
        if len(detail) > 12000:
            detail = "..." + detail[-12000:]
        raise PyGhidraScriptError("{} failed:\n{}".format(label, detail))


def end_outer_transaction(program, transaction_id, commit: bool,
                          label: str = "Ghidra script") -> None:
    """End a launcher-owned parent transaction and prove its final commit."""
    committed = bool(program.endTransaction(transaction_id, commit))
    if commit and not committed:
        raise PyGhidraScriptError(
            "{} did not commit its outer transaction; nested work was "
            "rolled back or a transaction was left open".format(label))
