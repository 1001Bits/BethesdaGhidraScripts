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


class PyGhidraScriptNoOp(PyGhidraScriptError):
    """The launched driver returned without proving that it executed."""


DRIVER_COMPLETE_PREFIX = "BGS-DRIVER-COMPLETE "


def script_program(script_globals):
    """Return ``currentProgram`` when running as a PyGhidra script, else None.

    PyGhidra executes a script with a ``PyGhidraScript`` mapping as its
    globals.  That mapping resolves ``currentProgram`` on *lookup* (through
    ``__missing__``) but does not report it for ``in``, so a
    ``'currentProgram' in globals()`` guard is always false and silently skips
    the driver.  A plain ``import`` (unit tests) has an ordinary dict and
    raises ``KeyError`` here instead.
    """
    try:
        return script_globals["currentProgram"]
    except KeyError:
        return None


def completion_line(driver: str) -> str:
    """Sentinel a driver prints, from its own globals, as its final act."""
    return DRIVER_COMPLETE_PREFIX + driver


def require_driver_completion(stdout, driver: str) -> None:
    """Fail closed unless the driver's completion sentinel is in ``stdout``.

    A script that returns without raising is not evidence that it ran: the
    entry-point guard may have been false, or ``run()`` may have been skipped.
    """
    wanted = completion_line(driver)
    rendered = "" if stdout is None else str(stdout)
    if not any(line.strip() == wanted for line in rendered.splitlines()):
        raise PyGhidraScriptNoOp(
            "{} returned without its completion sentinel ({!r}); it did not "
            "execute, so nothing it should have produced can be trusted".format(
                driver, wanted))


def end_outer_transaction(program, transaction_id, commit: bool,
                          label: str = "Ghidra script") -> None:
    """End a launcher-owned parent transaction and prove its final commit."""
    committed = bool(program.endTransaction(transaction_id, commit))
    if commit and not committed:
        raise PyGhidraScriptError(
            "{} did not commit its outer transaction; nested work was "
            "rolled back or a transaction was left open".format(label))
