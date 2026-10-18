"""Open a user's Ghidra project, and say something useful when it is locked.

Ghidra allows one writer per project.  When something else holds it, pyghidra
raises a Java ``LockException`` that surfaces as a two-level Python traceback
ending in ``Unable to lock project!`` -- which tells the user nothing about what
to do, and looks like a crash in the pipeline rather than a door that is simply
closed right now.

The lock is often held by nothing the user can see: a Ghidra JVM keeps the
project for a moment *after* its script has finished, so a step that follows
immediately can lose a race with the step before it.  Retrying is then the whole
fix, which is worth saying out loud -- a stale-lock message that only ever says
"close Ghidra" sends people hunting for a window that is not open.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

# Exit code the pipeline's entry points use for "the project was locked".  It is
# distinct from a generic failure so a caller can offer a retry instead of
# reporting the step as broken.
PROJECT_LOCKED_EXIT = 2

_LOCK_HINTS = (
    'lockexception',
    'unable to lock',
    'already locked',
    'is in use',
    'lock is held',
)


def is_lock_error(exc: BaseException) -> bool:
    """True when *exc* is Ghidra refusing to open a project that is held."""
    seen = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = '{}: {}'.format(type(current).__name__, current).lower()
        if any(hint in text for hint in _LOCK_HINTS):
            return True
        current = current.__cause__ or current.__context__
    return False


def lock_files(project_dir, project_name) -> List[Path]:
    """Any Ghidra lock files present for the project (may be empty)."""
    base = Path(project_dir) / str(project_name)
    return [path for path in (base.with_suffix('.lock'),
                              Path(str(base) + '.lock~'))
            if path.exists()]


def lock_message(project_dir, project_name) -> str:
    """A message that names the holder if we can find it, and the fix either way."""
    held = lock_files(project_dir, project_name)
    lines = [
        "Ghidra project '{}' in {} is locked, so it cannot be opened.".format(
            project_name, project_dir),
        '',
        'Ghidra allows one writer at a time.  Something else holds this project:',
        '',
        '  - a Ghidra window (CodeBrowser or the Project Manager), or',
        '  - a previous step of this pipeline that has not fully exited -- a',
        '    Ghidra JVM keeps the lock for a few seconds after its script is',
        '    done, so back-to-back steps can lose a race, or',
        '  - a crashed session that left the lock behind.',
        '',
    ]
    if held:
        lines.append('Lock file(s) present right now:')
        lines.extend('  {}'.format(path) for path in held)
        lines.append('')
        lines.append('Close any open Ghidra window, then retry.  If no Ghidra is')
        lines.append('running, the session that made these files crashed.  Open the')
        lines.append('project in the Ghidra GUI FIRST and accept or discard any')
        lines.append('"recover unsaved changes?" offer -- a script that opens the')
        lines.append('program discards that recovery data -- then delete the lock')
        lines.append('files and retry.')
    else:
        lines.append('No lock file is present, so the holder is a JVM that has not')
        lines.append('exited yet.  Nothing is wrong and nothing was written --')
        lines.append('wait a few seconds and retry.')
    return '\n'.join(lines)


def open_user_project(project_dir, project_name):
    """``pyghidra.open_project`` with a human answer when the project is locked.

    Raises ``SystemExit(PROJECT_LOCKED_EXIT)`` after printing the explanation, so
    a locked project ends the step cleanly instead of as a Java stack trace.
    """
    import pyghidra

    try:
        return pyghidra.open_project(project_dir, project_name, create=False)
    except Exception as exc:  # noqa: BLE001  (pyghidra raises a Java exception)
        if not is_lock_error(exc):
            raise
        print()
        print('ERROR: ' + lock_message(project_dir, project_name))
        print()
        raise SystemExit(PROJECT_LOCKED_EXIT) from exc


class UnsavedRecoveryError(RuntimeError):
    """The program has crash-recovery data that opening it would destroy."""


def open_program(domain_file, consumer, monitor, write):
    """Open a program without ever destroying the user's crash-recovery data.

    ``DomainFile.getDomainObject(consumer, okToUpgrade, okToRecover, monitor)``
    with ``okToRecover=False`` silently DELETES any recovery snapshot Ghidra
    kept for unsaved GUI work (``DBHandle``: "if false, any existing recovery
    data will be deleted").  So refuse while a snapshot exists, and open
    dry-run / read-only consumers through ``getReadOnlyDomainObject``, which
    touches neither recovery data nor the database version.
    """
    if domain_file.canRecover():
        raise UnsavedRecoveryError(
            "{} has unsaved crash-recovery data from a Ghidra session that did "
            "not exit cleanly.  Open it in the Ghidra GUI and accept or discard "
            "the recovery, save, close Ghidra, then retry.  Nothing was "
            "touched.".format(domain_file.getPathname()))
    if write:
        return domain_file.getDomainObject(consumer, True, False, monitor)
    from ghidra.framework.model import DomainFile
    return domain_file.getReadOnlyDomainObject(
        consumer, DomainFile.DEFAULT_VERSION, monitor)


def find_program(root, program_path):
    """The one domain file at exactly ``program_path``; ambiguity is an error."""
    wanted = "/" + str(program_path).strip("/")
    hits = []

    def walk(folder, prefix=""):
        for domain_file in folder.getFiles():
            if prefix + "/" + str(domain_file.getName()) == wanted:
                hits.append(domain_file)
        for child in folder.getFolders():
            walk(child, prefix + "/" + str(child.getName()))

    walk(root)
    if len(hits) > 1:
        raise RuntimeError("ambiguous project path {}".format(wanted))
    return hits[0] if hits else None


class AmbiguousProgramError(RuntimeError):
    """More than one project file matches a by-name program lookup."""


def find_program_by_name(root, program_name, program_path=None):
    """The one program to import into; never "whichever came first".

    With ``program_path`` this is :func:`find_program` (exact path).  Without
    it, files named ``program_name`` -- or Steamless-style variants such as
    ``Game.exe.unpacked.exe`` -- are collected across the WHOLE tree, and more
    than one hit raises :class:`AmbiguousProgramError` listing them: a project
    that holds several builds must be addressed by exact path.
    """
    if program_path is not None:
        return find_program(root, program_path)
    stem = str(program_name).rsplit('.', 1)[0]
    hits = []

    def walk(folder, prefix=""):
        for domain_file in folder.getFiles():
            name = str(domain_file.getName())
            if name == program_name or (
                    name.startswith(stem) and name.lower().endswith('.exe')):
                hits.append((prefix + "/" + name, domain_file))
        for child in folder.getFolders():
            walk(child, prefix + "/" + str(child.getName()))

    walk(root)
    if len(hits) > 1:
        raise AmbiguousProgramError(
            "{} programs match {!r}; pass --program-path with the exact one:"
            "\n  {}".format(len(hits), program_name,
                            "\n  ".join(sorted(path for path, _ in hits))))
    return hits[0][1] if hits else None


def ensure_ghidra_env(ghidra_dir=None) -> None:
    """Point GHIDRA_INSTALL_DIR at the repo's pinned Ghidra unless already set."""
    if ghidra_dir is None:
        ghidra_dir = Path(__file__).resolve().parents[2] / 'tools' / 'ghidra'
    os.environ.setdefault('GHIDRA_INSTALL_DIR', str(ghidra_dir))
