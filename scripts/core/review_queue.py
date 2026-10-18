"""Mined evidence vs. reviewer decisions: two files, two bindings.

A miner (``globals_harvest`` / ``ctor_mine``) writes an EVIDENCE csv whose
identity sidecar binds the exact file content to the exact executable.  A
reviewer must be able to fill in a decision column without breaking that
binding, so decisions live in a separate DECISIONS csv that is bound to the
same target but not to its own content.  Appliers read the rows from the
content-verified evidence and take ONLY the decision column from the
decisions file, so nothing a reviewer (or anything else) edits there can move
an address or change a mined type.

Both launchers (``discover_combined`` and ``apply_enrichment_to_user_project``)
export :func:`queue_environment` before any driver and call
:func:`merge_review_queue` after a miner ran, so they can never again disagree
about which kind/path the applier expects.
"""

from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path

from evidence_identity import (EvidenceIdentityError, bind_for_hash,
                               read_binding, validate_evidence)


class QueueSpec:
    def __init__(self, label, evidence_kind, decisions_kind, key_fields,
                 decision_field, coordinate, evidence_env, decisions_env,
                 evidence_default, decisions_default):
        self.label = label
        self.evidence_env = evidence_env
        self.decisions_env = decisions_env
        self.evidence_default = evidence_default
        self.decisions_default = decisions_default
        self.evidence_kind = evidence_kind
        self.decisions_kind = decisions_kind
        self.key_fields = tuple(key_fields)
        self.decision_field = decision_field
        self.coordinate = coordinate

    def key(self, row):
        parts = tuple((row.get(name) or '').strip().lower()
                      for name in self.key_fields)
        return parts if all(parts[:1]) else None


GLOBALS = QueueSpec('globals', 'globals_evidence', 'globals_decisions',
                    ('global_addr',), 'decision_type', 'VA',
                    'BGS_GLOBALS_CSV', 'BGS_GLOBALS_APPLY_CSV',
                    'globals_evidence_%s.csv', 'globals_decisions_%s.csv')
# A ctor decision approves one concrete proposal, so the proposed type/name are
# part of the key: a re-mined row that proposes something else starts unreviewed.
CTORS = QueueSpec('ctor', 'ctor_fields', 'ctor_decisions',
                  ('class', 'offset', 'type', 'name'), 'decision', 'NONE',
                  'BGS_CTOR_CSV', 'BGS_CTOR_DECISIONS_CSV',
                  'ctor_fields_%s.csv', 'ctor_decisions_%s.csv')

# Which miner refreshes which queue (used by both launchers).
MINER_SPECS = {'globals_harvest': GLOBALS, 'ctor_mine': CTORS}


class ReviewQueueError(RuntimeError):
    """The evidence/decisions pair cannot be trusted for this program."""


# ------------------------------------------------------------ miner output
# A miner run that produced nothing because its decompiler never worked must
# not replace the last good evidence (or print its completion sentinel).

class MinerHealthError(RuntimeError):
    """The miner's decompiler did not work; no evidence was written."""


# A pass fails when every decompile failed, or more than this share of them
# once there are enough to judge (a few timeouts on huge functions are normal).
DECOMPILE_FAILURE_RATIO = 0.5
DECOMPILE_MIN_SAMPLE = 20


def open_decompiler(decompiler, program, label):
    """``decompiler.openProgram(program)``, raising when it did not start.

    Ghidra returns False (it does not throw) when the decompiler process
    cannot be initialized; every later decompile then fails silently.
    """
    if not decompiler.openProgram(program):
        try:
            message = decompiler.getLastMessage()
        except Exception:  # noqa: BLE001
            message = ''
        raise MinerHealthError(
            '{}: the decompiler did not start ({}); no evidence was '
            'written'.format(label, message or 'no message'))


def require_decompile_health(label, attempted, failed, samples=()):
    """Raise :class:`MinerHealthError` when the failure rate is total or
    very high, so the caller writes no CSV and prints no sentinel."""
    if attempted <= 0:
        return
    if failed >= attempted or (attempted >= DECOMPILE_MIN_SAMPLE and
                               failed > attempted * DECOMPILE_FAILURE_RATIO):
        detail = ''.join('\n    ' + str(line) for line in list(samples)[:5])
        raise MinerHealthError(
            '{}: {} of {} decompiles failed; refusing to replace the previous '
            'evidence{}'.format(label, failed, attempted, detail))


def write_csv_atomically(path, header, rows):
    """Write ``header`` + ``rows`` to a temp file beside ``path`` and move it
    into place in one step: a run that dies half-way leaves the previous
    file untouched."""
    path = os.path.abspath(str(path))
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.',
                                suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def program_tag(program):
    """File-name tag for a program: its PROJECT path, folder included.

    ``program`` is a Ghidra Program (its domain file's pathname is used, the
    bare name only when it has none) or a project path / name string, so
    ``/Skyrim/SkyrimSE_1_5_97.exe`` -> ``Skyrim_SkyrimSE_1_5_97_exe`` whichever
    launcher -- or the in-Ghidra driver itself -- asks.
    """
    path = program
    if hasattr(program, 'getName'):
        try:
            path = program.getDomainFile().getPathname() or program.getName()
        except Exception:  # noqa: BLE001  (detached Program / test fake)
            path = program.getName()
    return (str(path).strip('/').replace('/', '_').replace(' ', '_')
            .replace('.', '_'))


def queue_paths(spec, program, environ=None):
    """``(evidence_csv, decisions_csv)`` -- the ONE place both the miners, the
    appliers and the launchers take these paths from.  Env overrides win.

    ``program`` is a Program or a project path; see :func:`program_tag`.
    """
    environ = os.environ if environ is None else environ
    refs = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'refs')
    tag = program_tag(program)
    evidence = environ.get(spec.evidence_env) or os.path.join(
        refs, spec.evidence_default % tag)
    decisions = environ.get(spec.decisions_env) or os.path.join(
        refs, spec.decisions_default % tag)
    return evidence, decisions


def queue_environment(program, environ=None):
    """``{env var: path}`` for every miner queue of ``program``.

    Launchers export this before running ANY driver, so a miner, the merge
    that follows it and a later applier read and write the same two files.
    """
    result = {}
    for spec in (GLOBALS, CTORS):
        evidence, decisions = queue_paths(spec, program, environ)
        result[spec.evidence_env] = evidence
        result[spec.decisions_env] = decisions
    return result


def _read_decisions(decision_path, spec):
    decisions = {}
    with Path(decision_path).open(newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            key = spec.key(row)
            value = (row.get(spec.decision_field) or '').strip()
            if key and value:
                decisions[key] = value
    return decisions


def _require_coordinate(binding, spec, what):
    if binding.get('address_coordinate') != spec.coordinate:
        raise EvidenceIdentityError('{} {} must use {} coordinates'.format(
            spec.label, what, spec.coordinate))


def merge_review_queue(evidence_path, decision_path, spec=GLOBALS):
    """Refresh evidence while preserving every explicit reviewer decision."""
    evidence_path = Path(evidence_path)
    decision_path = Path(decision_path)
    if not evidence_path.is_file():
        return
    try:
        evidence_binding = read_binding(
            evidence_path, spec.evidence_kind, require_content=True)
        _require_coordinate(evidence_binding, spec, 'evidence')
    except EvidenceIdentityError as exc:
        raise RuntimeError('refusing unbound {} evidence: {}'.format(
            spec.label, exc))
    decisions = {}
    if decision_path.is_file():
        try:
            old_binding = read_binding(decision_path, spec.decisions_kind)
            _require_coordinate(old_binding, spec, 'decisions')
            if old_binding['target_sha256'] != evidence_binding['target_sha256']:
                raise EvidenceIdentityError('decision target differs from evidence')
            for field in ('address_coordinate', 'image_base', 'pointer_size'):
                if old_binding.get(field) != evidence_binding.get(field):
                    raise EvidenceIdentityError(
                        'decision {} differs from evidence'.format(field))
            decisions = _read_decisions(decision_path, spec)
        except EvidenceIdentityError as exc:
            print('  Not preserving stale/unbound {} decisions: {}'.format(
                spec.label, exc))
    with evidence_path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    if spec.decision_field not in fieldnames:
        fieldnames.append(spec.decision_field)
    for row in rows:
        row.pop(None, None)
        row[spec.decision_field] = decisions.get(spec.key(row), '')
    decision_path.parent.mkdir(parents=True, exist_ok=True)
    temp = decision_path.with_suffix(decision_path.suffix + '.tmp')
    with temp.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temp, decision_path)
    bind_for_hash(decision_path, spec.decisions_kind,
                  evidence_binding['target_sha256'],
                  evidence_binding.get('program_name', ''),
                  image_base=evidence_binding.get('image_base'),
                  pointer_size=evidence_binding.get('pointer_size'),
                  address_coordinate=evidence_binding.get(
                      'address_coordinate', 'NONE'))


def load_reviewed_rows(evidence_path, decision_path, program, spec):
    """Rows for an applier: content-verified evidence + reviewer decisions.

    Raises :class:`ReviewQueueError` when the evidence is missing, stale,
    edited or bound to another executable, or when the decisions file is
    missing or not bound to this program.  Both launchers write the decisions
    file right after the miner, so a missing one means the applier is looking
    somewhere else than the reviewer edited (or the miner ran outside a
    launcher) -- never "no reviewer said skip, approve everything".
    """
    if not evidence_path or not os.path.isfile(evidence_path):
        raise ReviewQueueError('no {} evidence CSV at {} (run the miner '
                               'first)'.format(spec.label, evidence_path))
    try:
        binding = validate_evidence(evidence_path, program, spec.evidence_kind,
                                    require_content=True)
        _require_coordinate(binding, spec, 'evidence')
    except EvidenceIdentityError as exc:
        raise ReviewQueueError('stale/unbound {} evidence {}: {}'.format(
            spec.label, evidence_path, exc)) from exc
    if not decision_path or not os.path.isfile(decision_path):
        raise ReviewQueueError(
            'no {} decisions CSV at {} next to the evidence {}; re-run the '
            'miner through discover_combined.py or '
            'apply_enrichment_to_user_project.py, which write it'.format(
                spec.label, decision_path, evidence_path))
    try:
        # Identity-bound only: the reviewer edits this file by design.
        decision_binding = validate_evidence(
            decision_path, program, spec.decisions_kind,
            require_content=False)
        _require_coordinate(decision_binding, spec, 'decisions')
        decisions = _read_decisions(decision_path, spec)
    except EvidenceIdentityError as exc:
        raise ReviewQueueError('stale/unbound {} decisions {}: {}'.format(
            spec.label, decision_path, exc)) from exc
    with open(evidence_path, newline='', encoding='utf-8') as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row.pop(None, None)
        row[spec.decision_field] = decisions.get(spec.key(row), '')
    return rows, len(decisions)
