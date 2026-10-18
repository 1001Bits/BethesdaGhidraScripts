#!/usr/bin/env python3
"""Type-discovery sequencer: run the binary-derived improvement drivers
across every x64 program in a combined Ghidra project.

Drivers (scripts/core/, ported from alandtse's CommonLibVR fork):
  1. string_anchored_rename  -- name FUN_/sub_/thunk_ from self-naming
                                debug strings (mutates; idempotent)
  2. ctor_mine               -- decompile constructors -> field name+type
                                proposals CSV (read-only)
  3. globals_harvest         -- type untyped global singletons by the
                                class whose methods consume them (read-only)

The project lock is exclusive, so programs are processed SEQUENTIALLY:
the project is opened once and each program is driven in turn.  Per
program the rename driver runs first (and the program is saved), then
the two read-only proposal miners.

Usage:
  python scripts/discover_combined.py
      [--project-dir C:/GhidraProjects --project-name Combined]
      [--drivers string_anchored_rename ctor_mine globals_harvest]
      [--programs /Skyrim/SkyrimSE_1_5_97.exe ...]   # dry-run default: all x64 below
      [--all-programs]            # required instead of --programs to APPLY to all
      [--apply-rename]            # BGS_ENRICH_APPLY=go for the rename driver
      [--target-pe PATH ...]      # exact backing exe when the import path is gone
      [--ctor-max-classes N] [--globals-max-funcs N] [--globals-min-conf ...]

Any --apply-* flag requires an explicit --programs list (or --all-programs):
a mutation never falls back to "everything".  Driver tuning comes from CLI
flags only; inherited BGS_* tuning variables are scrubbed and the effective
values are echoed.

The PowerPC FalloutNV_Xbox_Debug build is excluded (the x86/x64
decompiler pcode model the drivers assume doesn't apply).
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'core'))
from binary_identity import verify_ghidra_program
from ghidra_project import (UnsavedRecoveryError, find_program,
                            open_program, open_user_project)
from review_queue import (GLOBALS, MINER_SPECS, merge_review_queue,
                          program_tag, queue_paths)
from target_pe import ENV_TARGET_PE, select_target_pe
from pyghidra_result import (PyGhidraScriptNoOp, end_outer_transaction,
                             require_driver_completion,
                             require_script_success)

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
CORE_DIR   = REPO_DIR / "scripts" / "core"

DRIVER_PATHS = {
    'string_anchored_rename': CORE_DIR / 'string_anchored_rename.py',
    'ctor_mine':              CORE_DIR / 'ctor_mine.py',
    'ctor_apply':             CORE_DIR / 'ctor_apply.py',
    'globals_harvest':        CORE_DIR / 'globals_harvest.py',
    'globals_apply':          CORE_DIR / 'globals_apply.py',
    'settings_harvest':       CORE_DIR / 'settings_harvest.py',
    'console_harvest':        CORE_DIR / 'console_harvest.py',
    'console_harvest_sf':     CORE_DIR / 'console_harvest_sf.py',
    'pe_unwind_enrich':       CORE_DIR / 'pe_unwind_enrich.py',
    'registration_harvest':   CORE_DIR / 'registration_harvest.py',
    # havok_mine is a verifier, not an improvement step -- retail builds ship
    # no offset-bearing havok reflection (proven; see havok_mine docstring).
    # Run it explicitly only to test a suspected debug/editor binary.
}


def _verified_program_manifest(program, candidates=(), cache=None):
    """Find the backing executable (recorded path or a ``--target-pe``
    candidate with the Program's import SHA-256) and verify its identity.

    Returns ``(path, manifest)``; raises when no provable file exists.
    """
    executable, manifest = select_target_pe(program, candidates, cache=cache)
    verify_ghidra_program(program, [manifest])
    return executable, manifest


# Driver tuning knobs: env var -> (CLI dest, driver default shown when unset).
# A value may ONLY come from the CLI; anything inherited from the parent
# shell is removed so an old `set BGS_GLOBALS_MIN_CONF=medium` cannot silently
# widen what a later apply run writes.
TUNING = {
    'BGS_CTOR_MAX_CLASSES':    ('ctor_max_classes', '0 (all)'),
    'BGS_CTOR_CATEGORY':       ('ctor_category', '(any)'),
    'BGS_CTOR_TIMEOUT':        ('ctor_timeout', '45'),
    'BGS_GLOBALS_MAX_FUNCS':   ('globals_max_funcs', '0 (all)'),
    'BGS_GLOBALS_MIN_CONF':    ('globals_min_conf', 'high'),
    'BGS_GLOBALS_MIN_INDEG':   ('globals_min_indeg', '8'),
    'BGS_GLOBALS_SAMPLES':     ('globals_samples', '4'),
    'BGS_GLOBALS_SCOPE':       ('globals_scope', 'data'),
    'BGS_REGISTRY_MIN_SITES':  ('registry_min_sites', '4'),
    'BGS_REGISTRY_MAX_FUNCS':  ('registry_max_funcs', '0 (all)'),
    'BGS_SFCMD_MINSHARE':      ('sfcmd_minshare', '4'),
    'BGS_RENAME_TELEMETRY_NS': ('rename_telemetry_ns', '(driver default)'),
    'BGS_ENRICH_ENTRY_WINDOW': ('enrich_entry_window', '0x80'),
}
# Per-program values the sequencer sets itself; never inherit them either.
SEQUENCER_ENV = ('BGS_ENRICH_APPLY', 'BGS_CTOR_CSV', 'BGS_CTOR_DECISIONS_CSV',
                 'BGS_GLOBALS_CSV', 'BGS_GLOBALS_APPLY_CSV', 'BGS_REGISTRY_CSV',
                 ENV_TARGET_PE)


def _apply_tuning(args, environ):
    """Scrub inherited knobs, set the CLI ones; return lines to echo."""
    lines = []
    for name in SEQUENCER_ENV:
        if environ.pop(name, None) is not None:
            lines.append('  {:<24} (inherited value ignored)'.format(name))
    for name, (dest, default) in TUNING.items():
        inherited = environ.pop(name, None)
        value = getattr(args, dest, None)
        if value not in (None, '', 0):
            environ[name] = str(value)
            lines.append('  {:<24} = {}  (CLI)'.format(name, value))
        else:
            note = ''
            if inherited is not None:
                note = '  [inherited {!r} IGNORED; use the CLI flag]'.format(
                    inherited)
            lines.append('  {:<24} = {}  (default){}'.format(
                name, default, note))
    return lines


def _resolve_programs(args, enabled, error):
    """An apply run never falls back to "every program"."""
    if args.programs and args.all_programs:
        error('--programs and --all-programs are mutually exclusive')
    if args.programs:
        return list(args.programs)
    if enabled and not args.all_programs:
        error('an --apply-* flag mutates programs: name them with --programs '
              '(or pass --all-programs to really apply to all {} defaults)'
              .format(len(DEFAULT_PROGRAMS)))
    return list(DEFAULT_PROGRAMS)
# Drivers that mutate the program (require a save).  The *_harvest/apply
# drivers only mutate when BGS_ENRICH_APPLY=go; saving an unchanged
# program is a no-op, so listing them here is safe either way.
DEFAULT_DRIVERS = [name for name in DRIVER_PATHS
                   if name != 'console_harvest_sf']
MUTATING = {'string_anchored_rename', 'ctor_apply', 'globals_apply',
            'settings_harvest', 'console_harvest', 'console_harvest_sf',
            'pe_unwind_enrich', 'registration_harvest'}

APPLY_GROUP = {
    'string_anchored_rename': 'renames',
    'ctor_apply': 'ctors',
    'globals_apply': 'globals',
    'settings_harvest': 'settings',
    'console_harvest': 'console',
    'console_harvest_sf': 'console',
    'pe_unwind_enrich': 'metadata',
    'registration_harvest': 'registries',
}

# Default target set: every x64 MSVC program in the standard Combined.gpr
# layout.  FalloutNV_Xbox_Debug (PPC) is deliberately absent.
DEFAULT_PROGRAMS = [
    '/Skyrim/SkyrimSE_1_5_97.exe',
    '/Skyrim/SkyrimAE_1_6_1170.exe',
    '/Skyrim/SkyrimAE_1_6_640.exe',
    '/Skyrim/SkyrimAE_1_7_104.exe',
    '/Skyrim/SkyrimAE_GOG Edition.exe',
    '/Skyrim/SkyrimVR_1_4_15.exe',
    '/Fallout4/Fallout4_OG_1_10_163.exe',
    '/Fallout4/Fallout4_NG_1_10_984.exe',
    '/Fallout4/Fallout4_AE_1_11_191.exe',
    '/Fallout4/Fallout4_1_11_221.exe',
    '/Fallout4/Fallout4_1_11_240.exe',
    '/Fallout4/Fallout4VR_1_2_72.exe',
    '/FalloutNV/FalloutNV_1_4_0_525.exe',
    '/Starfield/Starfield 1.16.236',
]


def _merge_review_queue(evidence_path, decision_path, spec=GLOBALS):
    """Refresh evidence while preserving every explicit reviewer decision.

    Shared with apply_enrichment_to_user_project (core/review_queue.py) so
    the single-driver launcher produces the same decisions file.
    """
    merge_review_queue(evidence_path, decision_path, spec)


def _modification(program):
    try:
        return int(program.getModificationNumber())
    except Exception:  # noqa: BLE001
        return -1


def _metrics(program):
    """Cheap fixed-point signature of what the program CONTAINS.

    Ghidra's modification counter is deliberately not part of it: a ROLLBACK
    increments that counter too (probed on 12.0.4: empty rollback 3 -> 4, empty
    commit unchanged), and every read-only miner / dry-run is rolled back, so
    including it made a pass look "changed" forever.  Committed drivers are
    tracked separately through :func:`_driver_changed`.
    """
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    named = sum(1 for f in fm.getFunctions(True)
                if not f.getName().startswith(('FUN_', 'sub_')))
    symbols = sum(1 for _ in st.getAllSymbols(True))
    return named, symbols, fm.getFunctionCount()


def _driver_changed(before, after, committed):
    """Did a driver leave a change behind?  Only a committed one can."""
    return bool(committed) and before != after


def _run_driver(ghidra_script, project, program, driver, *, apply, pass_no,
                monitor, evidence='', decisions='', queues=None, report=None):
    """Run one driver atomically.
    Returns 'OK', 'FAIL', 'FAIL-no-op' or 'FAIL-save'.

    Returning without an exception is not success: the driver must also have
    printed its completion sentinel, otherwise nothing is committed or saved.

    The outer transaction is COMMITTED only for a mutating driver that is
    applying.  Read-only miners and every dry-run are rolled back: their
    product is a CSV, and nothing they might have touched by accident is
    allowed to reach the program.

    ``report['changed']`` tells the caller whether a COMMITTED driver left a
    change behind (measured before the save, which moves the counter too).
    """
    if queues is None:
        queues = {'globals_harvest': (evidence, decisions)}
    if report is None:
        report = {}
    report['changed'] = False
    rc = 'FAIL'
    modification_before = _modification(program)
    tx = program.startTransaction("Atomic discovery driver " + driver)
    succeeded = False
    try:
        stdout, stderr = ghidra_script(
            str(DRIVER_PATHS[driver]), project, program,
            echo_stdout=True, echo_stderr=True)
        require_script_success(stderr, driver)
        require_driver_completion(stdout, driver)
        if driver in MINER_SPECS and driver in queues:
            _merge_review_queue(*queues[driver], MINER_SPECS[driver])
        succeeded = True
    except PyGhidraScriptNoOp as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        rc = 'FAIL-no-op'
    except Exception as e:  # noqa: BLE001
        print(f"  ERROR: {type(e).__name__}: {e}")
    finally:
        commit = succeeded and apply and driver in MUTATING
        try:
            end_outer_transaction(program, tx, commit, driver)
        except Exception as e:  # noqa: BLE001
            # A poisoned transaction (nested work rolled back): nothing may be
            # saved and the driver did not succeed.
            print(f"  ERROR: {type(e).__name__}: {e}")
            succeeded = False
    if succeeded:
        rc = 'OK'
        report['changed'] = _driver_changed(
            modification_before, _modification(program), committed=commit)
        if commit:
            try:
                program.save(f"discover: {driver} pass {pass_no}", monitor)
            except Exception as e:  # noqa: BLE001
                print(f"  ERROR: saving after {driver} failed: "
                      f"{type(e).__name__}: {e}")
                print("  The committed changes are NOT on disk; the program "
                      "is released without saving.")
                rc = 'FAIL-save'
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--drivers', nargs='+', default=DEFAULT_DRIVERS,
                    choices=list(DRIVER_PATHS))
    ap.add_argument('--programs', nargs='+', default=None,
                    help="exact project paths; REQUIRED with any --apply-* "
                         "flag (dry-run default: the built-in x64 set)")
    ap.add_argument('--all-programs', action='store_true',
                    help="explicitly target every built-in default program "
                         "(the only way to apply without --programs)")
    ap.add_argument('--target-pe', action='append', default=[],
                    metavar='PATH',
                    help="candidate backing executable (repeatable); used for "
                         "a program whose recorded import path is gone, when "
                         "its SHA-256 equals the Program's import hash")
    ap.add_argument('--apply-rename', '--apply-renames', dest='apply_renames',
                    action='store_true', help="apply reviewed string renames")
    ap.add_argument('--apply-ctors', action='store_true',
                    help="apply high-confidence constructor field proposals")
    ap.add_argument('--apply-globals', action='store_true',
                    help="apply reviewed/high-confidence global types")
    ap.add_argument('--apply-settings', action='store_true')
    ap.add_argument('--apply-console', action='store_true')
    ap.add_argument('--apply-metadata', action='store_true',
                    help="create/linker-proven .pdata entries and unwind annotations")
    ap.add_argument('--apply-registries', action='store_true',
                    help="apply only one-to-one, high-confidence registration names")
    ap.add_argument('--apply-all-reviewed', action='store_true',
                    help="enable all mutation groups (still confidence-gated)")
    ap.add_argument('--max-passes', type=int, default=4,
                    help="repeat applied improvement until stable (default 4, max 8)")
    ap.add_argument('--allow-missing', action='store_true',
                    help="do not fail when an explicitly listed program is absent")
    ap.add_argument('--ctor-max-classes', type=int, default=0)
    ap.add_argument('--ctor-category', default='')
    ap.add_argument('--ctor-timeout', type=int, default=0)
    ap.add_argument('--globals-max-funcs', type=int, default=0)
    ap.add_argument('--globals-min-conf', choices=('high', 'medium'),
                    default=None)
    ap.add_argument('--globals-min-indeg', type=int, default=0)
    ap.add_argument('--globals-samples', type=int, default=0)
    ap.add_argument('--globals-scope', choices=('data', 'class', 'all'),
                    default=None)
    ap.add_argument('--registry-min-sites', type=int, default=0)
    ap.add_argument('--registry-max-funcs', type=int, default=0)
    ap.add_argument('--sfcmd-minshare', default='')
    ap.add_argument('--rename-telemetry-ns', default='')
    ap.add_argument('--enrich-entry-window', default='')
    args = ap.parse_args()

    args.max_passes = max(1, min(args.max_passes, 8))
    enabled = set()
    for group in ('renames', 'ctors', 'globals', 'settings', 'console',
                  'metadata', 'registries'):
        if args.apply_all_reviewed or getattr(args, 'apply_' + group):
            enabled.add(group)
    args.programs = _resolve_programs(args, enabled, ap.error)
    # Never inherit write authority or tuning from a parent shell/process.
    print("Effective driver tuning (CLI flags only):")
    for line in _apply_tuning(args, os.environ):
        print(line)
    print("Apply groups: {}".format(', '.join(sorted(enabled)) or '(none: dry-run)'))
    print("Programs: {}".format(', '.join(args.programs)))

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    import time
    results = []
    pe_cache = {}
    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with open_user_project(args.project_dir, args.project_name) as project:
        root = project.getProjectData().getRootFolder()
        for prog_path in args.programs:
            df = find_program(root, prog_path)
            if df is None:
                print(f"\n### {prog_path}: NOT FOUND — skip")
                results.append((prog_path,
                                'SKIP' if args.allow_missing else 'FAIL-not-found', 0))
                continue
            passes = args.max_passes if enabled else 1
            for pass_no in range(1, passes + 1):
                pass_before = None
                pass_after = None
                pass_changed = False
                pass_failed = False
                consumer = java.lang.Object()
                try:
                    # A dry run opens read-only; neither mode may destroy the
                    # crash-recovery snapshot of unsaved GUI work.
                    program = open_program(df, consumer, monitor,
                                           write=bool(enabled))
                except UnsavedRecoveryError as exc:
                    print(f"  ERROR: {exc}")
                    results.append((f"{prog_path}  [open]", 'FAIL-recovery', 0))
                    break
                try:
                    try:
                        executable, _manifest = _verified_program_manifest(
                            program, args.target_pe, pe_cache)
                    except Exception as exc:  # noqa: BLE001
                        label = f"{prog_path}  [target identity]"
                        print(f"  ERROR: refusing unverifiable program: {exc}")
                        results.append((label, 'FAIL-identity', 0))
                        break
                    # The in-Ghidra drivers re-verify this exact file.
                    os.environ[ENV_TARGET_PE] = str(executable)
                    pass_before = _metrics(program)
                    pass_changed = False
                    for requested_driver in args.drivers:
                        driver = requested_driver
                        if driver == 'console_harvest' and prog_path.startswith('/Starfield/'):
                            driver = 'console_harvest_sf'
                        # Per-program queue paths come from review_queue --
                        # the same names apply_enrichment_to_user_project and
                        # the in-Ghidra appliers derive -- never inherited
                        # from the environment (scrubbed above).
                        tag = program_tag(prog_path)
                        queues = {
                            miner: queue_paths(spec, prog_path, {})
                            for miner, spec in MINER_SPECS.items()}
                        for miner, (evidence, decisions) in queues.items():
                            spec = MINER_SPECS[miner]
                            os.environ[spec.evidence_env] = evidence
                            os.environ[spec.decisions_env] = decisions
                        os.environ['BGS_REGISTRY_CSV'] = str(
                            CORE_DIR / 'refs' / f'registrations_{tag}.csv')
                        apply = APPLY_GROUP.get(driver) in enabled
                        if apply:
                            os.environ['BGS_ENRICH_APPLY'] = 'go'
                        else:
                            os.environ.pop('BGS_ENRICH_APPLY', None)
                        label = f"{prog_path}  [{driver}] pass={pass_no}"
                        print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
                        t0 = time.time()
                        report = {}
                        rc = _run_driver(
                            pyghidra.ghidra_script, project, program, driver,
                            apply=apply, pass_no=pass_no, monitor=monitor,
                            queues=queues, report=report)
                        dt = time.time() - t0
                        if report.get('changed'):
                            pass_changed = True
                            print(f"  {driver} changed the program "
                                  "(another pass will follow).")
                        results.append((label, rc, dt))
                        print(f"--- {label}: {rc} ({dt:.0f}s) ---")
                        if rc.startswith('FAIL'):
                            pass_failed = True
                            print("  Stopping this program: later drivers may "
                                  "depend on the failed evidence pass.")
                            break
                    pass_after = _metrics(program)
                finally:
                    program.release(consumer)
                    os.environ.pop('BGS_ENRICH_APPLY', None)
                    os.environ.pop(ENV_TARGET_PE, None)
                if pass_failed:
                    break
                if pass_after == pass_before and not pass_changed:
                    print(f"  Fixed point reached after pass {pass_no}.")
                    break

    print(f"\n{'=' * 70}\nDISCOVERY SUMMARY\n{'=' * 70}")
    for label, rc, dt in results:
        print(f"  {rc:<10} {dt:>6.0f}s  {label}")
    return 1 if any(rc.startswith('FAIL') for _, rc, _ in results) else 0


if __name__ == "__main__":
    sys.exit(main())
