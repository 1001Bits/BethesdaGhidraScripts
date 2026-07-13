#!/usr/bin/env python3
"""Type-discovery sequencer: run the binary-derived enrichment drivers
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
      [--programs /Skyrim/SkyrimSE_1_5_97.exe ...]   # default: all x64 below
      [--apply-rename]            # BGS_ENRICH_APPLY=go for the rename driver
      [--ctor-max-classes N] [--globals-max-funcs N]

The PowerPC FalloutNV_Xbox_Debug build is excluded (the x86/x64
decompiler pcode model the drivers assume doesn't apply).
"""
import argparse
import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'core'))
from evidence_identity import (EvidenceIdentityError, bind_for_hash,
                               read_binding)
from binary_identity import inspect_pe, verify_ghidra_program
from pyghidra_result import end_outer_transaction, require_script_success

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = REPO_DIR / "tools" / "ghidra"
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
    # havok_mine is a verifier, not an enrichment step -- retail builds ship
    # no offset-bearing havok reflection (proven; see havok_mine docstring).
    # Run it explicitly only to test a suspected debug/editor binary.
}
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
    '/Skyrim/SkyrimAE_GOG Edition.exe',
    '/Skyrim/SkyrimVR_1_4_15.exe',
    '/Fallout4/Fallout4_OG_1_10_163.exe',
    '/Fallout4/Fallout4_NG_1_10_984.exe',
    '/Fallout4/Fallout4_AE_1_11_191.exe',
    '/Fallout4/Fallout4_1_11_221.exe',
    '/Fallout4/Fallout4VR_1_2_72.exe',
    '/FalloutNV/FalloutNV_1_4_0_525.exe',
    '/Starfield/Starfield 1.16.236',
]


def _find(root, path):
    hit = []

    def walk(folder, prefix=""):
        for f in folder.getFiles():
            if prefix + "/" + f.getName() == path:
                hit.append(f)
        for sub in folder.getFolders():
            walk(sub, prefix + "/" + sub.getName())

    walk(root)
    return hit[0] if hit else None


def _merge_review_queue(evidence_path, decision_path):
    """Refresh evidence while preserving every explicit reviewer decision."""
    evidence_path = Path(evidence_path)
    decision_path = Path(decision_path)
    if not evidence_path.is_file():
        return
    try:
        evidence_binding = read_binding(
            evidence_path, 'globals_evidence', require_content=True)
        if evidence_binding.get('address_coordinate') != 'VA':
            raise EvidenceIdentityError(
                'globals evidence must use VA coordinates')
    except EvidenceIdentityError as exc:
        raise RuntimeError('refusing unbound globals evidence: {}'.format(exc))
    decisions = {}
    if decision_path.is_file():
        try:
            old_binding = read_binding(decision_path, 'globals_decisions')
            if old_binding.get('address_coordinate') != 'VA':
                raise EvidenceIdentityError(
                    'globals decisions must use VA coordinates')
            if old_binding['target_sha256'] != evidence_binding['target_sha256']:
                raise EvidenceIdentityError('decision target differs from evidence')
            for field in ('address_coordinate', 'image_base', 'pointer_size'):
                if old_binding.get(field) != evidence_binding.get(field):
                    raise EvidenceIdentityError(
                        'decision {} differs from evidence'.format(field))
            with decision_path.open(newline='', encoding='utf-8') as fh:
                for row in csv.DictReader(fh):
                    key = (row.get('global_addr') or '').strip().lower()
                    value = (row.get('decision_type') or '').strip()
                    if key and value:
                        decisions[key] = value
        except EvidenceIdentityError as exc:
            print('  Not preserving stale/unbound globals decisions: {}'.format(exc))
    with evidence_path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    if 'decision_type' not in fieldnames:
        fieldnames.append('decision_type')
    for row in rows:
        key = (row.get('global_addr') or '').strip().lower()
        row['decision_type'] = decisions.get(key, '')
    decision_path.parent.mkdir(parents=True, exist_ok=True)
    temp = decision_path.with_suffix(decision_path.suffix + '.tmp')
    with temp.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temp, decision_path)
    bind_for_hash(decision_path, 'globals_decisions',
                  evidence_binding['target_sha256'],
                  evidence_binding.get('program_name', ''),
                  image_base=evidence_binding.get('image_base'),
                  pointer_size=evidence_binding.get('pointer_size'),
                  address_coordinate=evidence_binding.get(
                      'address_coordinate', 'NONE'))


def _metrics(program):
    """Cheap fixed-point signature including Ghidra's modification counter."""
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    named = sum(1 for f in fm.getFunctions(True)
                if not f.getName().startswith(('FUN_', 'sub_')))
    symbols = sum(1 for _ in st.getAllSymbols(True))
    try:
        modification = int(program.getModificationNumber())
    except Exception:
        modification = -1
    return modification, named, symbols, fm.getFunctionCount()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--drivers', nargs='+', default=DEFAULT_DRIVERS,
                    choices=list(DRIVER_PATHS))
    ap.add_argument('--programs', nargs='+', default=DEFAULT_PROGRAMS)
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
                    help="repeat applied enrichment until stable (default 4, max 8)")
    ap.add_argument('--allow-missing', action='store_true',
                    help="do not fail when an explicitly listed program is absent")
    ap.add_argument('--ctor-max-classes', type=int, default=0)
    ap.add_argument('--globals-max-funcs', type=int, default=0)
    args = ap.parse_args()

    args.max_passes = max(1, min(args.max_passes, 8))
    enabled = set()
    for group in ('renames', 'ctors', 'globals', 'settings', 'console',
                  'metadata', 'registries'):
        if args.apply_all_reviewed or getattr(args, 'apply_' + group):
            enabled.add(group)
    # Never inherit broad write authority from a parent shell/process.
    os.environ.pop('BGS_ENRICH_APPLY', None)
    if args.ctor_max_classes:
        os.environ['BGS_CTOR_MAX_CLASSES'] = str(args.ctor_max_classes)
    if args.globals_max_funcs:
        os.environ['BGS_GLOBALS_MAX_FUNCS'] = str(args.globals_max_funcs)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    import time
    results = []
    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()
        for prog_path in args.programs:
            df = _find(root, prog_path)
            if df is None:
                print(f"\n### {prog_path}: NOT FOUND — skip")
                results.append((prog_path,
                                'SKIP' if args.allow_missing else 'FAIL-not-found', 0))
                continue
            passes = args.max_passes if enabled else 1
            for pass_no in range(1, passes + 1):
                pass_before = None
                pass_after = None
                pass_failed = False
                consumer = java.lang.Object()
                program = df.getDomainObject(consumer, True, False, monitor)
                try:
                    try:
                        executable = str(program.getExecutablePath() or '')
                        manifest = inspect_pe(executable)
                        verify_ghidra_program(program, [manifest])
                    except Exception as exc:  # noqa: BLE001
                        label = f"{prog_path}  [target identity]"
                        print(f"  ERROR: refusing unverifiable program: {exc}")
                        results.append((label, 'FAIL-identity', 0))
                        break
                    pass_before = _metrics(program)
                    for requested_driver in args.drivers:
                        driver = requested_driver
                        if driver == 'console_harvest' and prog_path.startswith('/Starfield/'):
                            driver = 'console_harvest_sf'
                # Per-program, per-driver output goes to a stable CSV path so
                # ctor_mine/globals_harvest don't collide across programs.
                        tag = prog_path.strip('/').replace('/', '_').replace(' ', '_').replace('.', '_')
                        evidence = str(CORE_DIR / 'refs' / f'globals_evidence_{tag}.csv')
                        decisions = str(CORE_DIR / 'refs' / f'globals_decisions_{tag}.csv')
                        os.environ['BGS_CTOR_CSV'] = str(CORE_DIR / 'refs' / f'ctor_fields_{tag}.csv')
                        os.environ['BGS_GLOBALS_CSV'] = evidence
                        os.environ['BGS_GLOBALS_APPLY_CSV'] = decisions
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
                        tx = program.startTransaction(
                            "Atomic discovery driver " + driver)
                        commit = False
                        try:
                            stdout, stderr = pyghidra.ghidra_script(
                                str(DRIVER_PATHS[driver]), project, program,
                                echo_stdout=True, echo_stderr=True)
                            require_script_success(stderr, driver)
                            if driver == 'globals_harvest':
                                _merge_review_queue(evidence, decisions)
                            commit = True
                        except Exception as e:  # noqa: BLE001
                            print(f"  ERROR: {type(e).__name__}: {e}")
                            rc = 'FAIL'
                        finally:
                            try:
                                end_outer_transaction(
                                    program, tx, commit, driver)
                            except Exception as e:  # noqa: BLE001
                                print(f"  ERROR: {type(e).__name__}: {e}")
                                commit = False
                                rc = 'FAIL'
                        if commit:
                            if driver in MUTATING and apply:
                                program.save(f"discover: {driver} pass {pass_no}", monitor)
                            rc = 'OK'
                        dt = time.time() - t0
                        results.append((label, rc, dt))
                        print(f"--- {label}: {rc} ({dt:.0f}s) ---")
                        if rc == 'FAIL':
                            pass_failed = True
                            print("  Stopping this program: later drivers may "
                                  "depend on the failed evidence pass.")
                            break
                    pass_after = _metrics(program)
                finally:
                    program.release(consumer)
                    os.environ.pop('BGS_ENRICH_APPLY', None)
                if pass_failed:
                    break
                if pass_after == pass_before:
                    print(f"  Fixed point reached after pass {pass_no}.")
                    break

    print(f"\n{'=' * 70}\nDISCOVERY SUMMARY\n{'=' * 70}")
    for label, rc, dt in results:
        print(f"  {rc:<10} {dt:>6.0f}s  {label}")
    return 1 if any(rc.startswith('FAIL') for _, rc, _ in results) else 0


if __name__ == "__main__":
    sys.exit(main())
