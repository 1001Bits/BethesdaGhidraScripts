#!/usr/bin/env python3
"""Pre-apply SF shift-map validation + generation.

Run after a target has been imported and generically analyzed, but before
``CommonLibImport_SF.py`` is generated or applied.  It validates the exact
target executable and decides what to do:

* **PE version == anchor reference (1.16.236)** -- the build is fully
  in-namespace with CommonLibSF's headers, no shifts needed.  If a
  reference layout CSV is missing, dump it now from the BGS pipeline
  project so future-version users have something to diff against.

* **PE version != anchor reference** -- dump the user's unmodified RTTI
  layouts, diff them against the anchor reference, and write a versioned
  map bound to the target SHA-256.  Generation fails closed until this map
  exists, preventing a wrong first-pass layout from becoming authoritative.

Designed to be cheap on the common case: if both layouts already
exist and the shift map is current, this script does ~nothing
(under 1 second).  Slow path is the first run on a fresh SF version:
~30 seconds for the dump (pyghidra-based, in-process, no MCP).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
SCRIPT_DIR  = Path(__file__).resolve().parent
CORE_DIR    = REPO_DIR / "scripts" / "core"
REFS_DIR    = SCRIPT_DIR / "refs"
EXES_DIR    = REPO_DIR / "exes" / "starfield" / "sf"
PROJECTS_DIR = REPO_DIR / "ghidraprojects"

GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"

sys.path.insert(0, str(CORE_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from pe_layout import PELayout
from sf_shift_manifest import (
    ANCHOR_VERSION,
    bind_generated_map,
    load_layout_identity,
    load_validated,
    map_path as _manifest_map_path,
)


def _ver_filename(v: Tuple[int, ...]) -> str:
    parts = list(v)
    while len(parts) < 4:
        parts.append(0)
    return '-'.join(str(x) for x in parts[:4])


def _ver_label(v: Tuple[int, ...]) -> str:
    parts = list(v)
    while len(parts) < 4:
        parts.append(0)
    return '.'.join(str(x) for x in parts[:4])


def _detect_sf_target():
    from pe_version import get_pe_version
    from binary_identity import artifact_is_fresh
    if not EXES_DIR.is_dir():
        return None
    candidates = []
    for fname in sorted(os.listdir(str(EXES_DIR))):
        if not fname.lower().endswith('.exe'):
            continue
        if 'unpacked' in fname.lower():
            continue
        v = get_pe_version(str(EXES_DIR / fname))
        if v and len(v) >= 3:
            while len(v) < 4:
                v = v + (0,)
            path = EXES_DIR / fname
            stem = path.stem.lower()
            artifacts = [p for p in sorted(EXES_DIR.iterdir())
                         if p.is_file() and 'unpacked' in p.name.lower()
                         and p.name.lower().startswith(stem)
                         and not p.name.lower().endswith('.identity.json')
                         and artifact_is_fresh(str(path), str(p))]
            if len(artifacts) > 1:
                raise RuntimeError('multiple fresh analyzed artifacts for {}'.format(path))
            analyzed = artifacts[0] if artifacts else path
            candidates.append((analyzed, v[:4], PELayout.read(str(analyzed))))
    if not candidates:
        return None
    if len(candidates) != 1:
        raise RuntimeError('ambiguous Starfield targets: {}'.format(
            ', '.join(p.name for p, _, _ in candidates)))
    return candidates[0]


def _layout_csv(version: Tuple[int, ...]) -> Path:
    return REFS_DIR / 'sf_{}_vtables.csv.gz'.format(_ver_filename(version))


def _versionlib_path(version: Tuple[int, ...]) -> Path:
    return (REPO_DIR / 'addresslibrary' / 'starfield' /
            'versionlib-{}.bin'.format(_ver_filename(version)))


def _validated_layout(path: Path, version: Tuple[int, ...],
                      expected_sha256: Optional[str] = None) -> bool:
    """Return true only for a content- and executable-bound layout."""
    if not path.is_file():
        return False
    try:
        is_anchor = tuple(version) == ANCHOR_VERSION
        load_layout_identity(
            path, version, expected_sha256,
            versionlib_path=_versionlib_path(version),
            require_function_names_included=is_anchor,
            require_fingerprint_mode='raw-bytes-32')
    except (OSError, ValueError) as exc:
        print('  Layout {} is stale/unbound: {}'.format(path.name, exc))
        return False
    return True


def _dump_layouts(version: Tuple[int, ...], expected_sha256: str,
                  program_name: str) -> str:
    """Invoke dump_vtable_layouts.py against the BGS pipeline project.

    Returns ``ok``, ``needs_program``, or ``invalid``.
    """
    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    if not (project_dir / '{}.gpr'.format(GHIDRA_PROJECT_NAME)).is_file():
        print('  WARNING: BGS pipeline project not found at {}'.format(project_dir))
        print('           Run `python run.py build` first to import Starfield.')
        return 'needs_program'

    versionlib = _versionlib_path(version)
    if not versionlib.is_file():
        print('  ERROR: exact address library is missing: {}'.format(versionlib))
        return 'invalid'

    out_csv = _layout_csv(version)
    REFS_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, str(SCRIPT_DIR / 'dump_vtable_layouts.py'),
        '--project-dir', str(project_dir),
        '--project-name', GHIDRA_PROJECT_NAME,
        '--program', program_name,
        '--label', 'sf_' + _ver_filename(version).replace('-', '_'),
        '--out', str(out_csv),
        '--expected-sha256', expected_sha256,
        '--versionlib', str(versionlib),
    ]
    if version != ANCHOR_VERSION:
        # Target analysis names may already contain a stale CommonLib import;
        # never let them become self-confirming exact-name shift evidence.
        cmd.append('--no-function-names')
    print('  Dumping vtable layouts for SF {} ...'.format(_ver_label(version)))
    r = subprocess.run(cmd, cwd=str(REPO_DIR))
    if r.returncode != 0:
        print('  ERROR: vtable dump failed (exit {}).'.format(r.returncode))
        return 'needs_program' if r.returncode == 2 else 'invalid'
    return 'ok' if out_csv.is_file() else 'invalid'


def _build_shift_map(ref_csv: Path, target_csv: Path,
                     target_version: Tuple[int, ...],
                     target_sha256: str) -> bool:
    """Diff layouts and write an identity-bound, versioned shift map."""
    out_json = _manifest_map_path(REFS_DIR, target_version)
    cmd = [
        sys.executable, str(CORE_DIR / 'build_shift_map.py'),
        '--ref', str(ref_csv),
        '--ref-label', 'sf',
        '--target', str(target_csv),
        '--target-label', 'sf_' + _ver_filename(target_version).replace('-', '_'),
        '--out', str(out_json),
        # Starfield IDs are version-stable, so the same function can be found
        # in both builds by identity instead of by comparing raw prologue
        # bytes -- which a rebuild invalidates almost everywhere, since it
        # moves nearly every function and with it every embedded call target.
        # load_validated below already binds both of these by SHA-256.
        '--ref-versionlib', str(_versionlib_path(ANCHOR_VERSION)),
        '--target-versionlib', str(_versionlib_path(target_version)),
    ]
    print('  Building shift map vs SF {} reference ...'.format(_ver_label(ANCHOR_VERSION)))
    env = os.environ.copy()
    env['PYTHONPATH'] = str(CORE_DIR) + os.pathsep + env.get('PYTHONPATH', '')
    r = subprocess.run(cmd, cwd=str(REPO_DIR), env=env)
    if r.returncode != 0 or not out_json.is_file():
        return False
    try:
        bind_generated_map(out_json, target_version, target_sha256,
                           ref_csv, target_csv,
                           reference_versionlib=_versionlib_path(ANCHOR_VERSION),
                           target_versionlib=_versionlib_path(target_version))
        load_validated(out_json, target_version, target_sha256,
                       reference_layout=ref_csv, target_layout=target_csv,
                       reference_versionlib=_versionlib_path(ANCHOR_VERSION),
                       target_versionlib=_versionlib_path(target_version))
    except (OSError, ValueError) as exc:
        print('  ERROR: generated shift map failed identity validation: {}'.format(exc))
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--force-redump', action='store_true',
                    help='re-dump even if a layout for this version already exists')
    ap.add_argument('--preflight', action='store_true',
                    help='pipeline mode: exit 2 when a clean analyzed target is required')
    args = ap.parse_args()

    target = _detect_sf_target()
    if target is None:
        print('SF shift check: no Starfield.exe in {} -- skipping.'.format(EXES_DIR))
        return 0
    exe_path, version, pe_layout = target

    print('SF shift check: detected version {}'.format(_ver_label(version)))
    print('  target: {}'.format(exe_path))
    print('  SHA-256: {}'.format(pe_layout.sha256))

    ref_csv    = _layout_csv(ANCHOR_VERSION)
    target_csv = _layout_csv(version)
    shift_json = _manifest_map_path(REFS_DIR, version)

    # Case 1: PE version IS the anchor.  Make sure the reference CSV exists.
    if version == ANCHOR_VERSION:
        legacy = REFS_DIR / 'shift_sf.json'
        if legacy.is_file():
            print('  WARNING: ignoring obsolete unversioned {}'.format(legacy.name))
        identity_ok = _validated_layout(ref_csv, version, pe_layout.sha256)
        if identity_ok and not args.force_redump:
            print('  Reference layout already at {} -- nothing to do.'.format(ref_csv.name))
            return 0
        print('  Reference layout is missing/stale; dumping exact target now.')
        dump_status = _dump_layouts(version, pe_layout.sha256, exe_path.name)
        if dump_status != 'ok':
            print('  A clean, analyzed project import matching the target SHA-256 is required.')
            return (2 if args.preflight and dump_status == 'needs_program'
                    else 1)
        print('  Reference seeded at {}.'.format(ref_csv))
        print('  Commit this file so future-version users have something to diff against.')
        return 0

    # A target layout is reusable only when its identity sidecar binds its
    # bytes to this exact executable.  Version equality alone is insufficient:
    # repacks/hotfixes can share the four-part file version.
    reference_valid = _validated_layout(ref_csv, ANCHOR_VERSION)
    if not reference_valid:
        print('  ERROR: anchor reference is missing or lacks exact executable provenance.')
        print('         Re-seed it from SF {} before building target maps.'.format(
            _ver_label(ANCHOR_VERSION)))
        return 2 if args.preflight else 1

    target_valid = _validated_layout(target_csv, version, pe_layout.sha256)
    if shift_json.is_file() and target_valid \
            and not args.force_redump:
        try:
            load_validated(shift_json, version, pe_layout.sha256,
                           reference_layout=ref_csv, target_layout=target_csv,
                           reference_versionlib=_versionlib_path(ANCHOR_VERSION),
                           target_versionlib=_versionlib_path(version))
            print('  Valid target-bound shift map already exists: {}'.format(
                shift_json.name))
            return 0
        except (OSError, ValueError) as exc:
            print('  Existing shift map is stale/invalid: {}'.format(exc))

    # Case 2: PE version != anchor.  Dump target layouts from a clean,
    # generically analyzed program.  Exact version-library addresses enumerate
    # the tables; COL metadata classifies primary/secondary identities.  No
    # CommonLib-imported names are accepted as evidence.
    if not target_valid or args.force_redump:
        dump_status = _dump_layouts(version, pe_layout.sha256, exe_path.name)
        if dump_status != 'ok':
            print('  Preflight needs a clean analyzed target in the BGS project.')
            print('  Import/analyze Starfield without CommonLibImport_SF.py, then rerun.')
            return (2 if args.preflight and dump_status == 'needs_program'
                    else 1)
        if not _validated_layout(target_csv, version, pe_layout.sha256):
            print('  ERROR: newly dumped target layout failed identity validation.')
            return 1

    # If the anchor reference is missing, we can't build a shift map.
    if not reference_valid:
        print('  ERROR: anchor reference {} is missing.'.format(ref_csv.name))
        print('         Refusing to generate or apply unshifted vtable names.')
        return 2 if args.preflight else 1

    # Build the shift map.
    if not _build_shift_map(ref_csv, target_csv, version, pe_layout.sha256):
        print('  ERROR: shift map build failed.')
        return 1

    print()
    print('  ============================================================')
    print('  Shift map generated and validated at {}.'.format(shift_json))
    print('  CommonLibImport_SF.py can now be generated and applied once.')
    print('  ============================================================')
    print()
    print('  Also: please open a GitHub issue and attach')
    print('    {}'.format(target_csv))
    print('  so the maintainer can ship a pre-built shift map for SF {}'.format(_ver_label(version)))
    print('  in the next release (saves all future {}+ users the dump pass).'.format(_ver_label(version)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
