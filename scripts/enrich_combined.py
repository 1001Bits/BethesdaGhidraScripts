#!/usr/bin/env python3
"""Sequencer: improve every game/version program inside Combined.gpr.

Runs all currently-supported improvement passes back-to-back so you
only have to close Ghidra once.  Each step is a subprocess.  The default is
fail-fast because later byte-signature write-back steps depend on names
created by earlier applies; use ``--keep-going`` only for independent
research runs.

Steps are addressed by their stable NAME (``--only skyrim-17104``,
``--skip fnv starfield``); the list below is generated from ``APPLY_STEPS``.
A 1-based position is still accepted as an alias, but positions shift whenever a
step is inserted, so prefer names in anything you save.

{steps}

  --rtti additionally runs core/run_vtable_pipeline per binary (slow).

Defaults assume C:/GhidraProjects/Combined.gpr with the user's typical
multi-binary layout.  Each step prints full output (no quiet mode) so
progress is visible.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_DIR / "scripts"

# (stable_name, label, script_relative_to_scripts_dir, extra_args)
APPLY_STEPS = [
    ("f4-ae", "F4 AE re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Fallout4/Fallout4_AE_1_11_191.exe"]),
    ("f4-221", "F4 1.11.221 re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "221",
      "--program-path", "/Fallout4/Fallout4_1_11_221.exe"]),
    ("f4-240", "F4 1.11.240 re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "240",
      "--program-path", "/Fallout4/Fallout4_1_11_240.exe"]),
    ("skyrim-se", "Skyrim SE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "se",
      "--program-path", "/Skyrim/SkyrimSE_1_5_97.exe"]),
    ("skyrim-ae", "Skyrim AE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Skyrim/SkyrimAE_1_6_1170.exe"]),
    ("skyrim-16640", "Skyrim AE 1.6.640 apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "16640",
      "--program-path", "/Skyrim/SkyrimAE_1_6_640.exe"]),
    ("skyrim-17104", "Skyrim AE 1.7.104 apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "17104",
      "--program-path", "/Skyrim/SkyrimAE_1_7_104.exe"]),
    ("skyrim-vr", "Skyrim VR apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "vr",
      "--program-path", "/Skyrim/SkyrimVR_1_4_15.exe"]),
    ("skyrim-bytesig", "Skyrim SE -> AE/VR bytesig port + write-back",
     "commonlibsse/bytesig_port_combined.py",
     # --target-paths so the Steam AE binary is picked unambiguously
     # (Combined.gpr also has a GOG Edition AE that matches the broader
     # 'skyrimae' hints).  --no-apply because the in-place renames have
     # already been done by the prior run -- we only want the write-back.
     ["--write-back-script",
      "--no-apply",
      "--target-paths",
      "ae=/Skyrim/SkyrimAE_1_6_1170.exe",
      "16640=/Skyrim/SkyrimAE_1_6_640.exe",
      "17104=/Skyrim/SkyrimAE_1_7_104.exe",
      "vr=/Skyrim/SkyrimVR_1_4_15.exe"]),
    ("f4-bytesig", "F4 221 -> OG/NG/AE/VR bytesig port + write-back",
     "commonlibf4/bytesig_port_combined.py",
     # The earlier exes/-based run_bytesig_port already did 221->AE +
     # AE->221 script merges via run_bytesig_port.py.  This Combined
     # variant covers OG/NG/VR (binaries not on disk for the standalone
     # run) and also lets the 221 PDB pool reach AE in-place.
     ["--write-back-script", "--no-apply"]),
    # A: FNV (PC build only -- Xbox debug build is PowerPC, skip)
    ("fnv", "FNV apply",
     "apply_fnv_to_user_project.py",
     ["--program-path", "/FalloutNV/FalloutNV_1_4_0_525.exe"]),
    # B: GOG is intentionally omitted.  A relib-re-keyed database proves
    # offsets, not target identity; an exact GOG-bound importer is required.
    # C: Starfield (PC only).
    # DO NOT apply the SF script to StarfieldVR.exe: it embeds PC 1.16.x
    # offsets and a previous run wrote 62k labels at wrong addresses into
    # the VR program (vtbl read_fail=25,687 -- offsets don't exist there).
    # If that pollution is still present, revert the StarfieldVR.exe
    # program to a pre-2026-06-09 version via its Ghidra history.
    ("starfield", "Starfield apply -> 1.16.236",
     "apply_sf_to_user_project.py",
     ["--program-path", "/Starfield/Starfield 1.16.236"]),
]

# D: RTTI vtable pipeline -- slow, run only when --rtti is given.
RTTI_TARGETS = [
    "/Fallout4/Fallout4_AE_1_11_191.exe",
    "/Fallout4/Fallout4_1_11_221.exe",
    "/Fallout4/Fallout4_1_11_240.exe",
    "/Fallout4/Fallout4_NG_1_10_984.exe",
    "/Fallout4/Fallout4_OG_1_10_163.exe",
    "/Fallout4/Fallout4VR_1_2_72.exe",
    "/Skyrim/SkyrimSE_1_5_97.exe",
    "/Skyrim/SkyrimAE_1_6_1170.exe",
    "/Skyrim/SkyrimAE_1_6_640.exe",
    "/Skyrim/SkyrimAE_1_7_104.exe",
    "/Skyrim/SkyrimAE_GOG Edition.exe",
    "/Skyrim/SkyrimVR_1_4_15.exe",
    "/FalloutNV/FalloutNV_1_4_0_525.exe",
    "/Starfield/Starfield 1.16.236",
    "/Starfield/StarfieldVR.exe",
]


def _step_listing(steps):
    """The numbered step list shown in the module docstring and ``--help``."""
    width = max(len(name) for name, _label, _script, _extra in steps)
    return "\n".join(
        "  {:>2}. {:<{}}  {}".format(index, name, width, label)
        for index, (name, label, _script, _extra) in enumerate(steps, 1))


def _select_steps(tokens, steps, option, error):
    """Resolve ``--only``/``--skip`` tokens to step names; reject unknowns.

    A token that selects nothing must never be ignored: ``--skip 9,10`` used to
    skip no step at all and let both mutating steps run.
    """
    names = [name for name, _label, _script, _extra in steps]
    chosen = set()
    for token in tokens:
        if token in names:
            chosen.add(token)
        elif token.isdigit() and 1 <= int(token) <= len(names):
            chosen.add(names[int(token) - 1])
        else:
            error("{} {!r} is not a step; choose from: {}".format(
                option, token, ", ".join(names)))
    return chosen


__doc__ = __doc__.format(steps=_step_listing(APPLY_STEPS))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--skip', nargs='+', default=[], metavar='STEP',
                    help="Skip apply-step(s) by name (e.g. --skip fnv starfield)")
    ap.add_argument('--only', nargs='+', default=None, metavar='STEP',
                    help="Run ONLY the named apply-step(s)")
    ap.add_argument('--rtti', action='store_true',
                    help="ALSO run RTTI vtable pipeline on each binary "
                         "(adds ~30 min per binary -- expect 3-5 hours)")
    ap.add_argument('--keep-going', action='store_true',
                    help="continue independent research after a failure; "
                         "unsafe dependent write-back steps may still fail")
    args = ap.parse_args()
    skip = _select_steps(args.skip, APPLY_STEPS, '--skip', ap.error)
    only = (_select_steps(args.only, APPLY_STEPS, '--only', ap.error)
            if args.only else None)

    common = ['--project-dir', args.project_dir,
              '--project-name', args.project_name]

    overall_start = time.time()
    results = []
    for i, (name, label, script, extra) in enumerate(APPLY_STEPS, 1):
        if only is not None and name not in only:
            continue
        if name in skip:
            print(f"\n{'=' * 70}\nSTEP {i} [{name}] SKIPPED: {label}\n{'=' * 70}")
            results.append((label, 'skipped', 0))
            continue
        script_path = SCRIPTS_DIR / script
        cmd = [sys.executable, str(script_path), *common, *extra]
        print(f"\n{'=' * 70}\nSTEP {i}/{len(APPLY_STEPS)} [{name}]: {label}\n"
              f"  cmd: {' '.join(repr(c) if ' ' in c else c for c in cmd)}\n"
              f"{'=' * 70}")
        step_start = time.time()
        rc = subprocess.run(cmd).returncode
        elapsed = time.time() - step_start
        status = 'OK' if rc == 0 else f'FAIL (rc={rc})'
        results.append((label, status, elapsed))
        print(f"\n--- STEP {i} {status} ({elapsed:.0f}s) ---")
        if rc != 0 and not args.keep_going:
            print("Stopping: later write-back steps depend on successful "
                  "upstream enrichment. Use --keep-going only when those "
                  "dependencies are intentionally out of scope.")
            break

    failed_apply = any(status.startswith('FAIL')
                       for _, status, _ in results)
    if args.rtti and (args.keep_going or not failed_apply):
        rtti_script = SCRIPTS_DIR / "core" / "run_vtable_pipeline.py"
        for prog_path in RTTI_TARGETS:
            label = f"RTTI walk -> {prog_path}"
            cmd = [sys.executable, str(rtti_script),
                   args.project_dir, args.project_name, prog_path]
            print(f"\n{'=' * 70}\n{label}\n  cmd: "
                  f"{' '.join(repr(c) if ' ' in c else c for c in cmd)}\n"
                  f"{'=' * 70}")
            step_start = time.time()
            rc = subprocess.run(cmd).returncode
            elapsed = time.time() - step_start
            status = 'OK' if rc == 0 else f'FAIL (rc={rc})'
            results.append((label, status, elapsed))
            print(f"\n--- {label} {status} ({elapsed:.0f}s) ---")

    total = time.time() - overall_start
    print(f"\n{'=' * 70}\nSUMMARY ({total:.0f}s total)\n{'=' * 70}")
    for i, (label, status, elapsed) in enumerate(results, 1):
        print(f"  {i:>2}. {status:<14}  {elapsed:>6.0f}s  {label}")
    failures = [label for label, status, _ in results
                if status.startswith('FAIL')]
    if failures:
        print(f"\nFAILED: {len(failures)} required improvement step(s).")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
